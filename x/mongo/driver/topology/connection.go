// Copyright (C) MongoDB, Inc. 2017-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package topology

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.mongodb.org/mongo-driver/x/bsonx/bsoncore"
	"go.mongodb.org/mongo-driver/x/mongo/driver"
	"go.mongodb.org/mongo-driver/x/mongo/driver/address"
	"go.mongodb.org/mongo-driver/x/mongo/driver/description"
	"go.mongodb.org/mongo-driver/x/mongo/driver/wiremessage"
	"golang.org/x/crypto/ocsp"
)

var globalConnectionID uint64 = 1

func nextConnectionID() uint64 { return atomic.AddUint64(&globalConnectionID, 1) }

type connection struct {
	id               string
	nc               net.Conn // When nil, the connection is closed.
	addr             address.Address
	idleTimeout      time.Duration
	idleDeadline     atomic.Value // Stores a time.Time
	lifetimeDeadline time.Time
	readTimeout      time.Duration
	writeTimeout     time.Duration
	desc             description.Server
	compressor       wiremessage.CompressorID
	zliblevel        int
	zstdLevel        int
	connected        int32 // must be accessed using the sync/atomic package
	connectDone      chan struct{}
	connectErr       error
	config           *connectionConfig

	// pool related fields
	pool       *pool
	poolID     uint64
	generation uint64
}

// newConnection handles the creation of a connection. It does not connect the connection.
func newConnection(ctx context.Context, addr address.Address, opts ...ConnectionOption) (*connection, error) {
	cfg, err := newConnectionConfig(opts...)
	if err != nil {
		return nil, err
	}

	var lifetimeDeadline time.Time
	if cfg.lifeTimeout > 0 {
		lifetimeDeadline = time.Now().Add(cfg.lifeTimeout)
	}

	id := fmt.Sprintf("%s[-%d]", addr, nextConnectionID())

	c := &connection{
		id:               id,
		addr:             addr,
		idleTimeout:      cfg.idleTimeout,
		lifetimeDeadline: lifetimeDeadline,
		readTimeout:      cfg.readTimeout,
		writeTimeout:     cfg.writeTimeout,
		connectDone:      make(chan struct{}),
		config:           cfg,
	}
	atomic.StoreInt32(&c.connected, initialized)

	return c, nil
}

// connect handles the I/O for a connection. It will dial, configure TLS, and perform
// initialization handshakes.
func (c *connection) connect(ctx context.Context) {

	if !atomic.CompareAndSwapInt32(&c.connected, initialized, connected) {
		return
	}
	defer close(c.connectDone)

	var err error
	c.nc, err = c.config.dialer.DialContext(ctx, c.addr.Network(), c.addr.String())
	if err != nil {
		atomic.StoreInt32(&c.connected, disconnected)
		c.connectErr = ConnectionError{Wrapped: err, init: true}
		return
	}

	if c.config.tlsConfig != nil {
		tlsConfig := c.config.tlsConfig.Clone()

		// store the result of configureTLS in a separate variable than c.nc to avoid overwriting c.nc with nil in
		// error cases.
		tlsNc, err := configureTLS(ctx, c.nc, c.addr, tlsConfig)
		if err != nil {
			if c.nc != nil {
				_ = c.nc.Close()
			}
			atomic.StoreInt32(&c.connected, disconnected)
			c.connectErr = ConnectionError{Wrapped: err, init: true}
			return
		}
		c.nc = tlsNc
	}

	c.bumpIdleDeadline()

	// running isMaster and authentication is handled by a handshaker on the configuration instance.
	handshaker := c.config.handshaker
	if handshaker == nil {
		return
	}

	handshakeConn := initConnection{c}
	c.desc, err = handshaker.GetDescription(ctx, c.addr, handshakeConn)
	if err == nil {
		err = handshaker.FinishHandshake(ctx, handshakeConn)
	}
	if err != nil {
		if c.nc != nil {
			_ = c.nc.Close()
		}
		atomic.StoreInt32(&c.connected, disconnected)
		c.connectErr = ConnectionError{Wrapped: err, init: true}
		return
	}

	if c.config.descCallback != nil {
		c.config.descCallback(c.desc)
	}
	if len(c.desc.Compression) > 0 {
	clientMethodLoop:
		for _, method := range c.config.compressors {
			for _, serverMethod := range c.desc.Compression {
				if method != serverMethod {
					continue
				}

				switch strings.ToLower(method) {
				case "snappy":
					c.compressor = wiremessage.CompressorSnappy
				case "zlib":
					c.compressor = wiremessage.CompressorZLib
					c.zliblevel = wiremessage.DefaultZlibLevel
					if c.config.zlibLevel != nil {
						c.zliblevel = *c.config.zlibLevel
					}
				case "zstd":
					c.compressor = wiremessage.CompressorZstd
					c.zstdLevel = wiremessage.DefaultZstdLevel
					if c.config.zstdLevel != nil {
						c.zstdLevel = *c.config.zstdLevel
					}
				}
				break clientMethodLoop
			}
		}
	}
}

func (c *connection) wait() error {
	if c.connectDone != nil {
		<-c.connectDone
	}
	return c.connectErr
}

func (c *connection) writeWireMessage(ctx context.Context, wm []byte) error {
	var err error
	if atomic.LoadInt32(&c.connected) != connected {
		return ConnectionError{ConnectionID: c.id, message: "connection is closed"}
	}
	select {
	case <-ctx.Done():
		return ConnectionError{ConnectionID: c.id, Wrapped: ctx.Err(), message: "failed to write"}
	default:
	}

	var deadline time.Time
	if c.writeTimeout != 0 {
		deadline = time.Now().Add(c.writeTimeout)
	}

	if dl, ok := ctx.Deadline(); ok && (deadline.IsZero() || dl.Before(deadline)) {
		deadline = dl
	}

	if err := c.nc.SetWriteDeadline(deadline); err != nil {
		return ConnectionError{ConnectionID: c.id, Wrapped: err, message: "failed to set write deadline"}
	}

	_, err = c.nc.Write(wm)
	if err != nil {
		c.close()
		return ConnectionError{ConnectionID: c.id, Wrapped: err, message: "unable to write wire message to network"}
	}

	c.bumpIdleDeadline()
	return nil
}

// readWireMessage reads a wiremessage from the connection. The dst parameter will be overwritten.
func (c *connection) readWireMessage(ctx context.Context, dst []byte) ([]byte, error) {
	if atomic.LoadInt32(&c.connected) != connected {
		return dst, ConnectionError{ConnectionID: c.id, message: "connection is closed"}
	}

	select {
	case <-ctx.Done():
		// We closeConnection the connection because we don't know if there is an unread message on the wire.
		c.close()
		return nil, ConnectionError{ConnectionID: c.id, Wrapped: ctx.Err(), message: "failed to read"}
	default:
	}

	var deadline time.Time
	if c.readTimeout != 0 {
		deadline = time.Now().Add(c.readTimeout)
	}

	if dl, ok := ctx.Deadline(); ok && (deadline.IsZero() || dl.Before(deadline)) {
		deadline = dl
	}

	if err := c.nc.SetReadDeadline(deadline); err != nil {
		return nil, ConnectionError{ConnectionID: c.id, Wrapped: err, message: "failed to set read deadline"}
	}

	// We use an array here because it only costs 4 bytes on the stack and means we'll only need to
	// reslice dst once instead of twice.
	var sizeBuf [4]byte

	// We do a ReadFull into an array here instead of doing an opportunistic ReadAtLeast into dst
	// because there might be more than one wire message waiting to be read, for example when
	// reading messages from an exhaust cursor.
	_, err := io.ReadFull(c.nc, sizeBuf[:])
	if err != nil {
		// We closeConnection the connection because we don't know if there are other bytes left to read.
		c.close()
		return nil, ConnectionError{ConnectionID: c.id, Wrapped: err, message: "incomplete read of message header"}
	}

	// read the length as an int32
	size := (int32(sizeBuf[0])) | (int32(sizeBuf[1]) << 8) | (int32(sizeBuf[2]) << 16) | (int32(sizeBuf[3]) << 24)

	if int(size) > cap(dst) {
		// Since we can't grow this slice without allocating, just allocate an entirely new slice.
		dst = make([]byte, 0, size)
	}
	// We need to ensure we don't accidentally read into a subsequent wire message, so we set the
	// size to read exactly this wire message.
	dst = dst[:size]
	copy(dst, sizeBuf[:])

	_, err = io.ReadFull(c.nc, dst[4:])
	if err != nil {
		// We closeConnection the connection because we don't know if there are other bytes left to read.
		c.close()
		return nil, ConnectionError{ConnectionID: c.id, Wrapped: err, message: "incomplete read of full message"}
	}

	c.bumpIdleDeadline()
	return dst, nil
}

func (c *connection) close() error {
	if atomic.LoadInt32(&c.connected) != connected {
		return nil
	}
	if c.pool == nil {
		var err error

		if c.nc != nil {
			err = c.nc.Close()
		}
		atomic.StoreInt32(&c.connected, disconnected)
		return err
	}
	return c.pool.closeConnection(c)
}

func (c *connection) expired() bool {
	now := time.Now()
	idleDeadline, ok := c.idleDeadline.Load().(time.Time)
	if ok && now.After(idleDeadline) {
		return true
	}

	if !c.lifetimeDeadline.IsZero() && now.After(c.lifetimeDeadline) {
		return true
	}

	return atomic.LoadInt32(&c.connected) == disconnected
}

func (c *connection) bumpIdleDeadline() {
	if c.idleTimeout > 0 {
		c.idleDeadline.Store(time.Now().Add(c.idleTimeout))
	}
}

// initConnection is an adapter used during connection initialization. It has the minimum
// functionality necessary to implement the driver.Connection interface, which is required to pass a
// *connection to a Handshaker.
type initConnection struct{ *connection }

var _ driver.Connection = initConnection{}

func (c initConnection) Description() description.Server {
	if c.connection == nil {
		return description.Server{}
	}
	return c.connection.desc
}
func (c initConnection) Close() error             { return nil }
func (c initConnection) ID() string               { return c.id }
func (c initConnection) Address() address.Address { return c.addr }
func (c initConnection) LocalAddress() address.Address {
	if c.connection == nil || c.nc == nil {
		return address.Address("0.0.0.0")
	}
	return address.Address(c.nc.LocalAddr().String())
}
func (c initConnection) WriteWireMessage(ctx context.Context, wm []byte) error {
	return c.writeWireMessage(ctx, wm)
}
func (c initConnection) ReadWireMessage(ctx context.Context, dst []byte) ([]byte, error) {
	return c.readWireMessage(ctx, dst)
}

// Connection implements the driver.Connection interface to allow reading and writing wire
// messages and the driver.Expirable interface to allow expiring.
type Connection struct {
	*connection
	s *Server

	mu sync.RWMutex
}

var _ driver.Connection = (*Connection)(nil)
var _ driver.Expirable = (*Connection)(nil)

// WriteWireMessage handles writing a wire message to the underlying connection.
func (c *Connection) WriteWireMessage(ctx context.Context, wm []byte) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.connection == nil {
		return ErrConnectionClosed
	}
	return c.writeWireMessage(ctx, wm)
}

// ReadWireMessage handles reading a wire message from the underlying connection. The dst parameter
// will be overwritten with the new wire message.
func (c *Connection) ReadWireMessage(ctx context.Context, dst []byte) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.connection == nil {
		return dst, ErrConnectionClosed
	}
	return c.readWireMessage(ctx, dst)
}

// CompressWireMessage handles compressing the provided wire message using the underlying
// connection's compressor. The dst parameter will be overwritten with the new wire message. If
// there is no compressor set on the underlying connection, then no compression will be performed.
func (c *Connection) CompressWireMessage(src, dst []byte) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.connection == nil {
		return dst, ErrConnectionClosed
	}
	if c.connection.compressor == wiremessage.CompressorNoOp {
		return append(dst, src...), nil
	}
	_, reqid, respto, origcode, rem, ok := wiremessage.ReadHeader(src)
	if !ok {
		return dst, errors.New("wiremessage is too short to compress, less than 16 bytes")
	}
	idx, dst := wiremessage.AppendHeaderStart(dst, reqid, respto, wiremessage.OpCompressed)
	dst = wiremessage.AppendCompressedOriginalOpCode(dst, origcode)
	dst = wiremessage.AppendCompressedUncompressedSize(dst, int32(len(rem)))
	dst = wiremessage.AppendCompressedCompressorID(dst, c.connection.compressor)
	opts := driver.CompressionOpts{
		Compressor: c.connection.compressor,
		ZlibLevel:  c.connection.zliblevel,
		ZstdLevel:  c.connection.zstdLevel,
	}
	compressed, err := driver.CompressPayload(rem, opts)
	if err != nil {
		return nil, err
	}
	dst = wiremessage.AppendCompressedCompressedMessage(dst, compressed)
	return bsoncore.UpdateLength(dst, idx, int32(len(dst[idx:]))), nil
}

// Description returns the server description of the server this connection is connected to.
func (c *Connection) Description() description.Server {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.connection == nil {
		return description.Server{}
	}
	return c.desc
}

// Close returns this connection to the connection pool. This method may not closeConnection the underlying
// socket.
func (c *Connection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.connection == nil {
		return nil
	}
	if c.s != nil {
		defer c.s.sem.Release(1)
	}
	err := c.pool.put(c.connection)
	c.connection = nil
	return err
}

// Expire closes this connection and will closeConnection the underlying socket.
func (c *Connection) Expire() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.connection == nil {
		return nil
	}
	if c.s != nil {
		c.s.sem.Release(1)
	}
	err := c.close()
	c.connection = nil
	return err
}

// Alive returns if the connection is still alive.
func (c *Connection) Alive() bool {
	return c.connection != nil
}

// ID returns the ID of this connection.
func (c *Connection) ID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.connection == nil {
		return "<closed>"
	}
	return c.id
}

// Address returns the address of this connection.
func (c *Connection) Address() address.Address {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.connection == nil {
		return address.Address("0.0.0.0")
	}
	return c.addr
}

// LocalAddress returns the local address of the connection
func (c *Connection) LocalAddress() address.Address {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.connection == nil || c.nc == nil {
		return address.Address("0.0.0.0")
	}
	return address.Address(c.nc.LocalAddr().String())
}

var notMasterCodes = []int32{10107, 13435}
var recoveringCodes = []int32{11600, 11602, 13436, 189, 91}

func configureTLS(ctx context.Context, nc net.Conn, addr address.Address, config *tls.Config) (net.Conn, error) {
	if !config.InsecureSkipVerify {
		hostname := addr.String()
		colonPos := strings.LastIndex(hostname, ":")
		if colonPos == -1 {
			colonPos = len(hostname)
		}

		hostname = hostname[:colonPos]
		config.ServerName = hostname
	}

	client := tls.Client(nc, config)

	errChan := make(chan error, 1)
	go func() {
		errChan <- client.Handshake()
	}()

	select {
	case err := <-errChan:
		if err != nil {
			return nil, err
		}

		if ocspErr := verifyOCSP(client.ConnectionState()); ocspErr != nil {
			return nil, ocspErr
		}
	case <-ctx.Done():
		return nil, errors.New("server connection cancelled/timeout during TLS handshake")
	}
	return client, nil
}

var (
	ocspExtensionID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
)

func verifyOCSP(connState tls.ConnectionState) error {
	if len(connState.VerifiedChains) == 0 {
		return fmt.Errorf("no verified certificate chains reported after TLS handshake")
	}

	certChain := connState.VerifiedChains[0]
	if numCerts := len(certChain); numCerts < 2 {
		// TODO: maybe return nil here
		return fmt.Errorf("certificate chain contained too few certificates: %d (at least 2 expected)", numCerts)
	}

	serverCert := certChain[0]
	caCert := certChain[1]

	var mustStaple bool // true if the server certificate has the must staple extension
	for _, extension := range serverCert.Extensions {
		if extension.Id.Equal(ocspExtensionID) {
			mustStaple = true
			break
		}
	}

	// If the server has a Must-Staple certificate and the server does not present a stapled OCSP response, error.
	if mustStaple && len(connState.OCSPResponse) == 0 {
		return errors.New("server provided a certificate with the Must-Staple extension but did not provide a stapled OCSP response")
	}

	// The server presented a stapled OCSP response.
	if len(connState.OCSPResponse) > 0 {
		if err := verifyOCSPResponse(serverCert, caCert, connState.OCSPResponse); err != nil {
			return fmt.Errorf("error verifying stapled OCSP response: %v", err)
		}
		return nil

		// // If the server staples an OCSP response that does not cover the certificate it presents, error.
		// parsedResponse, err := ocsp.ParseResponseForCert(connState.OCSPResponse, serverCert, caCert)
		// if err != nil {
		// 	return fmt.Errorf("server returned invalid OCSP staple data: %v", err)
		// }
		// // TODO: not sure if this is necessary
		// if err = parsedResponse.CheckSignatureFrom(caCert); err != nil {
		// 	return fmt.Errorf("server returned OCSP staple with invalid signature: %v", err)
		// }
		// if parsedResponse.Status != ocsp.Good {
		// 	return errors.New("server returned OCSP staple indiciating that the certificate has been revoked")
		// }

		// // If the server staples an OCSP response that covers the certificate it presents, accept the stapled OCSP
		// // response and validate all of the certificates that are presented in the response.
		// // TODO: presenting multiple certs in an OCSP staple is not possible right now because of openssl limitations.
		// // Do we have to do anything here?
		// return nil
	}

	// TODO: figure out status of OCSP/CRL cache access (steps 4-6 in the OCSP spec)

	if len(serverCert.OCSPServer) == 0 {
		return nil
	}

	// If the server’s certificate remains unvalidated and that certificate has an OCSP endpoint, the driver SHOULD
	// reach out to the OCSP endpoint specified and attempt to validate that certificate.
	// TODO: spec only mentions single OCSP endpoint, but x509.Certificate.OCSPServer is []string
	for _, ocspEndpoint := range serverCert.OCSPServer {
		ocspRequest, err := ocsp.CreateRequest(serverCert, caCert, nil)
		if err != nil {
			return fmt.Errorf("error creating OCSP request: %v", err)
		}

		// TODO: always POST?
		httpResponse, err := http.Post(ocspEndpoint, "application/ocsp-request", bytes.NewBuffer(ocspRequest))
		if err != nil {
			// TODO: this just means we couldn't contact the responder. should probably soft fail and continue without
			// propagating error
			return fmt.Errorf("error contacting OCSP responder: %v", err)
		}
		defer func() {
			_ = httpResponse.Body.Close()
		}()

		ocspResponse, err := ioutil.ReadAll(httpResponse.Body)
		if err != nil {
			return fmt.Errorf("error reading response from OCSP responder: %v", err)
		}
		_ = ocspResponse
		if err = verifyOCSPResponse(serverCert, caCert, ocspResponse); err != nil {
			return fmt.Errorf("error verifying respose from OCSP responder: %v", err)
			return err
		}
	}

	return nil
}

func verifyOCSPResponse(serverCert, caCert *x509.Certificate, ocspResponse []byte) error {
	// If the server staples an OCSP response that does not cover the certificate it presents, error.
	parsedResponse, err := ocsp.ParseResponseForCert(ocspResponse, serverCert, caCert)
	if err != nil {
		return fmt.Errorf("server returned invalid OCSP staple data: %v", err)
	}
	// TODO: not sure if this is necessary
	if caCert != nil {
		if err = parsedResponse.CheckSignatureFrom(caCert); err != nil {
			return fmt.Errorf("server returned OCSP staple with invalid signature: %v", err)
		}
	}
	if parsedResponse.Status != ocsp.Good {
		return errors.New("server returned OCSP staple indiciating that the certificate has been revoked")
	}

	// If the server staples an OCSP response that covers the certificate it presents, accept the stapled OCSP
	// response and validate all of the certificates that are presented in the response.
	// TODO: presenting multiple certs in an OCSP staple is not possible right now because of openssl limitations.
	// Do we have to do anything here?
	return nil
}

// func verifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
// 	// Per documentation for the tls.Config.VerifyPeerCertificate field (https://golang.org/pkg/crypto/tls/#Config),
// 	// the verifiedChains argument will be nil if InsecureSkipVerify is set, so we return without doing any
// 	// additional checking.
// 	if verifiedChains == nil {
// 		return nil
// 	}

// 	return nil
// }

// func verifyOCSP(connState tls.ConnectionState) error {
// if len(connState.OCSPResponse) == 0 {
// 	return nil
// }

// for _, chain := range connState.VerifiedChains {
// 	if n := len(chain); n < 2 {
// 		return fmt.Errorf("verified chain contained too few certificates: %d", n)
// 	}

// 	serverCert := chain[0]
// 	caCert := chain[1]

// 	resp, err := ocsp.ParseResponseForCert(connState.OCSPResponse, serverCert, caCert)
// 	if err != nil {
// 		return fmt.Errorf("invalid ocsp staple data: %v", err)
// 	}
// 	if err := resp.CheckSignatureFrom(caCert); err != nil {
// 		return fmt.Errorf("invalid ocsp signature: %v", err)
// 	}
// 	if resp.Status != ocsp.Good {
// 		return fmt.Errorf("certificate revoked /cn=%s", serverCert.Subject.CommonName)
// 	}
// }

// return nil
// }
