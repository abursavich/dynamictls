// Copyright 2020 Andrew Bursavich. All rights reserved.
// Use of this source code is governed by The MIT License
// which can be found in the LICENSE file.

package grpctls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/abursavich/dynamictls"
	"github.com/abursavich/dynamictls/internal/tlstest"
	"google.golang.org/grpc"

	pb "google.golang.org/grpc/test/grpc_testing"
)

func TestInvalidConfig(t *testing.T) {
	// create temp dir
	dir, err := ioutil.TempDir("", "")
	check(t, "Failed to create directory", err)
	defer os.RemoveAll(dir)

	// create certificate authority
	_, caCertPEM, _, err := tlstest.GenerateCert(nil)
	check(t, "Failed to create CA", err)
	caFile := createFile(t, dir, "certs.pem", caCertPEM)

	// create config
	cfg, err := dynamictls.NewConfig(
		dynamictls.WithBase(&tls.Config{
			CipherSuites: []uint16{tls.TLS_RSA_WITH_RC4_128_SHA},
		}),
		dynamictls.WithClientCAs(caFile),
		dynamictls.WithErrorLogger(t),
	)
	check(t, "Failed to create dynamic TLS config", err)
	defer cfg.Close()

	if _, err := NewCredentials(cfg); err == nil {
		t.Fatal("Expected an error")
	}
}

func TestHandshakeErrors(t *testing.T) {
	// create temp dir
	dir, err := ioutil.TempDir("", "")
	check(t, "Failed to create directory", err)
	defer os.RemoveAll(dir)

	// create certificates
	ca, caCertPEM, _, err := tlstest.GenerateCert(nil)
	check(t, "Failed to create CA", err)
	caFile := createFile(t, dir, "roots.pem", caCertPEM)
	_, certPEM, keyPEM, err := tlstest.GenerateCert(&tlstest.CertOptions{
		Template: &x509.Certificate{
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageServerAuth,
			},
		},
		Parent: ca,
	})
	check(t, "Failed to create certificate", err)
	certFile := createFile(t, dir, "cert.pem", certPEM)
	keyFile := createFile(t, dir, "key.pem", keyPEM)

	// create config
	cfg, err := dynamictls.NewConfig(
		dynamictls.WithBase(&tls.Config{
			MinVersion: tls.VersionTLS12,
		}),
		dynamictls.WithHTTP2(),
		dynamictls.WithCertificate(certFile, keyFile),
		dynamictls.WithRootCAs(caFile),
		dynamictls.WithErrorLogger(t),
	)
	check(t, "Failed to create dynamic TLS config", err)
	defer cfg.Close()

	creds, err := NewCredentials(cfg)
	check(t, "Failed to create credentials", err)

	if _, _, err := creds.ServerHandshake(errConn{}); err == nil {
		t.Fatal("ServerHandshake expected an error")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, _, err := creds.ClientHandshake(ctx, "foobar", errConn{}); err == nil {
		t.Fatal("ClientHandshake expected an error")
	}

	doneCtx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = creds.ClientHandshake(doneCtx, "foobar", &ctxWaitConn{ctx: ctx})
	if want := context.Canceled; err != want {
		t.Fatalf("ClientHandshake error; want: %v; got: %v", want, err)
	}
}

type ctxWaitConn struct {
	ctx context.Context
	errConn
}

func (c *ctxWaitConn) Read(b []byte) (n int, err error) {
	<-c.ctx.Done()
	return c.errConn.Read(b)
}

func (c *ctxWaitConn) Write(b []byte) (n int, err error) {
	<-c.ctx.Done()
	return c.errConn.Write(b)
}

type errConn struct{}

func (errConn) Read(b []byte) (n int, err error)   { return 0, io.ErrClosedPipe }
func (errConn) Write(b []byte) (n int, err error)  { return 0, io.ErrClosedPipe }
func (errConn) Close() error                       { return nil }
func (errConn) LocalAddr() net.Addr                { return &net.UnixAddr{Net: "unix", Name: "/tmp/fake"} }
func (errConn) RemoteAddr() net.Addr               { return &net.UnixAddr{Net: "unix", Name: "/tmp/fake"} }
func (errConn) SetDeadline(t time.Time) error      { return nil }
func (errConn) SetReadDeadline(t time.Time) error  { return nil }
func (errConn) SetWriteDeadline(t time.Time) error { return nil }

func TestGRPC(t *testing.T) {
	// create temp dir
	dir, err := ioutil.TempDir("", "")
	check(t, "Failed to create directory", err)
	defer os.RemoveAll(dir)

	// create certificate authority
	ca, caCertPEM, _, err := tlstest.GenerateCert(nil)
	check(t, "Failed to create CA", err)
	caFile := createFile(t, dir, "certs.pem", caCertPEM)

	// create server
	_, serverCertPEM, serverKeyPEM, err := tlstest.GenerateCert(&tlstest.CertOptions{
		Template: &x509.Certificate{
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageServerAuth,
			},
			DNSNames: []string{"foobar"},
		},
		Parent: ca,
	})
	check(t, "Failed to create server certificate", err)
	serverCfg, err := dynamictls.NewConfig(
		dynamictls.WithBase(&tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
		}),
		dynamictls.WithCertificate(
			createFile(t, dir, "server.crt", serverCertPEM),
			createFile(t, dir, "server.key", serverKeyPEM),
		),
		dynamictls.WithRootCAs(caFile),
		dynamictls.WithClientCAs(caFile),
		dynamictls.WithErrorLogger(t),
	)
	check(t, "Failed to create server TLS config", err)
	defer serverCfg.Close()
	serverCreds, err := NewCredentials(serverCfg)
	check(t, "Failed to create server gRPC credentials", err)
	srv := grpc.NewServer(grpc.Creds(serverCreds))
	pb.RegisterTestServiceServer(srv, &testServiceServer{})
	lis, err := net.Listen("tcp", "localhost:0")
	check(t, "Failed to create listener", err)
	defer lis.Close()
	_, port, err := net.SplitHostPort(lis.Addr().String())
	check(t, "Failed to get listen port", err)
	defer srv.GracefulStop()
	go srv.Serve(lis) //nolint:errcheck

	// create client
	_, clientCertPEM, clientKeyPEM, err := tlstest.GenerateCert(&tlstest.CertOptions{
		Template: &x509.Certificate{
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageServerAuth, // not strictly required for clients
			},
		},
		Parent: ca,
	})
	check(t, "Failed to create client certificate", err)
	clientCfg, err := dynamictls.NewConfig(
		dynamictls.WithBase(&tls.Config{
			MinVersion: tls.VersionTLS13,
		}),
		dynamictls.WithCertificate(
			createFile(t, dir, "client.crt", clientCertPEM),
			createFile(t, dir, "client.key", clientKeyPEM),
		),
		dynamictls.WithRootCAs(caFile),
		dynamictls.WithErrorLogger(t),
	)
	check(t, "Failed to create client TLS config", err)
	defer clientCfg.Close()
	clientCreds, err := NewCredentials(clientCfg)
	check(t, "Failed to create client gRPC credentials", err)
	check(t, "Failed to override server name", clientCreds.OverrideServerName("foobar"))
	conn, err := grpc.Dial("localhost:"+port,
		grpc.WithTransportCredentials(clientCreds),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
	)
	check(t, "Failed to create connection", err)
	defer conn.Close()
	client := pb.NewTestServiceClient(conn)

	// make gRPC call
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = client.UnaryCall(ctx, &pb.SimpleRequest{})
	check(t, "Failed to make RPC", err)
}

func createFile(t *testing.T, dir, base string, buf []byte) string {
	t.Helper()
	path := filepath.Join(dir, base)
	check(t, "Failed to write file", ioutil.WriteFile(path, buf, os.ModePerm))
	return path
}

func check(t *testing.T, msg string, err error) {
	if err != nil {
		t.Helper()
		t.Fatalf("%s: %v", msg, err)
	}
}

type testServiceServer struct {
	pb.UnimplementedTestServiceServer
}

func (*testServiceServer) UnaryCall(ctx context.Context, req *pb.SimpleRequest) (*pb.SimpleResponse, error) {
	return &pb.SimpleResponse{Payload: req.Payload}, nil
}
