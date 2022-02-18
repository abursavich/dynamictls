// SPDX-License-Identifier: MIT
//
// Copyright 2020 Andrew Bursavich. All rights reserved.
// Use of this source code is governed by The MIT License
// which can be found in the LICENSE file.

package dynamictls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"bursavich.dev/dynamictls/internal/tlstest"
	"github.com/google/go-cmp/cmp"
)

func TestOptions(t *testing.T) {
	// create temp dir
	dir, err := ioutil.TempDir("", "")
	check(t, "Failed to create directory", err)
	defer os.RemoveAll(dir)

	// create client certificate authority
	clientCA, clientCACertPEMBlock, _, err := tlstest.GenerateCert(nil)
	check(t, "Failed to create client CA", err)
	clientCAFile := createFile(t, dir, "clients.pem", clientCACertPEMBlock)
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(clientCA.Leaf)

	// create root certificate authority
	rootCA, rootCACertPEMBlock, _, err := tlstest.GenerateCert(nil)
	check(t, "Failed to create root CA", err)
	rootCAFile := createFile(t, dir, "roots.pem", rootCACertPEMBlock)
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(rootCA.Leaf)

	// create certificate
	cert, certPEMBlock, keyPEMBlock, err := tlstest.GenerateCert(&tlstest.CertOptions{Parent: rootCA})
	check(t, "Failed to create certificate", err)
	certFile := createFile(t, dir, "cert.pem", certPEMBlock)
	keyFile := createFile(t, dir, "key.pem", keyPEMBlock)
	certs := []tls.Certificate{*cert}
	certOption := WithCertificate(certFile, keyFile)

	tests := []struct {
		desc    string
		options []Option
		cfg     *tls.Config
		err     bool
	}{
		{
			desc: "None",
			err:  true,
		},
		{
			desc:    "WithCertificate",
			options: []Option{certOption},
			cfg:     &tls.Config{Certificates: certs},
		},
		{
			desc:    "WithCertificate Invalid Key Pair",
			options: []Option{WithCertificate(rootCAFile, keyFile)},
			err:     true,
		},
		{
			desc: "WithCertificate Nonexistent Directory",
			options: []Option{WithCertificate(
				filepath.Join(dir, "nonexistent/cert.pem"),
				filepath.Join(dir, "nonexistent/key.pem"),
			)},
			err: true,
		},
		{
			desc: "WithCertificate Nonexistent Cert File",
			options: []Option{WithCertificate(
				filepath.Join(dir, "nonexistent-cert.pem"),
				keyFile,
			)},
			err: true,
		},
		{
			desc: "WithCertificate Nonexistent Key File",
			options: []Option{WithCertificate(
				certFile,
				filepath.Join(dir, "nonexistent-key.pem"),
			)},
			err: true,
		},
		{
			desc:    "WithRootCAs",
			options: []Option{WithRootCAs(rootCAFile)},
			cfg:     &tls.Config{RootCAs: rootCAs},
		},
		{
			desc: "WithRootCAs Nonexistent Directory",
			options: []Option{WithRootCAs(
				filepath.Join(dir, "nonexistent/roots.pem"),
			)},
			err: true,
		},
		{
			desc: "WithRootCAs Nonexistent CA File",
			options: []Option{WithRootCAs(
				filepath.Join(dir, "nonexistent-roots.pem"),
			)},
			err: true,
		},
		{
			desc:    "WithClientCAs",
			options: []Option{WithClientCAs(clientCAFile)},
			cfg:     &tls.Config{ClientCAs: clientCAs},
		},
		{
			desc: "WithClientCAs Nonexistent Directory",
			options: []Option{WithClientCAs(
				filepath.Join(dir, "nonexistent/clients.pem"),
			)},
			err: true,
		},
		{
			desc: "WithClientCAs Nonexistent CA File",
			options: []Option{WithClientCAs(
				filepath.Join(dir, "nonexistent-clients.pem"),
			)},
			err: true,
		},
		{
			desc:    "WithHTTP1",
			options: []Option{certOption, WithHTTP1()},
			cfg: &tls.Config{
				Certificates: certs,
				NextProtos:   []string{"http/1.1"},
			},
		},
		{
			desc:    "WithHTTP2",
			options: []Option{certOption, WithHTTP2()},
			cfg: &tls.Config{
				Certificates: certs,
				NextProtos:   []string{"h2"},
			},
		},
		{
			desc:    "WithHTTP1 and WithHTTP2",
			options: []Option{certOption, WithHTTP1(), WithHTTP2()},
			cfg: &tls.Config{
				Certificates: certs,
				NextProtos:   []string{"h2", "http/1.1"},
			},
		},
		{
			desc:    "WithHTTP",
			options: []Option{certOption, WithHTTP()},
			cfg: &tls.Config{
				Certificates: certs,
				NextProtos:   []string{"h2", "http/1.1"},
			},
		},
		{
			desc: "WithHTTP Invalid Ciphers",
			options: []Option{
				certOption,
				WithHTTP(),
				WithBase(&tls.Config{
					CipherSuites: []uint16{tls.TLS_RSA_WITH_RC4_128_SHA},
				}),
			},
			err: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			c, err := NewConfig(append(tt.options, WithLogger(tlstest.Logr(t)))...)
			if err != nil {
				if tt.err {
					return // error is expected
				}
				t.Fatalf("Unexpected error: %v", err)
			}
			defer c.Close()
			if tt.err {
				t.Fatal("Expected an error")
			}
			got := c.Config()
			if !reflect.DeepEqual(tt.cfg.Certificates, got.Certificates) {
				t.Fatal("Unexpected Certificates")
			}
			if !certPoolEqual(tt.cfg.RootCAs, got.RootCAs) {
				t.Fatal("Unexpected RootCAs")
			}
			if !certPoolEqual(tt.cfg.ClientCAs, got.ClientCAs) {
				t.Fatal("Unexpected ClientCAs")
			}
			if diff := cmp.Diff(tt.cfg.NextProtos, got.NextProtos); diff != "" {
				t.Fatalf("Unexpected NextProtos:\n%s", diff)
			}
		})
	}
}

func certPoolEqual(x, y *x509.CertPool) bool {
	var xs, ys [][]byte
	if x != nil {
		xs = x.Subjects()
	}
	if y != nil {
		ys = x.Subjects()
	}
	return reflect.DeepEqual(xs, ys)
}

type testObserver struct {
	configCh chan *tls.Config
	errCh    chan error
}

func newTestObserver() *testObserver {
	return &testObserver{
		configCh: make(chan *tls.Config, 1),
		errCh:    make(chan error, 1),
	}
}

func (o *testObserver) ObserveConfig(cfg *tls.Config) {
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	select {
	case <-timeout.C:
	case o.configCh <- cfg:
	}
}

func (o *testObserver) ObserveReadError(err error) {
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	select {
	case <-timeout.C:
	case o.errCh <- err:
	}
}

func TestNotifyError(t *testing.T) {
	// create temp dir
	dir, err := ioutil.TempDir("", "")
	check(t, "Failed to create directory", err)
	defer os.RemoveAll(dir)

	// create certificate authority
	_, certPEMBlock, keyPEMBlock, err := tlstest.GenerateCert(nil)
	check(t, "Failed to create certificate", err)
	certFile := createFile(t, dir, "cert.pem", certPEMBlock)
	keyFile := createFile(t, dir, "key.pem", keyPEMBlock)

	// create config
	obs := newTestObserver()
	cfg, err := NewConfig(
		WithCertificate(certFile, keyFile),
		WithObserver(obs),
	)
	check(t, "Failed to initialize config", err)
	defer cfg.Close()

	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()

	select {
	case cfg := <-obs.configCh:
		if cfg == nil {
			t.Fatalf("Unexpected nil config")
		}
	case err := <-obs.errCh:
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
	case <-timeout.C:
		t.Fatal("Timeout waiting for notification")
	}

	check(t, "Failed to remove cert file", os.Remove(certFile))

	select {
	case cfg := <-obs.configCh:
		if cfg != nil {
			t.Fatalf("Unexpected config")
		}
	case err := <-obs.errCh:
		if err == nil {
			t.Fatal("Expected an error after deleting certs")
		}
	case <-timeout.C:
		t.Fatal("Timeout waiting for notification")
	}

	cfg.Close() // idempotent
	cfg.Close() // idempotent
}

func TestKubernetes(t *testing.T) {
	// See AtomicWriter for details of secret update algorithm used by kubelet:
	// https://godoc.org/k8s.io/kubernetes/pkg/volume/util#AtomicWriter.Write

	ca, caCertPEMBlock, _, err := tlstest.GenerateCert(nil)
	check(t, "Failed to create CA", err)
	cert0, certPEMBlock0, keyPEMBlock0, err := tlstest.GenerateCert(&tlstest.CertOptions{Parent: ca})
	check(t, "Failed to create certificate", err)
	cert1, certPEMBlock1, keyPEMBlock1, err := tlstest.GenerateCert(&tlstest.CertOptions{Parent: ca})
	check(t, "Failed to create certificate", err)

	dir, err := ioutil.TempDir("", "")
	check(t, "Failed to create directory", err)
	defer os.RemoveAll(dir)

	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	caFile := filepath.Join(dir, "ca.pem")

	// initialize data
	data := filepath.Join(dir, "..data")
	for _, name := range []string{"cert.pem", "key.pem", "ca.pem"} {
		check(t, "Failed to create symlink", os.Symlink(filepath.Join(data, name), filepath.Join(dir, name)))
	}
	data0 := filepath.Join(dir, "..data_0")
	createDir(t, data0, map[string][]byte{
		"cert.pem": certPEMBlock0,
		"key.pem":  keyPEMBlock0,
		"ca.pem":   caCertPEMBlock,
	})
	check(t, "Failed to create symlink", os.Symlink(data0, data))

	// create config
	obs := newTestObserver()
	wantCert := func(want *tls.Certificate) {
		t.Helper()
		timeout := time.NewTimer(5 * time.Second)
		defer timeout.Stop()
		var err error
		for {
			select {
			case err = <-obs.errCh:
				// An error can occur if a filesystem event triggers a reload and a
				// symlink flip happens between reading the public and private keys.
				// The keys won't match due to this race, but a subsequent reload
				// will also be triggered and they will match the next time.
				t.Logf("Unexpected error, may be transient: %v", err)
				continue
			case cfg := <-obs.configCh:
				if cfg == nil {
					t.Fatal("Config missing")
				}
				if len(cfg.Certificates) == 0 {
					t.Fatal("Config missing certs")
				}
				got := cfg.Certificates[0]
				if !reflect.DeepEqual(got.Certificate, want.Certificate) {
					t.Fatal("Unexpected cert")
				}
				if !reflect.DeepEqual(got.PrivateKey, want.PrivateKey) {
					t.Fatal("Unexpected key")
				}
				return // OK
			case <-timeout.C:
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
				t.Fatal("Timeout waiting for certs")
			}
		}
	}

	cfg, err := NewConfig(
		WithCertificate(certFile, keyFile),
		WithRootCAs(caFile),
		WithObserver(obs),
	)
	check(t, "Failed to initialize config", err)
	defer cfg.Close()
	wantCert(cert0)

	// update data
	data1 := filepath.Join(dir, "..data_1")
	createDir(t, data1, map[string][]byte{
		"cert.pem": certPEMBlock1,
		"key.pem":  keyPEMBlock1,
		"ca.pem":   caCertPEMBlock,
	})
	dataTmp := filepath.Join(dir, "..data_tmp")
	check(t, "Failed to create symlink", os.Symlink(data1, dataTmp))
	check(t, "Failed to rename symlink", os.Rename(dataTmp, data))
	wantCert(cert1)
}

func TestMTLS(t *testing.T) {
	// create temp dir
	dir, err := ioutil.TempDir("", "")
	check(t, "Failed to create directory", err)
	defer os.RemoveAll(dir)

	// create certificate authority
	ca, caCertPEM, _, err := tlstest.GenerateCert(nil)
	check(t, "Failed to create CA", err)
	caFile := createFile(t, dir, "certs.pem", caCertPEM)

	// create server config
	_, serverCertPEM, serverKeyPEM, err := tlstest.GenerateCert(&tlstest.CertOptions{
		Template: &x509.Certificate{
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageServerAuth,
			},
			DNSNames: []string{"localhost"},
		},
		Parent: ca,
	})
	check(t, "Failed to create server certificate", err)
	serverCfg, err := NewConfig(
		WithBase(&tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
		}),
		WithCertificate(
			createFile(t, dir, "server.crt", serverCertPEM),
			createFile(t, dir, "server.key", serverKeyPEM),
		),
		WithRootCAs(caFile),
		WithClientCAs(caFile),
		WithLogger(tlstest.Logr(t)),
		WithHTTP(),
	)
	check(t, "Failed to create server TLS config", err)
	defer serverCfg.Close()

	// create client config
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
	clientCfg, err := NewConfig(
		WithCertificate(
			createFile(t, dir, "client.crt", clientCertPEM),
			createFile(t, dir, "client.key", clientKeyPEM),
		),
		WithRootCAs(caFile),
		WithLogger(tlstest.Logr(t)),
		WithHTTP(),
	)
	check(t, "Failed to create client TLS config", err)
	defer clientCfg.Close()

	// create server
	lis, err := serverCfg.Listen(context.Background(), "tcp", "localhost:0")
	check(t, "Failed to create listener", err)
	defer lis.Close()
	const msg = "hello, test"
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprint(w, msg)
	})
	go http.Serve(lis, handler) //nolint:errcheck

	// create client
	client := &http.Client{
		// NB: DialTLSContext added in go 1.14, httpTransport uses DialTLS in previous go versions.
		// TODO: Remove when go 1.15 is released.
		Transport: httpTransport(clientCfg),
	}
	defer client.CloseIdleConnections()

	// make a request
	_, port, err := net.SplitHostPort(lis.Addr().String())
	check(t, "Failed to get listen port", err)
	resp, err := client.Get("https://localhost:" + port)
	check(t, "Failed HTTP request", err)
	buf, err := ioutil.ReadAll(resp.Body)
	check(t, "Failed reading HTTP response body", err)
	if got := string(buf); got != msg {
		t.Fatalf("Unexpected response; want: %q; got: %q", msg, got)
	}
}

func TestListenError(t *testing.T) {
	// create temp dir
	dir, err := ioutil.TempDir("", "")
	check(t, "Failed to create directory", err)
	defer os.RemoveAll(dir)

	// create self-signed certificate
	_, certPEMBlock, keyPEMBlock, err := tlstest.GenerateCert(nil)
	check(t, "Failed to create certificate", err)
	certFile := createFile(t, dir, "cert.pem", certPEMBlock)
	keyFile := createFile(t, dir, "key.pem", keyPEMBlock)

	// create config
	cfg, err := NewConfig(
		WithBase(&tls.Config{
			MinVersion: tls.VersionTLS12,
		}),
		WithHTTP2(),
		WithCertificate(certFile, keyFile),
		WithRootCAs(certFile),
		WithLogger(tlstest.Logr(t)),
	)
	check(t, "Failed to create dynamic TLS config", err)
	defer cfg.Close()

	if lis, err := cfg.Listen(context.Background(), "unknown", "unknown"); err == nil {
		lis.Close()
		t.Fatal("Expected an error")
	}
}

func TestDialErrors(t *testing.T) {
	// create temp dir
	dir, err := ioutil.TempDir("", "")
	check(t, "Failed to create directory", err)
	defer os.RemoveAll(dir)

	// create certificate authority
	_, caCertPEM, _, err := tlstest.GenerateCert(nil)
	check(t, "Failed to create CA", err)
	caFile := createFile(t, dir, "roots.pem", caCertPEM)

	// create config
	cfg, err := NewConfig(
		WithBase(&tls.Config{
			MinVersion: tls.VersionTLS12,
		}),
		WithHTTP2(),
		WithRootCAs(caFile),
		WithLogger(tlstest.Logr(t)),
	)
	check(t, "Failed to create dynamic TLS config", err)
	defer cfg.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dialErr := fmt.Errorf("dial test error")
	cfg.dialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, dialErr
	}
	if _, err := cfg.Dial(ctx, "tcp", "localhost"); err != dialErr {
		t.Fatalf("Dial error; want: %v; got: %v", dialErr, err)
	}

	cfg.dialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		return errConn{}, nil
	}
	if _, err = cfg.Dial(ctx, "tcp", "localhost"); err == nil {
		t.Fatal("Expected a handshake error")
	}

	cfg.dialFunc = func(_ context.Context, network, address string) (net.Conn, error) {
		return &ctxWaitConn{ctx: ctx}, nil // block handshake until deferred close
	}
	doneCtx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = cfg.Dial(doneCtx, "tcp", "localhost")
	if want := context.Canceled; err != want {
		t.Fatalf("Dial error; want: %v; got: %v", want, err)
	}
}

func createDir(t *testing.T, dir string, files map[string][]byte) {
	t.Helper()
	check(t, "Failed to make directory", os.Mkdir(dir, os.ModePerm))
	for name, buf := range files {
		createFile(t, dir, name, buf)
	}
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
