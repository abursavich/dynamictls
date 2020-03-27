// Copyright 2020 Andrew Bursavich. All rights reserved.
// Use of this source code is governed by The MIT License
// which can be found in the LICENSE file.

package dynamictls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/abursavich/dynamictls/internal/tlstest"
	"github.com/google/go-cmp/cmp"
)

func TestOptions(t *testing.T) {
	dir, err := ioutil.TempDir("", "")
	check(t, "Failed to create directory", err)
	defer os.RemoveAll(dir)

	clientCA, clientCACertPEMBlock, _, err := tlstest.GenerateCert(nil)
	check(t, "Failed to create client CA", err)
	clientCAFile := createFile(t, dir, "clients.pem", clientCACertPEMBlock)
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(clientCA.Leaf)

	rootCA, rootCACertPEMBlock, _, err := tlstest.GenerateCert(nil)
	check(t, "Failed to create root CA", err)
	rootCAFile := createFile(t, dir, "roots.pem", rootCACertPEMBlock)
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(rootCA.Leaf)

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
			c, err := NewConfig(append(tt.options, WithErrorLogger(t))...)
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
			if !reflect.DeepEqual(tt.cfg.RootCAs, got.RootCAs) {
				t.Fatal("Unexpected RootCAs")
			}
			if !reflect.DeepEqual(tt.cfg.ClientCAs, got.ClientCAs) {
				t.Fatal("Unexpected ClientCAs")
			}
			if diff := cmp.Diff(tt.cfg.NextProtos, got.NextProtos); diff != "" {
				t.Fatalf("Unexpected NextProtos:\n%s", diff)
			}
		})
	}
}

func TestKubernetes(t *testing.T) {
	// See AtomicWriter for details of secret update algorithm used by kubelet:
	// https://godoc.org/k8s.io/kubernetes/pkg/volume/util#AtomicWriter.Write

	type result struct {
		config *tls.Config
		err    error
	}

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
	ch := make(chan result, 1)
	notifyFn := func(config *tls.Config, err error) {
		select {
		case <-ch:
		default:
		}
		ch <- result{config: config, err: err}
	}
	wantCert := func(want *tls.Certificate) {
		t.Helper()
		timeout := time.NewTimer(5 * time.Second)
		defer timeout.Stop()
		var err error
		for {
			select {
			case res := <-ch:
				if res.err != nil {
					// An error can occur if a filesystem event triggers a reload and a
					// symlink flip happens between reading the public and private keys.
					// The keys won't match due to this race, but a subsequent reload
					// will also be triggered and they will match the next time.
					t.Logf("Unexpected error, may be transient: %v", res.err)
					err = res.err
					continue
				}
				if res.config == nil {
					t.Fatal("Config missing")
				}
				if len(res.config.Certificates) == 0 {
					t.Fatal("Config missing certs")
				}
				got := res.config.Certificates[0]
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
		WithNotifyFunc(notifyFn),
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
	lis, err := net.Listen("tcp", "localhost:0")
	check(t, "Failed to create listener", err)
	defer lis.Close()
	_, port, err := net.SplitHostPort(lis.Addr().String())
	check(t, "Failed to get listen port", err)
	addr := "localhost:" + port
	_, serverCertPEM, serverKeyPEM, err := tlstest.GenerateCert(&tlstest.CertOptions{
		Template: &x509.Certificate{
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageServerAuth,
			},
			DNSNames: []string{"localhost", addr},
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
		WithErrorLogger(t),
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
		WithErrorLogger(t),
		WithHTTP(),
	)
	check(t, "Failed to create client TLS config", err)
	defer clientCfg.Close()

	// create server
	const msg = "hello, test"
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprint(w, msg)
	})
	go http.Serve(NewListener(lis, serverCfg), handler) //nolint:errcheck

	// create client
	client := &http.Client{
		Transport: &http.Transport{
			DialTLSContext:    clientCfg.Dial,
			ForceAttemptHTTP2: true,
		},
	}
	defer client.CloseIdleConnections()

	// make a request
	resp, err := client.Get("https://" + addr)
	check(t, "Failed HTTP request", err)
	buf, err := ioutil.ReadAll(resp.Body)
	check(t, "Failed reading HTTP response body", err)
	if got := string(buf); got != msg {
		t.Fatalf("Unexpected response; want: %q; got: %q", msg, got)
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
