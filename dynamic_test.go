// Copyright 2020 Andrew Bursavich. All rights reserved.
// Use of this source code is governed by The MIT License
// which can be found in the LICENSE file.

package dynamictls

import (
	"crypto/tls"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/abursavich/dynamictls/internal/tlstest"
)

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
		select {
		case res := <-ch:
			if res.err != nil {
				t.Fatalf("Unexpected error: %v", err)
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
		case <-time.After(10 * time.Second):
			t.Fatal("Timeout waiting for certs")
		}
	}

	cfg, err := NewConfig(
		WithCertificate(certFile, keyFile),
		WithRootCAs(caFile),
		WithNotifyFunc(notifyFn),
		WithErrorLogger(t),
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

func createDir(t *testing.T, dir string, files map[string][]byte) {
	t.Helper()
	check(t, "Failed to make directory", os.Mkdir(dir, os.ModePerm))
	for name, buf := range files {
		check(t, "Failed to write file", ioutil.WriteFile(filepath.Join(dir, name), buf, os.ModePerm))
	}
}

func check(t *testing.T, msg string, err error) {
	if err != nil {
		t.Helper()
		t.Fatalf("%s: %v", msg, err)
	}
}
