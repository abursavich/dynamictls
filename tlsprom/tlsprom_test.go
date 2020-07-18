// SPDX-License-Identifier: MIT
//
// Copyright 2020 Andrew Bursavich. All rights reserved.
// Use of this source code is governed by The MIT License
// which can be found in the LICENSE file.

package tlsprom

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/abursavich/dynamictls/internal/tlstest"
	"github.com/prometheus/client_golang/prometheus"
)

func TestCollector(t *testing.T) {
	m, err := NewMetrics()
	check(t, "Failed to create metrics", err)
	reg := prometheus.NewRegistry()
	check(t, "Failed to register metrics", reg.Register(m))
	fams, err := reg.Gather()
	check(t, "Failed to gather metrics", err)
	names := []string{
		updateErrorName,
		verifyErrorName,
		expirationName,
	}
	if want, got := len(names), len(fams); want != got {
		t.Fatalf("Expected %v metrics; got: %d", want, got)
	}
	sort.Strings(names)
	sort.Slice(fams, func(i, k int) bool {
		return fams[i].GetName() < fams[k].GetName()
	})
	for i, want := range names {
		if got := fams[i].GetName(); want != got {
			t.Fatalf("Unexpected metric name; want: %v; got: %v", want, got)
		}
	}
}

func TestMetricNames(t *testing.T) {
	tests := []struct {
		desc      string
		options   []Option
		namespace string
		subsystem string
	}{
		{
			desc:      "http_server",
			options:   []Option{WithHTTP(), WithServer()},
			namespace: "http",
			subsystem: "server",
		},
		{
			desc:      "http_client",
			options:   []Option{WithHTTP(), WithClient()},
			namespace: "http",
			subsystem: "client",
		},
		{
			desc:      "grpc_server",
			options:   []Option{WithGRPC(), WithServer()},
			namespace: "grpc",
			subsystem: "server",
		},
		{
			desc:      "grpc_client",
			options:   []Option{WithGRPC(), WithClient()},
			namespace: "grpc",
			subsystem: "client",
		},
		{
			desc:      "foo_bar",
			options:   []Option{WithNamespace("foo"), WithSubsystem("bar")},
			namespace: "foo",
			subsystem: "bar",
		},
		{
			desc:      "foo_server",
			options:   []Option{WithNamespace("foo"), WithServer()},
			namespace: "foo",
			subsystem: "server",
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			m, err := NewMetrics(tt.options...)
			check(t, "Failed to create metrics", err)
			for baseName, metric := range map[string]*gauge{
				updateErrorName: readGauge(t, m.updateError),
				verifyErrorName: readGauge(t, m.verifyError),
				expirationName:  readGauge(t, m.expiration),
			} {
				got := metric.name
				want := tt.namespace + "_" + tt.subsystem + "_" + baseName
				if got != want {
					t.Errorf("Unexpected metric name; got: %q; want: %q", got, want)
				}
			}
		})
	}
}

func TestUpdateError(t *testing.T) {
	m, err := NewMetrics()
	check(t, "Failed to create metrics", err)

	metric := readGauge(t, m.updateError)
	if got, want := metric.value, float64(0); got != want {
		t.Fatalf("Unexpected %s value: got: %v; want: %v", metric.name, metric.value, want)
	}

	m.Update(nil, fmt.Errorf("testing"))
	metric = readGauge(t, m.updateError)
	if got, want := metric.value, float64(1); got != want {
		t.Fatalf("Unexpected %s value: got: %v; want: %v", metric.name, metric.value, want)
	}

	m.Update(&tls.Config{}, nil)
	metric = readGauge(t, m.updateError)
	if got, want := metric.value, float64(0); got != want {
		t.Fatalf("Unexpected %s value: got: %v; want: %v", metric.name, metric.value, want)
	}
}

func TestValidation(t *testing.T) {
	ca, _, _, err := tlstest.GenerateCert(nil)
	check(t, "Failed to create CA", err)
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(ca.Leaf)

	serverCert, _, _, err := tlstest.GenerateCert(&tlstest.CertOptions{
		Template: &x509.Certificate{
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
		Parent: ca,
	})
	check(t, "Failed to create server certificate", err)

	expiredCert, _, _, err := tlstest.GenerateCert(&tlstest.CertOptions{
		Template: &x509.Certificate{
			NotAfter: time.Now().Add(-15 * time.Minute),
		},
		Parent: ca,
	})
	check(t, "Failed to create expired certificate", err)
	expiredCert.Leaf = nil // require parsing

	tests := []struct {
		desc    string
		options []Option
		config  *tls.Config
		invalid bool
	}{
		{
			desc: "default",
			config: &tls.Config{
				Certificates: []tls.Certificate{*serverCert},
				RootCAs:      rootCAs,
			},
		},
		{
			desc:    "valid_usage",
			options: []Option{WithKeyUsages(x509.ExtKeyUsageServerAuth)},
			config: &tls.Config{
				Certificates: []tls.Certificate{*serverCert},
				RootCAs:      rootCAs,
			},
		},
		{
			desc:    "invalid_usage",
			options: []Option{WithKeyUsages(x509.ExtKeyUsageClientAuth)},
			config: &tls.Config{
				Certificates: []tls.Certificate{*serverCert},
				RootCAs:      rootCAs,
			},
			invalid: true,
		},
		{
			desc: "expired",
			config: &tls.Config{
				Certificates: []tls.Certificate{*expiredCert},
				RootCAs:      rootCAs,
			},
			invalid: true,
		},
		{
			desc: "no_roots",
			config: &tls.Config{
				Certificates: []tls.Certificate{*serverCert},
			},
			invalid: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			m, err := NewMetrics(tt.options...)
			check(t, "Failed to create metrics", err)
			m.Update(tt.config, nil)
			got := readGauge(t, m.verifyError)
			want := float64(0)
			if tt.invalid {
				want = 1
			}
			if got.value != want {
				t.Fatalf("Unexpected %s value: got: %v; want: %v", got.name, got.value, want)
			}
		})
	}
}

func TestExpiration(t *testing.T) {
	now := time.Now()
	caExp := now.Add(24 * time.Hour)
	ca, _, _, err := tlstest.GenerateCert(&tlstest.CertOptions{
		Template: &x509.Certificate{
			NotAfter: caExp,
		},
	})
	check(t, "Failed to create CA", err)
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(ca.Leaf)

	longExp := now.Add(48 * time.Hour)
	longCert, _, _, err := tlstest.GenerateCert(&tlstest.CertOptions{
		Template: &x509.Certificate{
			NotAfter: longExp,
		},
		Parent: ca,
	})
	check(t, "Failed to create certificate", err)

	medExp := now.Add(6 * time.Hour)
	medCert, _, _, err := tlstest.GenerateCert(&tlstest.CertOptions{
		Template: &x509.Certificate{
			NotAfter: medExp,
		},
		Parent: ca,
	})
	check(t, "Failed to create certificate", err)

	shortExp := now.Add(3 * time.Hour)
	shortCert, _, _, err := tlstest.GenerateCert(&tlstest.CertOptions{
		Template: &x509.Certificate{
			NotAfter: shortExp,
		},
		Parent: ca,
	})
	check(t, "Failed to create certificate", err)

	tests := []struct {
		desc   string
		config *tls.Config
		expiry time.Time
	}{
		{
			desc: "multiple_certs",
			config: &tls.Config{
				Certificates: []tls.Certificate{*medCert, *shortCert},
				RootCAs:      rootCAs,
			},
			expiry: shortExp,
		},
		{
			desc: "cert_before_ca",
			config: &tls.Config{
				Certificates: []tls.Certificate{*medCert},
				RootCAs:      rootCAs,
			},
			expiry: medExp,
		},
		{
			desc: "cert_after_ca",
			config: &tls.Config{
				Certificates: []tls.Certificate{*longCert},
				RootCAs:      rootCAs,
			},
			expiry: caExp,
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			m, err := NewMetrics(WithErrorLogger(t))
			check(t, "Failed to create metrics", err)
			m.Update(tt.config, nil)
			got := readGauge(t, m.expiration)
			want := float64(tt.expiry.Unix())
			if got.value != want {
				t.Fatalf("Unexpected %s value: got: %v; want: %v", got.name, got.value, want)
			}
		})
	}
}

type gauge struct {
	name  string
	value float64
}

func readGauge(t *testing.T, g prometheus.Gauge) *gauge {
	t.Helper()
	reg := prometheus.NewRegistry()
	check(t, "Failed to register gauge", reg.Register(g))
	fams, err := reg.Gather()
	check(t, "Failed to gather gauge", err)
	if n := len(fams); n != 1 {
		t.Fatalf("Unexpected number of metric families: got %d; want: 1", n)
	}
	fam := fams[0]
	metrics := fam.GetMetric()
	if n := len(metrics); n != 1 {
		t.Fatalf("Unexpected number of metrics: got %d; want: 1", n)
	}
	return &gauge{
		name:  fam.GetName(),
		value: metrics[0].GetGauge().GetValue(),
	}
}

func check(t *testing.T, msg string, err error) {
	if err != nil {
		t.Helper()
		t.Fatalf("%s: %v", msg, err)
	}
}
