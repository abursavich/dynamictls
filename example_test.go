// SPDX-License-Identifier: MIT
//
// Copyright 2020 Andrew Bursavich. All rights reserved.
// Use of this source code is governed by The MIT License
// which can be found in the LICENSE file.

//go:build go1.14
// +build go1.14

package dynamictls_test

import (
	"context"
	"crypto/tls"
	"net/http"

	"bursavich.dev/dynamictls"
	"bursavich.dev/dynamictls/tlsprom"
	"github.com/prometheus/client_golang/prometheus"
)

func ExampleConfig_Listen() {
	observer, err := tlsprom.NewObserver(
		tlsprom.WithHTTP(),
		tlsprom.WithServer(),
	)
	check(err)
	prometheus.MustRegister(observer)

	cfg, err := dynamictls.NewConfig(
		dynamictls.WithObserver(observer),
		dynamictls.WithCertificate(primaryCertFile, primaryKeyFile),
		dynamictls.WithCertificate(secondaryCertFile, secondaryKeyFile),
		dynamictls.WithRootCAs(caFile),
		dynamictls.WithHTTP(), // NB: adds HTTP/2 and HTTP/1.1 protocols
	)
	check(err)
	defer cfg.Close()

	lis, err := cfg.Listen(context.Background(), "tcp", addr)
	check(err)
	check(http.Serve(lis, http.DefaultServeMux))
}

func ExampleConfig_Dial() {
	observer, err := tlsprom.NewObserver(
		tlsprom.WithHTTP(),
		tlsprom.WithClient(),
	)
	check(err)
	prometheus.MustRegister(observer)

	cfg, err := dynamictls.NewConfig(
		dynamictls.WithObserver(observer),
		dynamictls.WithBase(&tls.Config{
			MinVersion: tls.VersionTLS12,
		}),
		dynamictls.WithCertificate(certFile, keyFile),
		dynamictls.WithRootCAs(caFile),
		dynamictls.WithHTTP(), // NB: adds HTTP/2 and HTTP/1.1 protocols
	)
	check(err)
	defer cfg.Close()

	client := &http.Client{
		Transport: &http.Transport{
			DialTLSContext:    cfg.Dial, // NB: DialTLSContext added in go 1.14
			ForceAttemptHTTP2: true,     // NB: required if using a custom dialer with HTTP/2
		},
	}
	defer client.CloseIdleConnections()
}
