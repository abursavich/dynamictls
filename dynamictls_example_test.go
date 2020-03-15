// Copyright 2020 Andrew Bursavich. All rights reserved.
// Use of this source code is governed by The MIT License
// which can be found in the LICENSE file.

package dynamictls_test

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/abursavich/dynamictls"
	"github.com/abursavich/dynamictls/tlsprom"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func ExampleConfig_Listen() {
	tlsMetrics, err := tlsprom.NewMetrics(
		tlsprom.WithHTTP(),
		tlsprom.WithServer(),
	)
	check(err)
	cfg, err := dynamictls.NewConfig(
		dynamictls.WithCertificate(primaryCertFile, primaryKeyFile),
		dynamictls.WithCertificate(secondaryCertFile, secondaryKeyFile),
		dynamictls.WithRootCAs(caFile),
		dynamictls.WithNotifyFunc(tlsMetrics.Update),
		dynamictls.WithHTTP(), // adds HTTP/2 and HTTP/1.1 protocols
	)
	check(err)
	defer cfg.Close()

	reg := prometheus.NewRegistry()
	reg.MustRegister(tlsMetrics)
	reg.MustRegister(prometheus.NewBuildInfoCollector())
	reg.MustRegister(prometheus.NewGoCollector())
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))

	lis, err := cfg.Listen(context.Background(), "tcp", addr)
	check(err)
	check(http.Serve(lis, mux))
}

func ExampleConfig_Dial() {
	cfg, err := dynamictls.NewConfig(
		dynamictls.WithBase(&tls.Config{
			MinVersion: tls.VersionTLS12,
		}),
		dynamictls.WithCertificate(certFile, keyFile),
		dynamictls.WithRootCAs(caFile),
		dynamictls.WithHTTP(), // adds HTTP/2 and HTTP/1.1 protocols
	)
	check(err)
	defer cfg.Close()

	client := &http.Client{
		Transport: &http.Transport{
			DialTLSContext:    cfg.Dial,
			ForceAttemptHTTP2: true, // required if using a custom dialer with HTTP/2
		},
	}
	defer client.CloseIdleConnections()
	makeRequests(client)
}
