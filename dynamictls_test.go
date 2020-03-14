// Copyright 2020 Andrew Bursavich. All rights reserved.
// Use of this source code is governed by The MIT License
// which can be found in the LICENSE file.

package dynamictls_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"

	"github.com/abursavich/dynamictls"
	"github.com/abursavich/dynamictls/tlsprom"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func ExampleConfig_Listen() {
	metrics, err := tlsprom.NewMetrics(
		tlsprom.WithPrefix("http_server"),
		tlsprom.WithKeyUsages(x509.ExtKeyUsageServerAuth),
	)
	if err != nil {
		log.Fatal(err)
	}
	cfg, err := dynamictls.NewConfig(
		dynamictls.WithBase(&tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			MinVersion: tls.VersionTLS12,
		}),
		dynamictls.WithCertificate(primaryCertFile, primaryKeyFile),
		dynamictls.WithCertificate(secondaryCertFile, secondaryKeyFile),
		dynamictls.WithRootCAs(rootCAsFile),
		dynamictls.WithClientCAs(clientCAsFile),
		dynamictls.WithNotifyFunc(metrics.Update),
		dynamictls.WithHTTP(),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer cfg.Close()

	lis, err := cfg.Listen(context.Background(), "tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(metrics)
	reg.MustRegister(prometheus.NewBuildInfoCollector())
	reg.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	reg.MustRegister(prometheus.NewGoCollector())
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	log.Fatal(http.Serve(lis, mux))
}

func ExampleConfig_Dial() {
	cfg, err := dynamictls.NewConfig(
		dynamictls.WithBase(&tls.Config{
			MinVersion: tls.VersionTLS12,
		}),
		dynamictls.WithCertificate(certFile, keyFile),
		dynamictls.WithRootCAs(caFile),
		dynamictls.WithHTTP(),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer cfg.Close()

	client := &http.Client{
		Transport: &http.Transport{
			DialTLSContext: cfg.Dial,
		},
	}
	defer client.CloseIdleConnections()
	makeRequests(client)
}
