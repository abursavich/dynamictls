// Copyright 2020 Andrew Bursavich. All rights reserved.
// Use of this source code is governed by The MIT License
// which can be found in the LICENSE file.

package dynamictls_test

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"

	"github.com/abursavich/dynamictls"
)

func ExampleConfig_Listen() {
	cfg, err := dynamictls.NewConfig(
		dynamictls.WithBase(&tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			MinVersion: tls.VersionTLS12,
		}),
		dynamictls.WithCertificate(certFile, keyFile),
		dynamictls.WithClientCAs(clientCAsFile),
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
	log.Fatal(http.Serve(lis, mux))
}

func ExampleConfig_Dial() {
	cfg, err := dynamictls.NewConfig(
		dynamictls.WithBase(&tls.Config{
			MinVersion: tls.VersionTLS12,
		}),
		dynamictls.WithCertificate(certFile, keyFile),
		dynamictls.WithRootCAs(rootCAsFile),
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
	makeRequests(client)
}
