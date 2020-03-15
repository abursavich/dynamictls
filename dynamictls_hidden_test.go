// Copyright 2020 Andrew Bursavich. All rights reserved.
// Use of this source code is governed by The MIT License
// which can be found in the LICENSE file.

package dynamictls_test

import (
	"log"
	"net/http"
)

var (
	addr string

	certFile, keyFile, caFile           string
	primaryCertFile, primaryKeyFile     string
	secondaryCertFile, secondaryKeyFile string
	rootCAsFile, clientCAsFile          string
)

func makeRequests(*http.Client) {}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
