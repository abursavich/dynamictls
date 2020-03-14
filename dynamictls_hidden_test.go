// Copyright 2020 Andrew Bursavich. All rights reserved.
// Use of this source code is governed by The MIT License
// which can be found in the LICENSE file.

package dynamictls_test

import (
	"net/http"
)

var (
	addr          string
	certFile      string
	keyFile       string
	clientCAsFile string
	rootCAsFile   string
	mux           = http.NewServeMux()
)

func makeRequests(*http.Client) {}
