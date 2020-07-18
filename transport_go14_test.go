// SPDX-License-Identifier: MIT
//
// Copyright 2020 Andrew Bursavich. All rights reserved.
// Use of this source code is governed by The MIT License
// which can be found in the LICENSE file.

// +build go1.14

package dynamictls

import (
	"net/http"
)

func httpTransport(cfg *Config) *http.Transport {
	return &http.Transport{
		DialTLSContext:    cfg.Dial, // NB: DialTLSContext added in go 1.14
		ForceAttemptHTTP2: true,     // NB: required if using a custom dialer with HTTP/2
	}
}
