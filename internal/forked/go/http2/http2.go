// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http2

import (
	"crypto/tls"
	"fmt"
)

// HTTP protocols
const (
	ProtoHTTP1 = "http/1.1"
	ProtoHTTP2 = "h2"
)

// AppendProto returns a copy of protos with the proto appended
// or protos unmodified if it already contains the proto.
func AppendProto(protos []string, proto string) []string {
	for _, p := range protos {
		if p == proto {
			return protos
		}
	}
	protos = append(make([]string, 0, len(protos)+1), protos...)
	return append(protos, proto)
}

// ValidateCipherSuites returns an error if the config's cipher suites
// are not suitable for HTTP/2.
func ValidateCipherSuites(config *tls.Config) error {
	if config.CipherSuites == nil {
		return nil
	}

	// Code imported from: https://github.com/golang/net/blob/5a598a2470a0279bd28bab287167dc1ef0813153/http2/server.go#L235-L256

	// If they already provided a CipherSuite list, return
	// an error if it has a bad order or is missing
	// ECDHE_RSA_WITH_AES_128_GCM_SHA256 or ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.
	haveRequired := false
	sawBad := false
	for i, cs := range config.CipherSuites {
		switch cs {
		case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			// Alternative MTI cipher to not discourage ECDSA-only servers.
			// See http://golang.org/cl/30721 for further information.
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
			haveRequired = true
		}
		if isBadCipher(cs) {
			sawBad = true
		} else if sawBad {
			return fmt.Errorf("http2: TLSConfig.CipherSuites index %d contains an HTTP/2-approved cipher suite (%#04x), but it comes after unapproved cipher suites. With this configuration, clients that don't support previous, approved cipher suites may be given an unapproved one and reject the connection", i, cs)
		}
	}
	if !haveRequired {
		return fmt.Errorf("http2: TLSConfig.CipherSuites is missing an HTTP/2-required AES_128_GCM_SHA256 cipher (need at least one of TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 or TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)")
	}

	return nil
}
