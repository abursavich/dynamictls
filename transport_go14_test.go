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
