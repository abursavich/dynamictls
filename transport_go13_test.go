// +build !go1.14

package dynamictls

import (
	"context"
	"net"
	"net/http"
)

func httpTransport(cfg *Config) *http.Transport {
	dial := func(network, addr string) (net.Conn, error) {
		return cfg.Dial(context.TODO(), network, addr)
	}
	return &http.Transport{
		DialTLS:           dial, // NB: DialTLSContext added in go 1.14
		ForceAttemptHTTP2: true, // NB: required if using a custom dialer with HTTP/2
	}
}
