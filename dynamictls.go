// SPDX-License-Identifier: MIT
//
// Copyright 2020 Andrew Bursavich. All rights reserved.
// Use of this source code is governed by The MIT License
// which can be found in the LICENSE file.

// Package dynamictls implements dynamic TLS configuration.
package dynamictls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"hash"
	"hash/fnv"
	"io/ioutil"
	"net"
	"path/filepath"
	"sort"
	"sync/atomic"

	"github.com/abursavich/dynamictls/internal/forked/go/http2"
	fsnotify "gopkg.in/fsnotify.v1"
)

const hashSize = 16 // 128-bit

// An ErrorLogger logs errors.
type ErrorLogger interface {
	Errorf(format string, args ...interface{})
}

type noopLogger struct{}

func (noopLogger) Errorf(format string, args ...interface{}) {}

// NotifyFunc is a function that is called when new config data
// is loaded or an error occurs loading new config data.
type NotifyFunc func(cfg *tls.Config, err error)

// An Option applies optional configuration.
type Option interface {
	apply(*Config) error
	weight() int
}

type option struct {
	fn func(*Config) error
	w  int
}

func optionFunc(fn func(*Config) error) Option {
	return option{fn: fn}
}

func weightedOptionFunc(weight int, fn func(*Config) error) Option {
	return option{fn: fn, w: weight}
}

func (o option) apply(c *Config) error { return o.fn(c) }
func (o option) weight() int           { return o.w }

type byWeight []Option

func (s byWeight) Len() int           { return len(s) }
func (s byWeight) Less(i, k int) bool { return s[i].weight() < s[k].weight() }
func (s byWeight) Swap(i, k int)      { s[i], s[k] = s[k], s[i] }

func sortedOptions(options []Option) []Option {
	if sort.IsSorted(byWeight(options)) {
		return options
	}
	// sort a copy
	options = append(make([]Option, 0, len(options)), options...)
	sort.Stable(byWeight(options))
	return options
}

// WithBase returns an Option that sets a base TLS config.
func WithBase(config *tls.Config) Option {
	return optionFunc(func(c *Config) error {
		c.base = config.Clone()
		return nil
	})
}

// WithRootCAs returns an Option that adds the certificates
// in the file to the config's root certificate pool.
func WithRootCAs(file string) Option {
	return optionFunc(func(c *Config) error {
		c.rootCAs = append(c.rootCAs, file)
		return c.addWatch(file)
	})
}

// WithClientCAs returns an Option that adds the certificates
// in the file to the config's client certificate pool.
func WithClientCAs(file string) Option {
	return optionFunc(func(c *Config) error {
		c.clientCAs = append(c.clientCAs, file)
		return c.addWatch(file)
	})
}

// WithCertificate returns an Option that adds the public/private
// key pair in the PEM encoded files to the config's certificates.
func WithCertificate(certFile, keyFile string) Option {
	return optionFunc(func(c *Config) error {
		c.certs = append(c.certs, keyPair{
			certFile: certFile,
			keyFile:  keyFile,
		})
		if err := c.addWatch(certFile); err != nil {
			return err
		}
		return c.addWatch(keyFile)
	})
}

// WithNotifyFunc returns an Option that registers the notify function.
func WithNotifyFunc(notify NotifyFunc) Option {
	return optionFunc(func(c *Config) error {
		c.notifyFns = append(c.notifyFns, notify)
		return nil
	})
}

// WithErrorLogger returns an Option that sets the logger for errors.
func WithErrorLogger(logger ErrorLogger) Option {
	return optionFunc(func(c *Config) error {
		c.logger = logger
		return nil
	})
}

// WithHTTP returns an Option that adds HTTP/2 and HTTP/1.1
// protocol negotiation to the config.
func WithHTTP() Option {
	// N.B: weight must be higher than WithBase
	return weightedOptionFunc(1, func(c *Config) error {
		if err := withHTTP2(c); err != nil {
			return err
		}
		return withHTTP1(c)
	})
}

// WithHTTP2 returns an Option that adds HTTP/2
// protocol negotiation to the config.
func WithHTTP2() Option {
	// N.B: weight must be higher than WithBase
	return weightedOptionFunc(1, withHTTP2)
}

// WithHTTP1 returns an Option that adds HTTP/1.1
// protocol negotiation to the config.
func WithHTTP1() Option {
	// N.B: weight must be higher than WithHTTP2
	return weightedOptionFunc(2, withHTTP1)
}

func withHTTP2(c *Config) error {
	if err := http2.ValidateCipherSuites(c.base); err != nil {
		return err
	}
	c.base.NextProtos = http2.AppendProto(c.base.NextProtos, http2.ProtoHTTP2)
	c.base.PreferServerCipherSuites = true
	return nil
}

func withHTTP1(c *Config) error {
	c.base.NextProtos = http2.AppendProto(c.base.NextProtos, http2.ProtoHTTP1)
	return nil
}

type keyPair struct {
	certFile, keyFile string
}

type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

var defaultDialFunc = (&net.Dialer{}).DialContext

// A Config is used to configure a TLS client or server.
type Config struct {
	latest atomic.Value
	hash   [hashSize]byte // dedupes notify calls

	base      *tls.Config
	rootCAs   []string
	clientCAs []string
	certs     []keyPair
	notifyFns []NotifyFunc
	logger    ErrorLogger

	watcher *fsnotify.Watcher
	close   chan struct{} // signals watch goroutine to end
	done    chan struct{} // signals watch goroutine has ended

	dialFunc dialFunc // used by tests
}

// NewConfig returns a new Config with the given options.
// It's an error if no dynamic file options are specified.
func NewConfig(options ...Option) (cfg *Config, err error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			w.Close()
		}
	}()
	cfg = &Config{
		base:     &tls.Config{},
		logger:   noopLogger{},
		watcher:  w,
		close:    make(chan struct{}),
		done:     make(chan struct{}),
		dialFunc: defaultDialFunc,
	}
	for _, o := range sortedOptions(options) {
		if err := o.apply(cfg); err != nil {
			return nil, err
		}
	}
	if len(cfg.rootCAs) == 0 && len(cfg.clientCAs) == 0 && len(cfg.certs) == 0 {
		return nil, fmt.Errorf("dynamictls: no dynamic options were specified")
	}
	if err := cfg.read(); err != nil {
		return nil, err
	}
	go cfg.watch()
	return cfg, nil
}

func (cfg *Config) addWatch(file string) error {
	return cfg.watcher.Add(filepath.Dir(file))
}

// Close closes the file watcher associated with the config.
func (cfg *Config) Close() error {
	select {
	case cfg.close <- struct{}{}:
		<-cfg.done
	case <-cfg.done:
	}
	return nil
}

// Config returns the latest TLS config.
// It is shared and must not be modified.
func (cfg *Config) Config() *tls.Config {
	return cfg.latest.Load().(*tls.Config)
}

// Listen creates a TLS listener accepting connections on the given network address.
func (cfg *Config) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	inner, err := (&net.ListenConfig{}).Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return NewListener(inner, cfg), nil
}

// Dial connects to the given network address and initiates a TLS handshake,
// returning the resulting TLS connection.
func (cfg *Config) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	rawConn, err := cfg.dialFunc(ctx, network, address)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	config := cfg.latest.Load().(*tls.Config)
	if config.ServerName != host {
		config = config.Clone()
		config.ServerName = host
	}
	tlsConn := tls.Client(rawConn, config)
	errCh := make(chan error, 1)
	go func() { errCh <- tlsConn.Handshake() }()
	select {
	case err = <-errCh:
	case <-ctx.Done():
		err = ctx.Err()
	}
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (cfg *Config) read() error {
	var sum [hashSize]byte
	h := fnv.New128a()

	certs, err := readCerts(h, cfg.certs)
	if err != nil {
		return err
	}
	clientCAs, err := readCAs(h, cfg.clientCAs)
	if err != nil {
		return err
	}
	rootCAs, err := readCAs(h, cfg.rootCAs)
	if err != nil {
		return err
	}

	if h.Sum(sum[:0]); cfg.hash == sum {
		return nil
	}
	cfg.hash = sum

	config := cfg.base.Clone()
	if certs != nil {
		config.Certificates = certs
	}
	if clientCAs != nil {
		config.ClientCAs = clientCAs
	}
	if rootCAs != nil {
		config.RootCAs = rootCAs
	}

	cfg.latest.Store(config)
	for _, fn := range cfg.notifyFns {
		fn(config, nil)
	}
	return nil
}

func (cfg *Config) watch() {
	defer close(cfg.done)
	defer cfg.watcher.Close()
	for {
		select {
		case <-cfg.watcher.Events:
			// TODO: ignore unrelated events
			if err := cfg.read(); err != nil {
				cfg.logger.Errorf("%v", err) // errors already decorated
				for _, fn := range cfg.notifyFns {
					fn(nil, err)
				}
			}
		case err := <-cfg.watcher.Errors:
			cfg.logger.Errorf("dynamictls: watch error: %v", err)
		case <-cfg.close:
			return
		}
	}
}

func readCerts(h hash.Hash, pairs []keyPair) ([]tls.Certificate, error) {
	var certs []tls.Certificate
	for _, pair := range pairs {
		certPEMBlock, err := ioutil.ReadFile(pair.certFile)
		if err != nil {
			return nil, fmt.Errorf("dynamictls: cert read error: %w", err)
		}
		keyPEMBlock, err := ioutil.ReadFile(pair.keyFile)
		if err != nil {
			return nil, fmt.Errorf("dynamictls: key read error: %w", err)
		}
		cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
		if err != nil {
			return nil, fmt.Errorf("dynamictls: keypair parsing error: %w", err)
		}
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
		certs = append(certs, cert)
		_, _ = h.Write(certPEMBlock)
		_, _ = h.Write(keyPEMBlock)
	}
	return certs, nil
}

func readCAs(h hash.Hash, files []string) (*x509.CertPool, error) {
	if len(files) == 0 {
		return nil, nil
	}
	pool := x509.NewCertPool()
	for _, file := range files {
		caPEMCerts, err := ioutil.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("dynamictls: certificate authorities read error: %w", err)
		}
		pool.AppendCertsFromPEM(caPEMCerts)
		_, _ = h.Write(caPEMCerts)
	}
	return pool, nil
}

// NewListener creates a Listener which accepts connections from an inner
// Listener and wraps each connection with TLS.
func NewListener(inner net.Listener, config *Config) net.Listener {
	return &listener{Listener: inner, cfg: config}
}

type listener struct {
	net.Listener
	cfg *Config
}

func (lis *listener) Accept() (net.Conn, error) {
	rawConn, err := lis.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return tls.Server(rawConn, lis.cfg.Config()), nil
}
