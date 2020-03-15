// Copyright 2020 Andrew Bursavich. All rights reserved.
// Use of this source code is governed by The MIT License
// which can be found in the LICENSE file.

// Package tlsprom provides Prometheus instrumentation for TLS configuration.
package tlsprom

import (
	"crypto/tls"
	"crypto/x509"
	"sort"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	updateErrorName = "tls_config_update_error"
	verifyErrorName = "tls_config_certificate_verify_error"
	expirationName  = "tls_config_earliest_certificate_expiration_time_seconds"
)

// An ErrorLogger logs errors.
type ErrorLogger interface {
	Errorf(format string, args ...interface{})
}

type noopLogger struct{}

func (noopLogger) Errorf(format string, args ...interface{}) {}

type config struct {
	namespace string
	subsystem string
	usages    []x509.ExtKeyUsage
	logger    ErrorLogger
}

// An Option applies optional configuration.
type Option interface {
	apply(*config) error
	weight() int
}

type opt struct {
	fn func(*config) error
	w  int
}

func optionFunc(fn func(*config) error) Option {
	return opt{fn: fn}
}

func weightedOptionFunc(weight int, fn func(*config) error) Option {
	return opt{fn: fn, w: weight}
}

func (o opt) apply(c *config) error { return o.fn(c) }
func (o opt) weight() int           { return o.w }

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

// WithErrorLogger returns an Option that sets the logger for errors.
func WithErrorLogger(logger ErrorLogger) Option {
	return optionFunc(func(c *config) error {
		c.logger = logger
		return nil
	})
}

// WithHTTP returns an Option that sets the namespace to "http".
func WithHTTP() Option {
	return optionFunc(func(c *config) error {
		c.namespace = "http"
		return nil
	})
}

// WithGRPC returns an Option that sets the namespace to "grpc".
func WithGRPC() Option {
	return optionFunc(func(c *config) error {
		c.namespace = "grpc"
		return nil
	})
}

// WithClient returns an Option that sets the subsystem to "client"
// and the key usage to ClientAuth.
func WithClient() Option {
	return optionFunc(func(c *config) error {
		c.subsystem = "client"
		c.usages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		return nil
	})
}

// WithServer returns an Option that sets the subsystem to "server"
// and the key usage to ServerAuth.
func WithServer() Option {
	return optionFunc(func(c *config) error {
		c.subsystem = "server"
		c.usages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		return nil
	})
}

// WithNamespace returns an Option that sets the namespace of metrics.
func WithNamespace(namespace string) Option {
	return weightedOptionFunc(1, func(c *config) error {
		c.namespace = namespace
		return nil
	})
}

// WithSubsystem returns an Option that sets the subsystem of metrics.
func WithSubsystem(subsystem string) Option {
	return weightedOptionFunc(1, func(c *config) error {
		c.subsystem = subsystem
		return nil
	})
}

// WithKeyUsages returns an Option that specifies the
// key usages for certificate verification.
func WithKeyUsages(usages ...x509.ExtKeyUsage) Option {
	return weightedOptionFunc(1, func(c *config) error {
		c.usages = usages
		return nil
	})
}

// Metrics is a collection of TLS config metrics.
type Metrics struct {
	updateError prometheus.Gauge
	verifyError prometheus.Gauge
	expiration  prometheus.Gauge

	usages []x509.ExtKeyUsage
	logger ErrorLogger
}

// NewMetrics returns new Metrics with the given options.
func NewMetrics(options ...Option) (*Metrics, error) {
	cfg := &config{
		usages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		logger: &noopLogger{},
	}
	for _, o := range sortedOptions(options) {
		if err := o.apply(cfg); err != nil {
			return nil, err
		}
	}
	m := &Metrics{
		updateError: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: cfg.namespace,
			Subsystem: cfg.subsystem,
			Name:      updateErrorName,
			Help:      "Indicates if there was an error updating the TLS configuration.",
		}),
		verifyError: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: cfg.namespace,
			Subsystem: cfg.subsystem,
			Name:      verifyErrorName,
			Help:      "Indicates if there was an error verifying the TLS configuration's certificates and expirations.",
		}),
		expiration: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: cfg.namespace,
			Subsystem: cfg.subsystem,
			Name:      expirationName,
			Help:      "Earliest expiration time of the TLS configuration's certificates in seconds since the Unix epoch.",
		}),
		usages: cfg.usages,
		logger: cfg.logger,
	}
	return m, nil
}

// Describe sends the super-set of all possible descriptors of metrics
// to the provided channel and returns once the last descriptor has been sent.
func (m *Metrics) Describe(ch chan<- *prometheus.Desc) {
	m.updateError.Describe(ch)
	m.verifyError.Describe(ch)
	m.expiration.Describe(ch)
}

// Collect sends each collected metric via the provided channel
// and returns once the last metric has been sent.
func (m *Metrics) Collect(ch chan<- prometheus.Metric) {
	m.updateError.Collect(ch)
	m.verifyError.Collect(ch)
	m.expiration.Collect(ch)
}

// Update updates the metrics with the new TLS config or error.
func (m *Metrics) Update(cfg *tls.Config, err error) {
	if err != nil {
		m.updateError.Set(1)
		return
	}
	m.updateError.Set(0)

	t, err := m.earliestExpiration(cfg)
	if err != nil || t.IsZero() {
		m.verifyError.Set(1)
		return
	}
	m.verifyError.Set(0)
	m.expiration.Set(float64(t.Unix()))
}

func (m *Metrics) earliestExpiration(cfg *tls.Config) (time.Time, error) {
	var t time.Time
	for _, cert := range cfg.Certificates {
		x509Cert := cert.Leaf
		if x509Cert == nil {
			var err error
			if x509Cert, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
				m.logger.Errorf("tlsprom: cert parsing error: %v", err)
				return time.Time{}, err
			}
		}
		chains, err := x509Cert.Verify(x509.VerifyOptions{
			Roots:     cfg.RootCAs,
			KeyUsages: m.usages,
		})
		if err != nil {
			m.logger.Errorf("tlsprom: cert verification error: %v", err)
			return time.Time{}, err
		}
		for _, chain := range chains {
			for _, cert := range chain {
				if v := cert.NotAfter; t.IsZero() || v.Before(t) {
					t = v
				}
			}
		}
	}
	if t.IsZero() {
		m.logger.Errorf("tlsprom: no certificates in config")
	}
	return t, nil
}
