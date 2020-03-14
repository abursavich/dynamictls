// Copyright 2020 Andrew Bursavich. All rights reserved.
// Use of this source code is governed by The MIT License
// which can be found in the LICENSE file.

// Package tlsprom provides Prometheus instrumentation for TLS configuration.
package tlsprom

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// An ErrorLogger logs errors.
type ErrorLogger interface {
	Errorf(format string, args ...interface{})
}

type noopLogger struct{}

func (noopLogger) Errorf(format string, args ...interface{}) {}

// An Option applies optional configuration.
type Option func(*option) error

type option struct {
	prefix string
	logger ErrorLogger
}

// WithPrefix returns an Option that sets a prefix on the metric names.
func WithPrefix(s string) Option {
	return func(o *option) error {
		o.prefix = strings.TrimRight(s, "_")
		return nil
	}
}

// WithErrorLogger returns an Option that sets the logger for errors.
func WithErrorLogger(logger ErrorLogger) Option {
	return func(o *option) error {
		o.logger = logger
		return nil
	}
}

// Metrics is a collection of TLS config metrics.
type Metrics struct {
	updateError prometheus.Gauge
	verifyError prometheus.Gauge
	expiration  prometheus.Gauge

	logger ErrorLogger
}

// NewMetrics returns new Metrics with the given options.
func NewMetrics(options ...Option) (*Metrics, error) {
	o := &option{
		logger: &noopLogger{},
	}
	for _, fn := range options {
		if err := fn(o); err != nil {
			return nil, err
		}
	}
	m := &Metrics{
		updateError: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: o.prefix,
			Name:      "tls_config_update_error",
			Help:      "Indicates if there was an error updating the TLS configuration.",
		}),
		verifyError: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: o.prefix,
			Name:      "tls_config_certificate_verify_error",
			Help:      "Indicates if there was an error verifying the TLS configuration's certificates and expirations.",
		}),
		expiration: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: o.prefix,
			Name:      "tls_config_earliest_certificate_expiration_time_seconds",
			Help:      "Earliest expiration time of the TLS configuration's certificates in seconds since the Unix epoch.",
		}),
		logger: o.logger,
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
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err != nil {
			m.logger.Errorf("tlsprom: cert verification error: %v", err)
			return time.Time{}, err
		}
		for _, chain := range chains {
			for _, cert := range chain {
				if v := cert.NotBefore; t.IsZero() || v.Before(t) {
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
