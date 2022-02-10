// SPDX-License-Identifier: MIT
//
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

	"bursavich.dev/dynamictls"
	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	updateErrorName = "tls_config_update_error"
	verifyErrorName = "tls_config_certificate_verify_error"
	expirationName  = "tls_config_earliest_certificate_expiration_time_seconds"
)

type config struct {
	namespace string
	subsystem string
	usages    []x509.ExtKeyUsage
	log       logr.Logger
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

// WithLogger returns an Option that sets the logger for errors.
func WithLogger(log logr.Logger) Option {
	return optionFunc(func(c *config) error {
		c.log = log
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

// Observer is a collection of TLS config metrics.
type Observer interface {
	dynamictls.Observer
	prometheus.Collector
}

type observer struct {
	updateError prometheus.Gauge
	verifyError prometheus.Gauge
	expiration  prometheus.Gauge

	usages []x509.ExtKeyUsage
	log    logr.Logger
}

// NewObserver returns a new Observer with the given options.
func NewObserver(options ...Option) (Observer, error) {
	cfg := &config{
		usages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		log:    logr.Discard(),
	}
	for _, o := range sortedOptions(options) {
		if err := o.apply(cfg); err != nil {
			return nil, err
		}
	}
	o := &observer{
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
		log:    cfg.log,
	}
	return o, nil
}

// Describe sends the super-set of all possible descriptors of metrics
// to the provided channel and returns once the last descriptor has been sent.
func (o *observer) Describe(ch chan<- *prometheus.Desc) {
	o.updateError.Describe(ch)
	o.verifyError.Describe(ch)
	o.expiration.Describe(ch)
}

// Collect sends each collected metric via the provided channel
// and returns once the last metric has been sent.
func (o *observer) Collect(ch chan<- prometheus.Metric) {
	o.updateError.Collect(ch)
	o.verifyError.Collect(ch)
	o.expiration.Collect(ch)
}

func (o *observer) ObserveConfig(cfg *tls.Config) {
	o.updateError.Set(0)

	t, err := o.earliestExpiration(cfg)
	if err != nil || t.IsZero() {
		o.verifyError.Set(1)
		o.expiration.Set(0)
		return
	}
	o.verifyError.Set(0)
	o.expiration.Set(float64(t.Unix()))
}

func (o *observer) ObserveReadError(err error) {
	o.updateError.Set(1)
}

func (o *observer) earliestExpiration(cfg *tls.Config) (time.Time, error) {
	var t time.Time
	for _, cert := range cfg.Certificates {
		x509Cert := cert.Leaf
		if x509Cert == nil {
			var err error
			if x509Cert, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
				o.log.Error(err, "Failed to parse TLS certificate")
				return time.Time{}, err
			}
		}
		chains, err := x509Cert.Verify(x509.VerifyOptions{
			Roots:     cfg.RootCAs,
			KeyUsages: o.usages,
		})
		if err != nil {
			o.log.Error(err, "Failed to validate TLS certificate")
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
		o.log.Error(nil, "Failed to find a certificate in the TLS config")
	}
	return t, nil
}
