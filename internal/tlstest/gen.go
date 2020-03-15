// Copyright 2020 Andrew Bursavich. All rights reserved.
// Use of this source code is governed by The MIT License
// which can be found in the LICENSE file.

// Package tlstest provides utilities for testing with TLS certificates.
package tlstest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// CertOptions are certificate options.
type CertOptions struct {
	Template *x509.Certificate
	Parent   *tls.Certificate
	Curve    elliptic.Curve
}

// GenerateCert generates a certificate with the give options.
func GenerateCert(options *CertOptions) (cert *tls.Certificate, certPEMBlock, keyPEMBlock []byte, err error) {
	// See: https://golang.org/src/crypto/tls/generate_cert.go
	if options == nil {
		options = &CertOptions{}
	}

	template := options.Template
	if template == nil {
		template = &x509.Certificate{}
	}
	if template.SerialNumber == nil {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("serial number generation error: %v", err)
		}
		template.SerialNumber = serialNumber
	}
	if template.Subject.String() == "" {
		template.Subject = pkix.Name{
			Organization: []string{"Acme Co"},
		}
	}
	if template.NotBefore.IsZero() {
		template.NotBefore = time.Now().Add(-time.Hour)
	}
	if template.NotAfter.IsZero() {
		template.NotAfter = time.Now().Add(time.Hour)
	}
	if len(template.ExtKeyUsage) == 0 {
		template.ExtKeyUsage = []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		}
	}
	template.KeyUsage |= x509.KeyUsageKeyEncipherment
	template.KeyUsage |= x509.KeyUsageDigitalSignature

	curve := options.Curve
	if curve == nil {
		curve = elliptic.P256()
	}
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("private key generation error: %v", err)
	}

	var (
		parent *x509.Certificate
		key    crypto.Signer
	)
	if options.Parent != nil {
		if parent = options.Parent.Leaf; parent == nil {
			parent, err = x509.ParseCertificate(options.Parent.Certificate[0])
			if err != nil {
				return nil, nil, nil, fmt.Errorf("parent certificate parse error: %v", err)
			}
		}
		key = options.Parent.PrivateKey.(crypto.Signer)
	} else { // self-signed
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		template.BasicConstraintsValid = true
		parent = template
		key = priv
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, parent, &priv.PublicKey, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("certificate creation error: %v", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("private key marshalling error: %v", err)
	}
	certPEMBlock = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEMBlock = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	crt, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("key pair unmarshalling error: %v", err)
	}
	crt.Leaf, err = x509.ParseCertificate(crt.Certificate[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("certificate parsing error: %v", err)
	}
	return &crt, certPEMBlock, keyPEMBlock, nil
}
