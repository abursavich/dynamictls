// SPDX-License-Identifier: MIT
//
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
	Parent     *tls.Certificate
	Template   *x509.Certificate
	PrivateKey crypto.Signer
}

// GenerateCert generates a certificate with the given options.
func GenerateCert(options *CertOptions) (cert *tls.Certificate, certPEMBlock, keyPEMBlock []byte, err error) {
	// See: https://golang.org/src/crypto/tls/generate_cert.go
	if options == nil {
		options = &CertOptions{}
	}

	selfSigned := options.Parent == nil
	template, err := certTemplate(options.Template, selfSigned)
	if err != nil {
		return nil, nil, nil, err
	}

	priv := options.PrivateKey
	if priv == nil {
		if priv, err = privateKey(); err != nil {
			return nil, nil, nil, err
		}
	}

	parent := template
	signer := priv
	if !selfSigned {
		if parent = options.Parent.Leaf; parent == nil {
			if parent, err = x509.ParseCertificate(options.Parent.Certificate[0]); err != nil {
				return nil, nil, nil, fmt.Errorf("parent certificate parse error: %v", err)
			}
		}
		signer = options.Parent.PrivateKey.(crypto.Signer)
	}

	return generateCert(template, parent, priv, signer)
}

func certTemplate(template *x509.Certificate, selfSigned bool) (*x509.Certificate, error) {
	var tmpl x509.Certificate
	if template != nil {
		tmpl = *template
	}
	if tmpl.SerialNumber == nil {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return nil, fmt.Errorf("serial number generation error: %v", err)
		}
		tmpl.SerialNumber = serialNumber
	}
	if tmpl.Subject.String() == "" {
		tmpl.Subject = pkix.Name{
			Organization: []string{"Acme Co"},
		}
	}
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Now().Add(-time.Hour)
	}
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = time.Now().Add(time.Hour)
	}
	if tmpl.ExtKeyUsage == nil {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		}
	}
	tmpl.KeyUsage |= x509.KeyUsageDigitalSignature
	if selfSigned {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
		tmpl.IsCA = true
	}
	tmpl.BasicConstraintsValid = true
	return &tmpl, nil
}

func privateKey() (*ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("private key generation error: %v", err)
	}
	return priv, err
}

func generateCert(template, parent *x509.Certificate, priv crypto.Signer, signer crypto.Signer) (cert *tls.Certificate, certPEMBlock, keyPEMBlock []byte, err error) {
	derBytes, err := x509.CreateCertificate(rand.Reader, template, parent, priv.Public(), signer)
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
