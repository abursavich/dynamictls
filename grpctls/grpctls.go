// Copyright 2020 Andrew Bursavich. All rights reserved.
// Use of this source code is governed by The MIT License
// which can be found in the LICENSE file.

// Package grpctls implements dynamic TLS credential support for gRPC.
package grpctls

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/abursavich/dynamictls"
	"github.com/abursavich/dynamictls/internal/syscallconn"
	"google.golang.org/grpc/credentials"
)

// NewCredentials returns gRPC transport credentials based on the given
// dynamic TLS config.
func NewCredentials(config *dynamictls.Config) credentials.TransportCredentials {
	cfg := config.Config()
	return &creds{
		cfg:        config,
		serverName: cfg.ServerName,
		nextProtos: appendH2ToNextProtos(cfg.NextProtos),
	}
}

type creds struct {
	cfg        *dynamictls.Config
	serverName string
	nextProtos []string
}

func (c *creds) config() (cfg *tls.Config, isClone bool) {
	cfg = c.cfg.Config()
	if cfg.ServerName == c.serverName &&
		len(cfg.NextProtos) == len(c.nextProtos) &&
		cfg.MinVersion >= tls.VersionTLS12 {
		return cfg, false
	}
	cfg = cfg.Clone()
	cfg.ServerName = c.serverName
	cfg.NextProtos = c.nextProtos
	if cfg.MinVersion < tls.VersionTLS12 {
		cfg.MinVersion = tls.VersionTLS12
	}
	return cfg, true
}

func (c *creds) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	cfg, isClone := c.config()
	if cfg.ServerName == "" {
		if !isClone {
			cfg = cfg.Clone()
		}
		serverName, _, err := net.SplitHostPort(authority)
		if err != nil {
			serverName = authority
		}
		cfg.ServerName = serverName
	}
	conn := tls.Client(rawConn, cfg)
	errCh := make(chan error, 1)
	go func() { errCh <- conn.Handshake() }()
	var err error
	select {
	case err = <-errCh:
	case <-ctx.Done():
		err = ctx.Err()
	}
	if err != nil {
		rawConn.Close()
		return nil, nil, err
	}
	info := credentials.TLSInfo{
		State: conn.ConnectionState(),
		CommonAuthInfo: credentials.CommonAuthInfo{
			SecurityLevel: credentials.PrivacyAndIntegrity,
		},
	}
	return syscallconn.Wrap(rawConn, conn), info, nil
}

func (c *creds) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	cfg, _ := c.config()
	conn := tls.Server(rawConn, cfg)
	if err := conn.Handshake(); err != nil {
		conn.Close()
		return nil, nil, err
	}
	info := credentials.TLSInfo{
		State: conn.ConnectionState(),
		CommonAuthInfo: credentials.CommonAuthInfo{
			SecurityLevel: credentials.PrivacyAndIntegrity,
		},
	}
	return syscallconn.Wrap(rawConn, conn), info, nil
}

func (c *creds) Info() credentials.ProtocolInfo {
	vers := "1.2"
	if c.cfg.Config().MinVersion >= tls.VersionTLS13 {
		vers = "1.3"
	}
	return credentials.ProtocolInfo{
		SecurityProtocol: "tls",
		SecurityVersion:  vers,
		ServerName:       c.serverName,
	}
}

func (c *creds) Clone() credentials.TransportCredentials {
	v := *c
	return &v
}

func (c *creds) OverrideServerName(serverName string) error {
	c.serverName = serverName
	return nil
}

func appendH2ToNextProtos(s []string) []string {
	const h2Proto = "h2"
	for _, p := range s {
		if p == h2Proto {
			return s
		}
	}
	return append(append(make([]string, 0, len(s)+1), s...), h2Proto)
}
