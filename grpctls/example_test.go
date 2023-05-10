// SPDX-License-Identifier: MIT
//
// Copyright 2020 Andrew Bursavich. All rights reserved.
// Use of this source code is governed by The MIT License
// which can be found in the LICENSE file.

package grpctls_test

import (
	"crypto/tls"
	"net"

	"bursavich.dev/dynamictls"
	"bursavich.dev/dynamictls/grpctls"
	"bursavich.dev/dynamictls/tlsprom"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"

	pb "google.golang.org/grpc/interop/grpc_testing"
)

func Example() {
	// create shared metrics
	observer, err := tlsprom.NewObserver(tlsprom.WithGRPC())
	check(err)
	prometheus.MustRegister(observer)

	// create shared TLS config
	cfg, err := dynamictls.NewConfig(
		dynamictls.WithObserver(observer),
		dynamictls.WithBase(&tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			MinVersion: tls.VersionTLS13,
		}),
		dynamictls.WithCertificate(certFile, keyFile),
		dynamictls.WithRootCAs(caFile),
		dynamictls.WithClientCAs(caFile),
		dynamictls.WithHTTP2(),
	)
	check(err)
	defer cfg.Close()

	// create shared credentials
	creds, err := grpctls.NewCredentials(cfg)
	check(err)

	// create frontend server with backend client
	conn, err := grpc.Dial(
		backendAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
	)
	check(err)
	defer conn.Close()
	srv := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterTestServiceServer(srv, &testServer{
		backend: pb.NewTestServiceClient(conn),
	})

	// listen and serve
	lis, err := net.Listen("tcp", addr) // NB: use plain listener
	check(err)
	check(srv.Serve(lis))
}

func Example_client() {
	// create metrics
	observer, err := tlsprom.NewObserver(
		tlsprom.WithGRPC(),
		tlsprom.WithClient(),
	)
	check(err)
	prometheus.MustRegister(observer)

	// create TLS config
	cfg, err := dynamictls.NewConfig(
		dynamictls.WithObserver(observer),
		dynamictls.WithBase(&tls.Config{
			MinVersion: tls.VersionTLS13,
		}),
		dynamictls.WithCertificate(certFile, keyFile),
		dynamictls.WithRootCAs(caFile),
		dynamictls.WithHTTP2(),
	)
	check(err)
	defer cfg.Close()

	// create client with credentials
	creds, err := grpctls.NewCredentials(cfg)
	check(err)
	conn, err := grpc.Dial(
		addr,
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
	)
	check(err)
	defer conn.Close()
	client := pb.NewTestServiceClient(conn)

	// use client
	_ = client
}

func Example_server() {
	// create metrics
	observer, err := tlsprom.NewObserver(
		tlsprom.WithGRPC(),
		tlsprom.WithServer(),
	)
	check(err)
	prometheus.MustRegister(observer)

	// create TLS config
	cfg, err := dynamictls.NewConfig(
		dynamictls.WithObserver(observer),
		dynamictls.WithBase(&tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			MinVersion: tls.VersionTLS13,
		}),
		dynamictls.WithCertificate(certFile, keyFile),
		dynamictls.WithRootCAs(caFile), // NB: metrics use RootCAs to verify local cert expiration
		dynamictls.WithClientCAs(caFile),
		dynamictls.WithHTTP2(),
	)
	check(err)
	defer cfg.Close()

	// create server with credentials
	creds, err := grpctls.NewCredentials(cfg)
	check(err)
	srv := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterTestServiceServer(srv, &testServer{})

	// listen and serve
	lis, err := net.Listen("tcp", addr) // NB: use plain listener
	check(err)
	check(srv.Serve(lis))
}
