// SPDX-License-Identifier: MIT
//
// Copyright 2020 Andrew Bursavich. All rights reserved.
// Use of this source code is governed by The MIT License
// which can be found in the LICENSE file.

package grpctls_test

import (
	"context"
	"log"

	pb "google.golang.org/grpc/interop/grpc_testing"
)

var (
	backendAddr string
	addr        string
	certFile    string
	keyFile     string
	caFile      string
)

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

type testServer struct {
	pb.UnimplementedTestServiceServer
	backend pb.TestServiceClient
}

func (*testServer) UnaryCall(ctx context.Context, req *pb.SimpleRequest) (*pb.SimpleResponse, error) {
	return &pb.SimpleResponse{Payload: req.Payload}, nil
}
