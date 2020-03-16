package grpctls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/abursavich/dynamictls"
	"github.com/abursavich/dynamictls/internal/tlstest"
	"google.golang.org/grpc"

	pb "google.golang.org/grpc/test/grpc_testing"
)

func TestGRPC(t *testing.T) {
	// create temp dir
	dir, err := ioutil.TempDir("", "")
	check(t, "Failed to create directory", err)
	defer os.RemoveAll(dir)

	// create certificate authority
	ca, caCertPEM, _, err := tlstest.GenerateCert(nil)
	check(t, "Failed to create CA", err)
	caFile := createFile(t, dir, "certs.pem", caCertPEM)

	// create server
	lis, err := net.Listen("tcp", "localhost:0")
	check(t, "Failed to create listener", err)
	defer lis.Close()
	_, port, err := net.SplitHostPort(lis.Addr().String())
	check(t, "Failed to get listen port", err)
	addr := "localhost:" + port
	_, serverCertPEM, serverKeyPEM, err := tlstest.GenerateCert(&tlstest.CertOptions{
		Template: &x509.Certificate{
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageServerAuth,
			},
			DNSNames: []string{"localhost", addr},
		},
		Parent: ca,
	})
	check(t, "Failed to create server certificate", err)
	serverCfg, err := dynamictls.NewConfig(
		dynamictls.WithBase(&tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
		}),
		dynamictls.WithCertificate(
			createFile(t, dir, "server.crt", serverCertPEM),
			createFile(t, dir, "server.key", serverKeyPEM),
		),
		dynamictls.WithRootCAs(caFile),
		dynamictls.WithClientCAs(caFile),
		dynamictls.WithErrorLogger(t),
	)
	check(t, "Failed to create server TLS config", err)
	defer serverCfg.Close()
	serverCreds, err := NewCredentials(serverCfg)
	check(t, "Failed to create server gRPC credentials", err)
	srv := grpc.NewServer(grpc.Creds(serverCreds))
	pb.RegisterTestServiceServer(srv, &testServiceServer{})
	defer srv.GracefulStop()
	go srv.Serve(lis) //nolint:errcheck

	// create client
	_, clientCertPEM, clientKeyPEM, err := tlstest.GenerateCert(&tlstest.CertOptions{
		Template: &x509.Certificate{
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageServerAuth, // not strictly required for clients
			},
		},
		Parent: ca,
	})
	check(t, "Failed to create client certificate", err)
	clientCfg, err := dynamictls.NewConfig(
		dynamictls.WithCertificate(
			createFile(t, dir, "client.crt", clientCertPEM),
			createFile(t, dir, "client.key", clientKeyPEM),
		),
		dynamictls.WithRootCAs(caFile),
		dynamictls.WithErrorLogger(t),
	)
	check(t, "Failed to create client TLS config", err)
	defer clientCfg.Close()
	clientCreds, err := NewCredentials(serverCfg)
	check(t, "Failed to create client gRPC credentials", err)
	conn, err := grpc.Dial(addr,
		grpc.WithTransportCredentials(clientCreds),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
	)
	check(t, "Failed to create connection", err)
	defer conn.Close()
	client := pb.NewTestServiceClient(conn)

	// make gRPC call
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = client.UnaryCall(ctx, &pb.SimpleRequest{})
	check(t, "Failed to make RPC", err)
}

func createFile(t *testing.T, dir, base string, buf []byte) string {
	t.Helper()
	path := filepath.Join(dir, base)
	check(t, "Failed to write file", ioutil.WriteFile(path, buf, os.ModePerm))
	return path
}

func check(t *testing.T, msg string, err error) {
	if err != nil {
		t.Helper()
		t.Fatalf("%s: %v", msg, err)
	}
}

type testServiceServer struct {
	pb.UnimplementedTestServiceServer
}

func (*testServiceServer) UnaryCall(ctx context.Context, req *pb.SimpleRequest) (*pb.SimpleResponse, error) {
	return &pb.SimpleResponse{Payload: req.Payload}, nil
}
