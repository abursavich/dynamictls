# DynamicTLS
[![License](https://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/abursavich/dynamictls/master/LICENSE)
[![GoDev Reference](https://pkg.go.dev/badge/github.com/abursavich/dynamictls)](https://pkg.go.dev/github.com/abursavich/dynamictls)
[![Go Report Card](https://goreportcard.com/badge/github.com/abursavich/dynamictls)](https://goreportcard.com/report/github.com/abursavich/dynamictls)
[![Coverage Status](https://coveralls.io/repos/github/abursavich/dynamictls/badge.svg?branch=master)](https://coveralls.io/github/abursavich/dynamictls?branch=master)
[![Build Status](https://travis-ci.com/abursavich/dynamictls.svg?branch=master)](https://travis-ci.com/abursavich/dynamictls)

DynamicTLS watches the filesystem and updates TLS configuration when certificate changes occur.

It provides simple integrations with HTTP/1.1, HTTP/2, gRPC, and Prometheus.

## Examples

### HTTP Server

```go
// create metrics
metrics, err := tlsprom.NewMetrics(
    tlsprom.WithHTTP(),
    tlsprom.WithServer(),
)
check(err)
prometheus.MustRegister(metrics)

// create TLS config
cfg, err := dynamictls.NewConfig(
    dynamictls.WithNotifyFunc(metrics.Update),
    dynamictls.WithCertificate(primaryCertFile, primaryKeyFile),
    dynamictls.WithCertificate(secondaryCertFile, secondaryKeyFile),
    dynamictls.WithRootCAs(caFile),
    dynamictls.WithHTTP(), // NB: adds HTTP/2 and HTTP/1.1 protocols
)
check(err)
defer cfg.Close()

// listen and serve
lis, err := cfg.Listen(context.Background(), "tcp", addr)
check(err)
check(http.Serve(lis, http.DefaultServeMux))
```

### HTTP Client

```go
// create metrics
metrics, err := tlsprom.NewMetrics(
    tlsprom.WithHTTP(),
    tlsprom.WithClient(),
)
check(err)
prometheus.MustRegister(metrics)

// create TLS config
cfg, err := dynamictls.NewConfig(
    dynamictls.WithNotifyFunc(metrics.Update),
    dynamictls.WithBase(&tls.Config{
        MinVersion: tls.VersionTLS12,
    }),
    dynamictls.WithCertificate(certFile, keyFile),
    dynamictls.WithRootCAs(caFile),
    dynamictls.WithHTTP(), // NB: adds HTTP/2 and HTTP/1.1 protocols
)
check(err)
defer cfg.Close()

// create HTTP client
client := &http.Client{
    Transport: &http.Transport{
        DialTLSContext:    cfg.Dial, // NB: DialTLSContext added in go 1.14
        ForceAttemptHTTP2: true,     // NB: required if using a custom dialer with HTTP/2
    },
}
defer client.CloseIdleConnections()
```

### gRPC Server

```go
// create metrics
metrics, err := tlsprom.NewMetrics(
    tlsprom.WithGRPC(),
    tlsprom.WithServer(),
)
check(err)
prometheus.MustRegister(metrics)

// create TLS config
cfg, err := dynamictls.NewConfig(
    dynamictls.WithNotifyFunc(metrics.Update),
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
```

### gRPC Client

```go
// create metrics
metrics, err := tlsprom.NewMetrics(
    tlsprom.WithGRPC(),
    tlsprom.WithClient(),
)
check(err)
prometheus.MustRegister(metrics)

// create TLS config
cfg, err := dynamictls.NewConfig(
    dynamictls.WithNotifyFunc(metrics.Update),
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
```