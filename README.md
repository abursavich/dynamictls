# DynamicTLS
[![License](https://img.shields.io/badge/license-mit-blue.svg?style=for-the-badge)](https://raw.githubusercontent.com/abursavich/dynamictls/master/LICENSE)
[![GoDev Reference](https://img.shields.io/static/v1?logo=go&logoColor=white&color=00ADD8&label=dev&message=reference&style=for-the-badge)](https://pkg.go.dev/bursavich.dev/dynamictls)
[![Go Report Card](https://goreportcard.com/badge/bursavich.dev/dynamictls?style=for-the-badge)](https://goreportcard.com/report/bursavich.dev/dynamictls)
[![Build Status](https://img.shields.io/travis/com/abursavich/dynamictls/master?style=for-the-badge)](https://app.travis-ci.com/github/abursavich/dynamictls)
[![Coverage Status](https://img.shields.io/coveralls/github/abursavich/dynamictls/master?style=for-the-badge)](https://coveralls.io/github/abursavich/dynamictls?branch=master)

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