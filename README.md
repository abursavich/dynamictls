# DynamicTLS
[![License](https://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/abursavich/dynamictls/master/LICENSE)
[![GoDev](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=flat-square)](https://pkg.go.dev/github.com/abursavich/dynamictls)
[![GoReportCard](https://goreportcard.com/badge/github.com/abursavich/dynamictls)](https://goreportcard.com/report/github.com/abursavich/dynamictls)

DynamicTLS watches the filesystem and updates TLS configuration when certificate changes occur.

It provides simple integrations with HTTP/1.1, HTTP/2, gRPC, and Prometheus.

## Examples

### HTTP Server

```go
metrics, err := tlsprom.NewMetrics(
    tlsprom.WithHTTP(),
    tlsprom.WithServer(),
)
check(err)
prometheus.MustRegister(metrics)

cfg, err := dynamictls.NewConfig(
    dynamictls.WithCertificate(primaryCertFile, primaryKeyFile),
    dynamictls.WithCertificate(secondaryCertFile, secondaryKeyFile),
    dynamictls.WithRootCAs(caFile),
    dynamictls.WithNotifyFunc(metrics.Update),
    dynamictls.WithHTTP(), // adds HTTP/2 and HTTP/1.1 protocols
)
check(err)
defer cfg.Close()

lis, err := cfg.Listen(context.Background(), "tcp", addr)
check(err)
check(http.Serve(lis, http.DefaultServeMux))
```

### HTTP Client

```go
metrics, err := tlsprom.NewMetrics(
    tlsprom.WithHTTP(),
    tlsprom.WithClient(),
)
check(err)
prometheus.MustRegister(metrics)

cfg, err := dynamictls.NewConfig(
    dynamictls.WithBase(&tls.Config{
        MinVersion: tls.VersionTLS12,
    }),
    dynamictls.WithCertificate(certFile, keyFile),
    dynamictls.WithRootCAs(caFile),
    dynamictls.WithNotifyFunc(metrics.Update),
    dynamictls.WithHTTP(), // adds HTTP/2 and HTTP/1.1 protocols
)
check(err)
defer cfg.Close()

client := &http.Client{
    Transport: &http.Transport{
        DialTLSContext:    cfg.Dial,
        ForceAttemptHTTP2: true, // required if using a custom dialer with HTTP/2
    },
}
defer client.CloseIdleConnections()
```

### gRPC Server

```go
metrics, err := tlsprom.NewMetrics(
    tlsprom.WithGRPC(),
    tlsprom.WithServer(),
)
check(err)
prometheus.MustRegister(metrics)

cfg, err := dynamictls.NewConfig(
    dynamictls.WithBase(&tls.Config{
        ClientAuth: tls.RequireAndVerifyClientCert,
    }),
    dynamictls.WithCertificate(certFile, keyFile),
    dynamictls.WithRootCAs(caFile), // used by metrics to verify cert expiration
    dynamictls.WithClientCAs(caFile),
    dynamictls.WithNotifyFunc(metrics.Update),
)
check(err)
defer cfg.Close()

creds, err := grpctls.NewCredentials(cfg)
check(err)
grpcSrv := grpc.NewServer(grpc.Creds(creds))
pb.RegisterFooServer(grpcSrv, &fooServer{})

lis, err := net.Listen("tcp", addr)
check(err)
check(grpcSrv.Serve(lis)) // gRPC server uses plain TCP listener
```

### gRPC Client

```go
metrics, err := tlsprom.NewMetrics(
    tlsprom.WithGRPC(),
    tlsprom.WithClient(),
)
check(err)
prometheus.MustRegister(metrics)

cfg, err := dynamictls.NewConfig(
    dynamictls.WithCertificate(certFile, keyFile),
    dynamictls.WithRootCAs(caFile),
    dynamictls.WithNotifyFunc(metrics.Update),
)
check(err)
defer cfg.Close()

creds, err := grpctls.NewCredentials(cfg)
check(err)
conn, err := grpc.Dial(addr,
    grpc.WithTransportCredentials(creds),
    grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
)
check(err)
defer conn.Close()

client := pb.NewTestServiceClient(conn)
```