# DynamicTLS
[![License](https://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/abursavich/dynamictls/master/LICENSE)
[![GoDev](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=flat-square)](https://pkg.go.dev/github.com/abursavich/dynamictls)
[![GoReportCard](https://goreportcard.com/badge/github.com/abursavich/dynamictls)](https://goreportcard.com/report/github.com/abursavich/dynamictls)

DynamicTLS watches the filesystem and updates TLS configuration when certificate changes occur.

It provides easy integrations with HTTP/1.1, HTTP/2, gRPC, and Prometheus.

## Examples

### HTTP Server

```go
tlsMetrics, err := tlsprom.NewMetrics(
    tlsprom.WithHTTP(),
    tlsprom.WithServer(),
)
check(err)
cfg, err := dynamictls.NewConfig(
    dynamictls.WithCertificate(primaryCertFile, primaryKeyFile),
    dynamictls.WithCertificate(secondaryCertFile, secondaryKeyFile),
    dynamictls.WithRootCAs(caFile),
    dynamictls.WithNotifyFunc(tlsMetrics.Update),
    dynamictls.WithHTTP(),
)
check(err)
defer cfg.Close()

reg := prometheus.NewRegistry()
reg.MustRegister(tlsMetrics)
reg.MustRegister(prometheus.NewBuildInfoCollector())
reg.MustRegister(prometheus.NewGoCollector())
mux := http.NewServeMux()
mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))

lis, err := cfg.Listen(context.Background(), "tcp", addr)
check(err)
check(http.Serve(lis, mux))
```

### HTTP Client

```go
cfg, err := dynamictls.NewConfig(
    dynamictls.WithBase(&tls.Config{
        MinVersion: tls.VersionTLS12,
    }),
    dynamictls.WithCertificate(certFile, keyFile),
    dynamictls.WithRootCAs(caFile),
    dynamictls.WithHTTP(),
)
check(err)
defer cfg.Close()

client := &http.Client{
    Transport: &http.Transport{
        DialTLSContext: cfg.Dial,
    },
}
defer client.CloseIdleConnections()
makeRequests(client)
```

### gRPC Server

```go
tlsMetrics, err := tlsprom.NewMetrics(
    tlsprom.WithGRPC(),
    tlsprom.WithServer(),
)
check(err)
cfg, err := dynamictls.NewConfig(
    dynamictls.WithBase(&tls.Config{
        ClientAuth: tls.RequireAndVerifyClientCert,
    }),
    dynamictls.WithCertificate(certFile, keyFile),
    dynamictls.WithRootCAs(caFile),
    dynamictls.WithClientCAs(caFile),
    dynamictls.WithNotifyFunc(tlsMetrics.Update),
)
check(err)
defer cfg.Close()

creds, err := grpctls.NewCredentials(cfg)
check(err)
srv := grpc.NewServer(grpc.Creds(creds))
pb.RegisterFooServer(srv, &fooServer{})

reg := prometheus.NewRegistry()
reg.MustRegister(tlsMetrics)
reg.MustRegister(prometheus.NewBuildInfoCollector())
reg.MustRegister(prometheus.NewGoCollector())
mux := http.NewServeMux()
mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
go func() { check(http.ListenAndServe(httpAddr, mux)) }()

lis, err := net.Listen("tcp", grpcAddr)
check(err)
check(srv.Serve(lis))
```