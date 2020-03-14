# DynamicTLS
[![License](https://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/abursavich/dynamictls/master/LICENSE)
[![GoDev](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=flat-square)](https://pkg.go.dev/github.com/abursavich/dynamictls)
[![GoReportCard](https://goreportcard.com/badge/github.com/abursavich/dynamictls)](https://goreportcard.com/report/github.com/abursavich/dynamictls)

DynamicTLS watches the filesystem and updates TLS configuration when certificate changes occur.

## Examples

### HTTP Server

```go
cfg, err := dynamictls.NewConfig(
    dynamictls.WithBase(&tls.Config{
        ClientAuth: tls.RequireAndVerifyClientCert,
        MinVersion: tls.VersionTLS12,
    }),
    dynamictls.WithCertificate(certFile, keyFile),
    dynamictls.WithClientCAs(clientCAsFile),
    dynamictls.WithHTTP(),
)
if err != nil {
    log.Fatal(err)
}
defer cfg.Close()

lis, err := cfg.Listen(context.Background(), "tcp", addr)
if err != nil {
    log.Fatal(err)
}
log.Fatal(http.Serve(lis, mux))
```

### HTTP Client

```go
cfg, err := dynamictls.NewConfig(
    dynamictls.WithBase(&tls.Config{
        MinVersion: tls.VersionTLS12,
    }),
    dynamictls.WithCertificate(certFile, keyFile),
    dynamictls.WithRootCAs(rootCAsFile),
    dynamictls.WithHTTP(),
)
if err != nil {
    log.Fatal(err)
}
defer cfg.Close()

client := &http.Client{
    Transport: &http.Transport{
        DialTLSContext: cfg.Dial,
    },
}
makeRequests(client)
```