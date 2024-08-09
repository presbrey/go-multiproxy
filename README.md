# MultiProxy Client for Go

![Go Test](https://github.com/presbrey/go-multiproxy/workflows/Go%20Test/badge.svg)
[![codecov](https://codecov.io/gh/presbrey/go-multiproxy/branch/main/graph/badge.svg)](https://codecov.io/gh/presbrey/go-multiproxy)

## Overview

MultiProxy Client is a robust Go library designed to manage multiple HTTP/HTTPS proxies efficiently. It provides a fault-tolerant and load-balanced approach to making HTTP requests through a pool of proxies, with features like automatic retries, backoff mechanisms, and proxy rotation.

## Features

- Multiple proxy support
- Automatic proxy rotation
- Fault tolerance with retry mechanism
- Configurable timeouts and delays
- Cookie management
- Basic authentication support for proxies
- User-Agent rotation
- HTTPS and SOCKS5 proxy support
- Concurrent request handling using singleflight pattern

## Installation

To use MultiProxy Client in your Go project, you can install it using `go get`:

```
go get github.com/presbrey/go-multiproxy
```

Replace `yourusername` with the actual GitHub username or organization where this project is hosted.

## Usage

Here's a basic example of how to use the MultiProxy Client:

```go
package main

import (
    "fmt"
    "net/http"
    "time"
    
    "github.com/presbrey/go-multiproxy"
)

func main() {
    config := multiproxy.Config{
        ProxyURLs: []string{
            "http://proxy1.example.com:8080",
            "http://proxy2.example.com:8080",
        },
        ProxyAuth: map[string]multiproxy.ProxyAuth{
            "http://proxy1.example.com:8080": {Username: "user1", Password: "pass1"},
            "http://proxy2.example.com:8080": {Username: "user2", Password: "pass2"},
        },
        CookieTimeout:  10 * time.Minute,
        CookieOptions:  &cookiejar.Options{PublicSuffixList: publicsuffix.List},
        DialTimeout:    30 * time.Second,
        RequestTimeout: 1 * time.Minute,
        RetryAttempts:  3,
        RetryDelay:     5 * time.Second,
        ProxyRotateCount: 10,
    }

    client, err := multiproxy.NewClient(config)
    if err != nil {
        panic(err)
    }

    resp, err := client.Get("https://example.com")
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    fmt.Printf("Response status: %s\n", resp.Status)
}
```

## Configuration

The `Config` struct allows you to customize the behavior of the MultiProxy Client:

- `ProxyURLs`: List of proxy URLs to use
- `ProxyAuth`: Map of proxy URLs to their respective authentication credentials
- `ProxyRotateCount`: Number of requests after which to rotate to the next proxy
- `ProxyUserAgents`: Map of proxy URLs to their respective User-Agent strings

- `BackoffTime`: Time to wait before retrying a failed proxy
- `DialTimeout`: Timeout for establishing a connection to a proxy
- `RequestTimeout`: Timeout for the entire request (including dialing, writing request, and reading response)
- `RetryDelay`: Delay between retry attempts

- `CookieOptions`: Options for configuring the cookie jar (see `http.cookiejar.Options`)
- `CookieTimeout`: Duration for which cookies are valid

- `DefaultUserAgent`: Default User-Agent string to use if not specified in `ProxyUserAgents`

- `RateLimits`: Map of proxy URLs to their respective rate limit durations

- `RetryAttempts`: Number of times to retry a failed request

- `InsecureSkipVerify`: Whether to skip TLS certificate verification

## Testing

The project includes comprehensive test suites:

- `multiproxy_test.go`: Tests for the main MultiProxy Client functionality
- `connect_test.go`: Tests for HTTPS and CONNECT proxy functionality
- `errors_test.go`: Tests for error handling scenarios

To run the tests, use the following command:

```
go test ./...
```

## Contributing

Contributions to the MultiProxy Client are welcome! Please feel free to submit issues, fork the repository and send pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This software is provided as-is, and users should be aware of the legal and ethical considerations when using proxy servers. Always ensure you have the right to use the proxy servers you configure with this client.
