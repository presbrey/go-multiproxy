package multiproxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/proxy"
	"golang.org/x/sync/singleflight"
)

type ProxyAuth struct {
	Username string
	Password string
}

type Config struct {
	// Proxy configuration
	ProxyURLs        []string
	ProxyAuth        map[string]ProxyAuth
	ProxyRotateCount int
	ProxyUserAgents  map[string]string

	// Timeouts and delays
	BackoffTime    time.Duration
	DialTimeout    time.Duration
	RequestTimeout time.Duration
	RetryDelay     time.Duration

	// Cookie handling
	CookieOptions *cookiejar.Options
	CookieTimeout time.Duration

	// User-Agent configuration
	DefaultUserAgent string

	// Rate limiting
	RateLimits map[string]time.Duration

	// Retry configuration
	RetryAttempts int

	// TLS configuration
	InsecureSkipVerify bool
}

type proxyState struct {
	client        *http.Client
	cookieJar     *cookiejar.Jar
	lastUsed      time.Time
	backoffUntil  time.Time
	requestCount  int
	failureCount  int
	successCount  int
	lastRequestAt time.Time
}

type Client struct {
	states     []proxyState
	currentIdx int
	mu         sync.Mutex
	sf         singleflight.Group

	config  Config
	servers []*url.URL
}

func NewClient(config Config) (*Client, error) {
	if len(config.ProxyURLs) == 0 {
		return nil, errors.New("at least one proxy URL is required")
	}

	c := &Client{
		config:  config,
		servers: make([]*url.URL, len(config.ProxyURLs)),
		states:  make([]proxyState, len(config.ProxyURLs)),
	}

	for i, proxyURL := range config.ProxyURLs {
		serverURL, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL %s: %v", proxyURL, err)
		}
		c.servers[i] = serverURL

		auth, hasAuth := c.config.ProxyAuth[serverURL.Host]

		var transport http.RoundTripper

		dialer := &net.Dialer{
			KeepAlive: 30 * time.Second,
		}
		if c.config.DialTimeout > 0 {
			dialer.Timeout = c.config.DialTimeout
		}

		if serverURL.Scheme == "socks5" {
			auth := &proxy.Auth{
				User:     auth.Username,
				Password: auth.Password,
			}
			if !hasAuth {
				auth = nil
			}
			socksDialer, err := proxy.SOCKS5("tcp", serverURL.Host, auth, dialer)
			if err != nil {
				return nil, fmt.Errorf("failed to create SOCKS5 dialer for %s: %v", serverURL.Host, err)
			}
			transport = &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return socksDialer.(proxy.ContextDialer).DialContext(ctx, network, addr)
				},
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: config.InsecureSkipVerify,
				},
			}
		} else {
			proxyURL := func(_ *http.Request) (*url.URL, error) {
				return serverURL, nil
			}
			transport = &http.Transport{
				Proxy:       proxyURL,
				DialContext: dialer.DialContext,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: config.InsecureSkipVerify,
				},
			}
			if hasAuth {
				transport.(*http.Transport).ProxyConnectHeader = http.Header{
					"Proxy-Authorization": {basicAuth(auth.Username, auth.Password)},
				}
				// Also set it for non-CONNECT requests
				transport.(*http.Transport).Proxy = func(req *http.Request) (*url.URL, error) {
					req.Header.Set("Proxy-Authorization", basicAuth(auth.Username, auth.Password))
					return serverURL, nil
				}
			}
		}

		jar, _ := cookiejar.New(config.CookieOptions)

		c.states[i] = proxyState{
			client: &http.Client{
				Transport: transport,
				Jar:       jar,
			},
			cookieJar: jar,
		}
	}

	return c, nil
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	startIdx := c.currentIdx
	now := time.Now()

	var lastErr error

	for i := 0; i < len(c.states); i++ {
		idx := (startIdx + i) % len(c.states)
		state := &c.states[idx]

		if now.Before(state.backoffUntil) {
			continue
		}

		if c.config.CookieTimeout > 0 && now.Sub(state.lastUsed) > c.config.CookieTimeout {
			jar, _ := cookiejar.New(c.config.CookieOptions)
			state.cookieJar = jar
			state.client.Jar = jar
		}

		// Apply rate limiting
		if limit, ok := c.config.RateLimits[c.servers[idx].Host]; ok {
			if now.Sub(state.lastRequestAt) < limit {
				time.Sleep(limit - now.Sub(state.lastRequestAt))
			}
		}

		// Set proxy-specific User-Agent if configured
		if userAgent, ok := c.config.ProxyUserAgents[c.servers[idx].Host]; ok {
			req.Header.Set("User-Agent", userAgent)
		}

		// Set request timeout
		var (
			ctx    context.Context
			cancel context.CancelFunc
		)
		if c.config.DialTimeout > 0 || c.config.RequestTimeout > 0 {
			ctx, cancel = context.WithTimeout(req.Context(), c.config.DialTimeout+c.config.RequestTimeout)
		} else {
			ctx, cancel = context.WithCancel(req.Context())
		}
		defer cancel()
		req = req.WithContext(ctx)

		resp, err := state.client.Do(req)
		state.lastRequestAt = time.Now()
		state.requestCount++

		if err != nil {
			lastErr = err
			state.failureCount += 1
			if c.config.BackoffTime > 0 {
				state.backoffUntil = now.Add(c.config.BackoffTime)
			}
			continue
		}
		state.successCount += 1

		state.lastUsed = now

		// Rotate proxy if needed
		if c.config.ProxyRotateCount > 0 && state.requestCount%c.config.ProxyRotateCount == 0 {
			c.currentIdx = (c.currentIdx + 1) % len(c.states)
		}

		return resp, nil
	}

	return nil, fmt.Errorf("all proxy servers failed, last error: %v", lastErr)
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var finalErr error

	for attempt := 0; attempt <= c.config.RetryAttempts; attempt++ {
		v, err, _ := c.sf.Do(req.URL.String(), func() (interface{}, error) {
			return c.do(req)
		})

		if err == nil {
			resp = v.(*http.Response)
			finalErr = nil
			break
		}
		finalErr = err

		if attempt < c.config.RetryAttempts {
			time.Sleep(c.config.RetryDelay)
		}
	}

	return resp, finalErr
}

func (c *Client) NewRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	// Set default User-Agent if configured
	if c.config.DefaultUserAgent != "" {
		req.Header.Set("User-Agent", c.config.DefaultUserAgent)
	}

	return req, nil
}

func (c *Client) Get(url string) (*http.Response, error) {
	req, err := c.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func (c *Client) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := c.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.Do(req)
}

func (c *Client) Head(url string) (*http.Response, error) {
	req, err := c.NewRequest("HEAD", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}
