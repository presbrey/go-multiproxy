package multiproxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/proxy"
	"golang.org/x/sync/singleflight"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

type ProxyAuth struct {
	Username string
	Password string
}

type Config struct {
	ProxyURLs          []string
	ProxyAuth          map[string]ProxyAuth
	CookieTimeout      time.Duration
	DialTimeout        time.Duration
	BackoffTime        time.Duration
	RequestTimeout     time.Duration
	RetryAttempts      int
	RetryDelay         time.Duration
	DefaultUserAgent   string
	ProxyUserAgents    map[string]string
	RateLimits         map[string]time.Duration
	ProxyRotateCount   int
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

	servers          []*url.URL
	proxyAuth        map[string]ProxyAuth
	cookieTimer      time.Duration
	dialTimeout      time.Duration
	backoffTime      time.Duration
	requestTimeout   time.Duration
	retryAttempts    int
	retryDelay       time.Duration
	defaultUserAgent string
	proxyUserAgents  map[string]string
	rateLimits       map[string]time.Duration
	proxyRotateCount int
}

func NewClient(config Config) (*Client, error) {
	if len(config.ProxyURLs) == 0 {
		return nil, errors.New("at least one proxy URL is required")
	}

	c := &Client{
		servers:          make([]*url.URL, len(config.ProxyURLs)),
		states:           make([]proxyState, len(config.ProxyURLs)),
		proxyAuth:        config.ProxyAuth,
		cookieTimer:      config.CookieTimeout,
		dialTimeout:      config.DialTimeout,
		backoffTime:      config.BackoffTime,
		requestTimeout:   config.RequestTimeout,
		retryAttempts:    config.RetryAttempts,
		retryDelay:       config.RetryDelay,
		defaultUserAgent: config.DefaultUserAgent,
		proxyUserAgents:  config.ProxyUserAgents,
		rateLimits:       config.RateLimits,
		proxyRotateCount: config.ProxyRotateCount,
	}

	for i, proxyURL := range config.ProxyURLs {
		serverURL, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL %s: %v", proxyURL, err)
		}
		c.servers[i] = serverURL

		auth, hasAuth := c.proxyAuth[serverURL.Host]

		var transport http.RoundTripper

		dialer := &net.Dialer{
			KeepAlive: 30 * time.Second,
		}
		if c.dialTimeout > 0 {
			dialer.Timeout = c.dialTimeout
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

		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, err
		}

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

		if c.cookieTimer > 0 && now.Sub(state.lastUsed) > c.cookieTimer {
			jar, err := cookiejar.New(nil)
			if err != nil {
				return nil, err
			}
			state.cookieJar = jar
			state.client.Jar = jar
		}

		// Apply rate limiting
		if limit, ok := c.rateLimits[c.servers[idx].Host]; ok {
			if now.Sub(state.lastRequestAt) < limit {
				time.Sleep(limit - now.Sub(state.lastRequestAt))
			}
		}

		// Set User-Agent
		if userAgent, ok := c.proxyUserAgents[c.servers[idx].Host]; ok {
			req.Header.Set("User-Agent", userAgent)
		} else if c.defaultUserAgent != "" {
			req.Header.Set("User-Agent", c.defaultUserAgent)
		}

		// Set request timeout
		var (
			ctx    context.Context
			cancel context.CancelFunc
		)
		if c.dialTimeout > 0 || c.requestTimeout > 0 {
			ctx, cancel = context.WithTimeout(req.Context(), c.dialTimeout+c.requestTimeout)
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
			if c.backoffTime > 0 {
				state.backoffUntil = now.Add(c.backoffTime)
			}
			continue
		}
		state.successCount += 1

		state.lastUsed = now

		// Rotate proxy if needed
		if c.proxyRotateCount > 0 && state.requestCount%c.proxyRotateCount == 0 {
			c.currentIdx = (c.currentIdx + 1) % len(c.states)
		}

		return resp, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all proxy servers failed, last error: %v", lastErr)
	}
	return nil, errors.New("all proxy servers are unavailable")
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var finalErr error

	for attempt := 0; attempt <= c.retryAttempts; attempt++ {
		v, err, _ := c.sf.Do(req.URL.String(), func() (interface{}, error) {
			return c.do(req)
		})

		if err == nil {
			resp = v.(*http.Response)
			finalErr = nil
			break
		}
		finalErr = err

		if attempt < c.retryAttempts {
			time.Sleep(c.retryDelay)
		}
	}

	return resp, finalErr
}

func (c *Client) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}
