package multiproxy

import (
	"context"
	"encoding/base64"
	"errors"
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
	ProxyURLs        []string
	ProxyAuth        map[string]ProxyAuth
	CookieTimeout    time.Duration
	DialTimeout      time.Duration
	BackoffTime      time.Duration
	RequestTimeout   time.Duration
	RetryAttempts    int
	RetryDelay       time.Duration
	UserAgents       []string
	RateLimits       map[string]time.Duration
	ProxyRotateCount int
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
	servers          []*url.URL
	states           []proxyState
	proxyAuth        map[string]ProxyAuth
	currentIdx       int
	mu               sync.Mutex
	cookieTimer      time.Duration
	dialTimeout      time.Duration
	backoffTime      time.Duration
	requestTimeout   time.Duration
	retryAttempts    int
	retryDelay       time.Duration
	userAgents       []string
	rateLimits       map[string]time.Duration
	proxyRotateCount int
	sf               singleflight.Group
}

func NewClient(config Config) (*Client, error) {
	if len(config.ProxyURLs) == 0 {
		return nil, errors.New("at least one proxy URL is required")
	}

	if config.DialTimeout == 0 {
		config.DialTimeout = 30 * time.Second
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
		userAgents:       config.UserAgents,
		rateLimits:       config.RateLimits,
		proxyRotateCount: config.ProxyRotateCount,
	}

	for i, proxyURL := range config.ProxyURLs {
		serverURL, err := url.Parse(proxyURL)
		if err != nil {
			return nil, err
		}
		c.servers[i] = serverURL

		auth, hasAuth := c.proxyAuth[serverURL.Host]

		var transport http.RoundTripper

		if serverURL.Scheme == "socks5" {
			auth := &proxy.Auth{
				User:     auth.Username,
				Password: auth.Password,
			}
			if !hasAuth {
				auth = nil
			}
			dialer, _ := proxy.SOCKS5("tcp", serverURL.Host, auth, proxy.Direct)
			transport = &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.Dial(network, addr)
				},
			}
		} else {
			proxyURL := func(_ *http.Request) (*url.URL, error) {
				return serverURL, nil
			}
			transport = &http.Transport{
				Proxy: proxyURL,
			}
			if hasAuth {
				transport.(*http.Transport).ProxyConnectHeader = http.Header{
					"Proxy-Authorization": {basicAuth(auth.Username, auth.Password)},
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

		// Set a random User-Agent if available
		if len(c.userAgents) > 0 {
			req.Header.Set("User-Agent", c.userAgents[state.requestCount%len(c.userAgents)])
		}

		// Set request timeout
		var (
			ctx    context.Context
			cancel context.CancelFunc
		)
		if c.requestTimeout > 0 {
			ctx, cancel = context.WithTimeout(req.Context(), c.requestTimeout)
		} else {
			ctx, cancel = context.WithCancel(req.Context())
		}
		defer cancel()
		req = req.WithContext(ctx)

		resp, err := state.client.Do(req)
		state.lastRequestAt = time.Now()
		state.requestCount++

		if err != nil {
			state.failureCount += 1
			if c.backoffTime > 0 {
				state.backoffUntil = now.Add(c.backoffTime)
			}
			continue
		}
		state.successCount += 1

		state.lastUsed = now

		// always rotate proxy
		// c.currentIdx = (idx + 1) % len(c.states)

		// Rotate proxy if needed
		if c.proxyRotateCount > 0 && state.requestCount%c.proxyRotateCount == 0 {
			c.currentIdx = (c.currentIdx + 1) % len(c.states)
		}

		return resp, nil
	}

	return nil, errors.New("all proxy servers are unavailable")
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error

	for attempt := 0; attempt <= c.retryAttempts; attempt++ {
		v, err, _ := c.sf.Do(req.URL.String(), func() (interface{}, error) {
			return c.do(req)
		})

		if err == nil {
			resp = v.(*http.Response)
			break
		}

		if attempt < c.retryAttempts {
			time.Sleep(c.retryDelay)
		}
	}

	return resp, err
}

func (c *Client) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}
