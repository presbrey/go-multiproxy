package multiproxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/armon/go-socks5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupSlowServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		fmt.Fprintf(w, "Hello from %s", r.URL.Path)
	}))
}

func setupTestServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello from %s", r.URL.Path)
	}))
}

func setupSocks5Server(t *testing.T, username, password string) (string, func()) {
	conf := &socks5.Config{}
	if username != "" && password != "" {
		cator := socks5.UserPassAuthenticator{
			Credentials: socks5.StaticCredentials{
				username: password,
			},
		}
		conf.AuthMethods = []socks5.Authenticator{cator}
	}

	server, err := socks5.New(conf)
	require.NoError(t, err)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	errCh := make(chan error, 1)
	go func() {
		err := server.Serve(listener)
		if err != nil && strings.Contains(err.Error(), "use of closed network connection") {
			err = nil
		}
		errCh <- err
	}()

	return listener.Addr().String(), func() {
		listener.Close()
		select {
		case err := <-errCh:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Error("Timeout waiting for server to close")
		}
	}
}

func TestRoundRobinSelection(t *testing.T) {
	testServer := setupTestServer()
	defer testServer.Close()

	proxy1, cleanup1 := setupSocks5Server(t, "", "")
	defer cleanup1()
	proxy2, cleanup2 := setupSocks5Server(t, "", "")
	defer cleanup2()

	config := Config{
		Proxies: []Proxy{
			{URL: &url.URL{Scheme: "socks5", Host: proxy1}},
			{URL: &url.URL{Scheme: "socks5", Host: proxy2}},
		},
		DialTimeout:      5 * time.Second,
		ProxyRotateCount: 1,
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	for i := 0; i < 4; i++ {
		resp, err := client.Get(testServer.URL)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		t.Logf("Response %d: %s", i, string(body))
		resp.Body.Close()
	}

	assert.Equal(t, 2, client.states[0].requestCount)
	assert.Equal(t, 2, client.states[1].requestCount)
}

func TestBackoff(t *testing.T) {
	testServer := setupTestServer()
	defer testServer.Close()

	proxy1, cleanup1 := setupSocks5Server(t, "", "")
	defer cleanup1()
	invalidProxy := "127.0.0.1:1" // Invalid proxy to trigger backoff

	config := Config{
		Proxies: []Proxy{
			{URL: &url.URL{Scheme: "socks5", Host: proxy1}},
			{URL: &url.URL{Scheme: "socks5", Host: invalidProxy}},
		},
		DialTimeout:      2 * time.Second,
		BackoffTime:      5 * time.Second,
		ProxyRotateCount: 1,
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		resp, err := client.Get(testServer.URL)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		t.Logf("Response %d: %s", i, string(body))
		resp.Body.Close()
	}

	assert.Equal(t, 3, client.states[0].requestCount)
	assert.Equal(t, 3, client.states[0].successCount)
	assert.Equal(t, 0, client.states[0].failureCount)
	assert.Equal(t, 1, client.states[1].requestCount)
	assert.Equal(t, 0, client.states[1].successCount)
	assert.Equal(t, 1, client.states[1].failureCount)
}

func TestAuthentication(t *testing.T) {
	testServer := setupTestServer()
	defer testServer.Close()

	proxy1, cleanup1 := setupSocks5Server(t, "user1", "pass1")
	defer cleanup1()
	proxy2, cleanup2 := setupSocks5Server(t, "user2", "pass2")
	defer cleanup2()

	config := Config{
		Proxies: []Proxy{
			{URL: &url.URL{Scheme: "socks5", Host: proxy1}, Auth: &ProxyAuth{Username: "user1", Password: "pass1"}},
			{URL: &url.URL{Scheme: "socks5", Host: proxy2}, Auth: &ProxyAuth{Username: "user2", Password: "pass2"}},
		},
		DialTimeout:      5 * time.Second,
		ProxyRotateCount: 1,
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	for i := 0; i < 4; i++ {
		resp, err := client.Get(testServer.URL)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		t.Logf("Response %d: %s", i, string(body))
		resp.Body.Close()
	}

	assert.Equal(t, 2, client.states[0].requestCount)
	assert.Equal(t, 2, client.states[1].requestCount)
}

func TestRetryMechanism(t *testing.T) {
	testServer := setupSlowServer()
	defer testServer.Close()

	proxy1, cleanup1 := setupSocks5Server(t, "", "")
	defer cleanup1()
	invalidProxy := "127.0.0.1:1" // Invalid proxy to trigger retry

	config := Config{
		Proxies: []Proxy{
			{URL: &url.URL{Scheme: "socks5", Host: invalidProxy}},
			{URL: &url.URL{Scheme: "socks5", Host: proxy1}},
		},
		RetryAttempts: 2,
		RetryDelay:    time.Second,
	}

	client, err := NewClient(config)
	assert.NoError(t, err)

	startTime := time.Now()
	resp, err := client.Get(testServer.URL)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
	duration := time.Since(startTime)

	assert.True(t, duration >= time.Second, "Retry mechanism was not triggered")
	assert.Equal(t, 1, client.states[0].requestCount)
	assert.Equal(t, 0, client.states[0].successCount)
	assert.Equal(t, 1, client.states[0].failureCount)
	assert.Equal(t, 1, client.states[1].requestCount)
	assert.Equal(t, 1, client.states[1].successCount)
	assert.Equal(t, 0, client.states[1].failureCount)
}

func TestUserAgentOverride(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.UserAgent())
	}))
	defer testServer.Close()

	proxy1, cleanup1 := setupSocks5Server(t, "", "")
	defer cleanup1()
	proxy2, cleanup2 := setupSocks5Server(t, "", "")
	defer cleanup2()

	config := Config{
		Proxies: []Proxy{
			{URL: &url.URL{Scheme: "socks5", Host: proxy1}, UserAgent: "CustomUserAgent/1.0"},
			{URL: &url.URL{Scheme: "socks5", Host: proxy2}},
		},
		DefaultUserAgent: "DefaultUserAgent/1.0",
		DialTimeout:      5 * time.Second,
		ProxyRotateCount: 1, // Ensure we switch proxies after each request
	}

	client, err := NewClient(config)
	assert.NoError(t, err)

	// Test custom user agent for proxy1
	resp, err := client.Get(testServer.URL)
	assert.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, "CustomUserAgent/1.0", string(body))

	// Test default user agent for proxy2
	resp, err = client.Get(testServer.URL)
	assert.NoError(t, err)
	body, err = io.ReadAll(resp.Body)
	assert.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, "DefaultUserAgent/1.0", string(body))
}

func TestRateLimiting(t *testing.T) {
	testServer := setupTestServer()
	defer testServer.Close()

	proxy1, cleanup1 := setupSocks5Server(t, "", "")
	defer cleanup1()

	proxyURL := &url.URL{Scheme: "socks5", Host: proxy1}
	config := Config{
		Proxies: []Proxy{
			{URL: proxyURL},
		},
		RateLimits: map[string]time.Duration{
			proxyURL.Host: 1 * time.Second,
		},
		DialTimeout: 5 * time.Second,
	}

	client, err := NewClient(config)
	assert.NoError(t, err)

	startTime := time.Now()
	for i := 0; i < 3; i++ {
		resp, err := client.Get(testServer.URL)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	}
	duration := time.Since(startTime)

	assert.True(t, duration >= 2*time.Second, "Rate limiting was not respected")
}

func TestProxyRotation(t *testing.T) {
	testServer := setupTestServer()
	defer testServer.Close()

	proxy1, cleanup1 := setupSocks5Server(t, "", "")
	defer cleanup1()
	proxy2, cleanup2 := setupSocks5Server(t, "", "")
	defer cleanup2()

	config := Config{
		Proxies: []Proxy{
			{URL: &url.URL{Scheme: "socks5", Host: proxy1}},
			{URL: &url.URL{Scheme: "socks5", Host: proxy2}},
		},
		ProxyRotateCount: 2,
		DialTimeout:      5 * time.Second,
	}

	client, err := NewClient(config)
	assert.NoError(t, err)

	for i := 0; i < 6; i++ {
		resp, err := client.Get(testServer.URL)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	}

	assert.Equal(t, 4, client.states[0].requestCount)
	assert.Equal(t, 2, client.states[1].requestCount)
}

func TestCookieTimeout(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("test_cookie")
		if err == http.ErrNoCookie {
			http.SetCookie(w, &http.Cookie{Name: "test_cookie", Value: "test_value"})
			w.WriteHeader(http.StatusOK)
			return
		}
		if cookie.Value == "test_value" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer testServer.Close()

	proxy, cleanup := setupSocks5Server(t, "", "")
	defer cleanup()

	config := Config{
		Proxies: []Proxy{
			{URL: &url.URL{Scheme: "socks5", Host: proxy}},
		},
		CookieTimeout: 2 * time.Second,
		DialTimeout:   5 * time.Second,
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	// First request should set the cookie
	resp, err := client.Get(testServer.URL)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Second request should use the existing cookie
	resp, err = client.Get(testServer.URL)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Wait for the cookie to expire
	time.Sleep(3 * time.Second)

	// Third request should set a new cookie
	resp, err = client.Get(testServer.URL)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	assert.Equal(t, 3, client.states[0].requestCount)
}

func TestClientHead(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "HEAD" {
			t.Errorf("Expected HEAD request, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
	}))
	defer testServer.Close()

	proxy, cleanup := setupSocks5Server(t, "", "")
	defer cleanup()

	config := Config{
		Proxies:     []Proxy{{URL: &url.URL{Scheme: "socks5", Host: proxy}}},
		DialTimeout: 5 * time.Second,
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	resp, err := client.Head(testServer.URL)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/plain", resp.Header.Get("Content-Type"))
	resp.Body.Close()

	assert.Equal(t, 1, client.states[0].requestCount)
}

func TestClientPost(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/x-www-form-urlencoded" {
			t.Errorf("Expected Content-Type application/x-www-form-urlencoded, got %s", contentType)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Error reading body: %v", err)
		}
		if string(body) != "key=value" {
			t.Errorf("Expected body 'key=value', got '%s'", string(body))
		}
		fmt.Fprint(w, "POST successful")
	}))
	defer testServer.Close()

	proxy, cleanup := setupSocks5Server(t, "", "")
	defer cleanup()

	config := Config{
		Proxies:     []Proxy{{URL: &url.URL{Scheme: "socks5", Host: proxy}}},
		DialTimeout: 5 * time.Second,
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	resp, err := client.Post(testServer.URL, "application/x-www-form-urlencoded", strings.NewReader("key=value"))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "POST successful", string(body))
	resp.Body.Close()

	assert.Equal(t, 1, client.states[0].requestCount)
}
