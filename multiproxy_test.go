package multiproxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
		ProxyURLs: []string{
			"socks5://" + proxy1,
			"socks5://" + proxy2,
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
		ProxyURLs: []string{
			"socks5://" + proxy1,
			"socks5://" + invalidProxy,
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
		ProxyURLs: []string{
			"socks5://" + proxy1,
			"socks5://" + proxy2,
		},
		ProxyAuth: map[string]ProxyAuth{
			proxy1: {Username: "user1", Password: "pass1"},
			proxy2: {Username: "user2", Password: "pass2"},
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
		ProxyURLs: []string{
			"socks5://" + invalidProxy,
			"socks5://" + proxy1,
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

func TestUserAgentRotation(t *testing.T) {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
	}

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.UserAgent())
	}))
	defer testServer.Close()

	proxy1, cleanup1 := setupSocks5Server(t, "", "")
	defer cleanup1()

	config := Config{
		ProxyURLs:   []string{"socks5://" + proxy1},
		UserAgents:  userAgents,
		DialTimeout: 5 * time.Second,
	}

	client, err := NewClient(config)
	assert.NoError(t, err)

	for i := 0; i < 4; i++ {
		resp, err := client.Get(testServer.URL)
		assert.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		resp.Body.Close()

		assert.Equal(t, userAgents[i%2], string(body))
	}
}

func TestRateLimiting(t *testing.T) {
	testServer := setupTestServer()
	defer testServer.Close()

	proxy1, cleanup1 := setupSocks5Server(t, "", "")
	defer cleanup1()

	config := Config{
		ProxyURLs: []string{"socks5://" + proxy1},
		RateLimits: map[string]time.Duration{
			proxy1: 1 * time.Second,
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
		ProxyURLs: []string{
			"socks5://" + proxy1,
			"socks5://" + proxy2,
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
		ProxyURLs: []string{
			"socks5://" + proxy,
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
