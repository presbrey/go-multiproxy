package multiproxy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAllProxiesUnavailable(t *testing.T) {
	testServer := setupTestServer()
	defer testServer.Close()

	// Use non-routable IPs to simulate unavailable proxies
	config := Config{
		ProxyURLs: []string{
			"socks5://10.255.255.1:1080",
			"socks5://10.255.255.2:1080",
		},
		DialTimeout:      1 * time.Second,
		DefaultUserAgent: "DefaultUserAgent/1.0",
		RetryAttempts:    1,
		RetryDelay:       500 * time.Millisecond,
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	_, err = client.Get(testServer.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all proxy servers failed")

	// Check that both proxies were attempted
	// Each proxy should be attempted twice due to the retry
	assert.Equal(t, 2, client.states[0].requestCount)
	assert.Equal(t, 2, client.states[0].failureCount)
	assert.Equal(t, 2, client.states[1].requestCount)
	assert.Equal(t, 2, client.states[1].failureCount)
}

func TestClientGetError(t *testing.T) {
	config := Config{
		ProxyURLs:   []string{"http://10.255.255.1:8080"},
		DialTimeout: 5 * time.Second,
	}

	client, err := NewClient(config)
	require.NoError(t, err)
	_, err = client.Get("\000")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid control character")
}

func TestClientNewError(t *testing.T) {
	config := Config{
		ProxyURLs:   []string{"\000"},
		DialTimeout: 5 * time.Second,
	}

	_, err := NewClient(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid control character")
}

func TestClientWithNoProxyURLs(t *testing.T) {
	config := Config{
		ProxyURLs:   []string{},
		DialTimeout: 5 * time.Second,
	}

	_, err := NewClient(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one proxy URL is required")
}

func TestDialTimeout(t *testing.T) {
	// Use a non-routable IP address to simulate a timeout
	nonRoutableIP := "10.255.255.1:8080"

	config := Config{
		ProxyURLs: []string{
			"http://" + nonRoutableIP,
		},
		DialTimeout:    1 * time.Second,
		RequestTimeout: 1 * time.Second,
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	start := time.Now()
	_, err = client.Get("http://example.com")
	duration := time.Since(start)

	require.Error(t, err)
	assert.True(t, duration >= 1*time.Second, "Expected timeout to be at least 1 second, got %v", duration)
	assert.True(t, duration < 2*time.Second, "Expected timeout to be less than 2 seconds, got %v", duration)
}
