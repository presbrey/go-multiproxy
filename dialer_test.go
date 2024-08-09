package multiproxy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	assert.True(t, duration >= 2*time.Second, "Expected timeout to be at least 2 seconds, got %v", duration)
	assert.True(t, duration < 3*time.Second, "Expected timeout to be less than 3 seconds, got %v", duration)
}
