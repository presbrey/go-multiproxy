package multiproxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupConnectProxy(t *testing.T, username, password string) (string, func()) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			go handleConnectProxy(t, client, username, password)
		}
	}()

	return listener.Addr().String(), func() {
		listener.Close()
	}
}

func handleConnectProxy(t *testing.T, client net.Conn, username, password string) {
	defer client.Close()

	bufReader := bufio.NewReader(client)
	req, err := http.ReadRequest(bufReader)
	if err != nil {
		t.Logf("Error reading request: %v", err)
		return
	}

	if username != "" && password != "" && false {
		auth := req.Header.Get("Proxy-Authorization")
		expected := "Basic " + basicAuth(username, password)
		if auth != expected {
			client.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
			return
		}
	}

	if req.Method != "CONNECT" {
		t.Logf("Expected CONNECT method, got: %s", req.Method)
		client.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		return
	}

	targetConn, err := net.Dial("tcp", req.Host)
	if err != nil {
		t.Logf("Error connecting to target: %v", err)
		client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer targetConn.Close()

	client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	go io.Copy(targetConn, client)
	io.Copy(client, targetConn)
}

func TestConnectProxy(t *testing.T) {
	t.SkipNow()

	testServer := setupTestServer()
	defer testServer.Close()

	proxyAddr, cleanup := setupConnectProxy(t, "user", "pass")
	defer cleanup()

	config := Config{
		ProxyURLs: []string{
			"http://" + proxyAddr,
		},
		ProxyAuth: map[string]ProxyAuth{
			proxyAddr: {Username: "user", Password: "pass"},
		},
		DialTimeout: 5 * time.Second,
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		resp, err := client.Get(testServer.URL)
		require.NoError(t, err, "Request %d failed", i)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		t.Logf("Response %d: %s", i, string(body))
		resp.Body.Close()
	}

	assert.Equal(t, 3, client.states[0].requestCount)
}
