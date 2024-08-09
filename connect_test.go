package multiproxy

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateCertificate() ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return certPEM, keyPEM, nil
}

func setupHTTPSServer(t *testing.T) (*httptest.Server, []byte) {
	certPEM, keyPEM, err := generateCertificate()
	require.NoError(t, err)

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello from HTTPS server")
	}))

	server.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	server.StartTLS()

	return server, certPEM
}

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
	t.Logf("Received request: %s %s", req.Method, req.URL)

	if username != "" && password != "" {
		auth := req.Header.Get("Proxy-Authorization")
		expected := basicAuth(username, password)
		if auth != expected {
			t.Logf("Authentication failed")
			client.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
			return
		}
	}

	if req.Method != "CONNECT" {
		t.Logf("Expected CONNECT method, got: %s", req.Method)
		client.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		return
	}

	t.Logf("Attempting to connect to target: %s", req.URL.Host)
	targetConn, err := net.Dial("tcp", req.URL.Host)
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

func TestConnectProxyWithHTTPS(t *testing.T) {
	httpsServer, _ := setupHTTPSServer(t)
	if httpsServer == nil {
		t.Fatal("Failed to set up HTTPS server")
	}
	defer httpsServer.Close()

	proxyAddr, cleanup := setupConnectProxy(t, "user", "pass")
	if proxyAddr == "" {
		t.Fatal("Failed to set up CONNECT proxy")
	}
	defer cleanup()

	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("Failed to parse proxy URL: %v", err)
	}

	config := Config{
		Proxies: []Proxy{
			{
				URL:  proxyURL,
				Auth: &ProxyAuth{Username: "user", Password: "pass"},
			},
		},
		DialTimeout:        5 * time.Second,
		InsecureSkipVerify: true,
		RetryAttempts:      2,
		RetryDelay:         time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	if client == nil {
		t.Fatal("Client is nil")
	}

	t.Logf("HTTPS Server URL: %s", httpsServer.URL)
	t.Logf("Proxy Address: %s", proxyAddr)

	for i := 0; i < 3; i++ {
		resp, err := client.Get(httpsServer.URL)
		require.NoError(t, err, "Request %d failed", i)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		t.Logf("Response %d: %s", i, string(body))
		resp.Body.Close()
	}

	if len(client.states) == 0 {
		t.Fatal("Client states is empty")
	}
	assert.Equal(t, 3, client.states[0].requestCount)
}
