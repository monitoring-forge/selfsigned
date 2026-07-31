package selfsigned

import (
	"crypto/ecdsa"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTLSConfig_Default(t *testing.T) {
	cfg, err := TLSConfig()
	assert.NoError(t, err, "unexpected error")
	assert.NotNil(t, cfg, "expected non-nil tls.Config")
	assert.Equal(t, len(cfg.Certificates), 1, "expected exactly one certificate in tls.Config")
}

func TestTLSConfig_WithOptions(t *testing.T) {
	commonName := "example.com"
	notAfter := time.Now().AddDate(1, 0, 0).Truncate(time.Second)
	cfg, err := TLSConfig(CommonName(commonName), NotAfter(notAfter))
	assert.NoError(t, err, "unexpected error")
	assert.NotNil(t, cfg, "expected non-nil tls.Config")
	assert.Equal(t, len(cfg.Certificates), 1, "expected exactly one certificate in tls.Config")
	assert.NotNil(t, cfg.Certificates[0].Certificate, "expected certificate to be non-nil")
	assert.Equal(t, cfg.Certificates[0].Leaf.Subject.CommonName, commonName, "expected certificate CommonName to match")
	assert.Equal(t, cfg.Certificates[0].Leaf.NotAfter, notAfter.UTC(), "expected certificate NotAfter to match")
	assert.NotNil(t, cfg.Certificates[0].PrivateKey, "expected private key to be non-nil")
	_, ok := cfg.Certificates[0].PrivateKey.(*ecdsa.PrivateKey)
	assert.True(t, ok, "expected private key to be of type *ecdsa.PrivateKey")
}

// httpsサーバを起動して、自己署名証明書が正しく機能するかを確認するテスト
func TestTLSConfig_HTTPSServer(t *testing.T) {
	commonName := "example.com"
	cfg, err := TLSConfig(CommonName(commonName))
	assert.NoError(t, err, "unexpected error")
	assert.NotNil(t, cfg, "expected non-nil tls.Config")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	server := &http.Server{
		Handler:   mux,
		TLSConfig: cfg,
	}

	go func() {
		err := server.ServeTLS(ln, "", "")
		assert.NoError(t, err, "unexpected error")
	}()

	// クライアントからHTTPSリクエストを送信
	baseURL := "https://" + ln.Addr().String()
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
	}
	resp, err := client.Get(baseURL + "/healthz")
	assert.NoError(t, err, "unexpected error")
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "expected status OK")
	assert.NotNil(t, resp.TLS, "expected resp.TLS to be non-nil")
	assert.Greater(t, len(resp.TLS.PeerCertificates), 0, "expected at least one peer certificate")
	err = resp.TLS.PeerCertificates[0].VerifyHostname("example.com")
	assert.NoError(t, err, "unexpected error")
}
