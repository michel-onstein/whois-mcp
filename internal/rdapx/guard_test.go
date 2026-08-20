package rdapx

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBlockReason(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.15.2.9", "::1",
		"10.0.0.5", "172.16.0.1", "192.168.1.1",
		"169.254.169.254", // cloud metadata: the classic SSRF target
		"fd00::1",         // unique-local
		"fe80::1",         // link-local
		"0.0.0.0", "::",
		"100.64.0.1", // CGNAT
		"224.0.0.1",  // multicast
		"198.18.0.1", // benchmarking
		"240.0.0.1",  // reserved
	}
	for _, s := range blocked {
		if r := blockReason(net.ParseIP(s)); r == "" {
			t.Errorf("blockReason(%s) = allowed; want blocked", s)
		}
	}

	allowed := []string{"1.1.1.1", "8.8.8.8", "199.7.83.42", "2606:4700::1111"}
	for _, s := range allowed {
		if r := blockReason(net.ParseIP(s)); r != "" {
			t.Errorf("blockReason(%s) = %q; want allowed", s, r)
		}
	}

	if blockReason(nil) == "" {
		t.Error("nil IP must be blocked")
	}
}

// TestGuardBlocksLoopbackInPractice proves the guard is actually wired into the
// dialer, not merely defined: a real request to a loopback server must fail.
func TestGuardBlocksLoopbackInPractice(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewHTTPClient(2 * time.Second)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if _, err := c.Do(req); err == nil {
		t.Fatal("request to loopback succeeded; the SSRF guard is not wired into the dialer")
	}
}

func TestTestClientCanReachLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewHTTPClientWithOptions(2*time.Second, HTTPClientOptions{AllowPrivateAddresses: true})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("guard-disabled client could not reach loopback: %v", err)
	}
	resp.Body.Close()
}

func TestResponseBodyIsCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		chunk := make([]byte, 1<<20)
		for i := 0; i < 8; i++ { // 8 MiB, over the 5 MiB cap
			_, _ = w.Write(chunk)
		}
	}))
	defer srv.Close()

	c := NewHTTPClientWithOptions(20*time.Second, HTTPClientOptions{AllowPrivateAddresses: true})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	n, _ := io_Copy(resp.Body)
	if n > MaxResponseBytes {
		t.Errorf("read %d bytes; cap is %d", n, MaxResponseBytes)
	}
}

func io_Copy(r interface{ Read([]byte) (int, error) }) (int64, error) {
	buf := make([]byte, 32<<10)
	var total int64
	for {
		n, err := r.Read(buf)
		total += int64(n)
		if err != nil {
			return total, nil
		}
	}
}
