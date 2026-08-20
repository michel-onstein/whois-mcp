package rdapx

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/qjam/whois-mcp/internal/netguard"
)

// MaxResponseBytes caps any single upstream response body. RDAP responses are
// small; anything larger is a misbehaving or hostile server.
const MaxResponseBytes = 5 << 20

// maxRedirects bounds redirect chains. Referral URLs come from third parties,
// so an unbounded chain is an amplification and SSRF vector.
const maxRedirects = 2

// limitTransport caps response bodies. A hostile upstream cannot exhaust our
// memory by streaming indefinitely.
type limitTransport struct{ base http.RoundTripper }

func (t *limitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.LimitReader(resp.Body, MaxResponseBytes), resp.Body}
	return resp, nil
}

// HTTPClientOptions tunes the guarded client.
type HTTPClientOptions struct {
	// AllowPrivateAddresses disables the address guard.
	//
	// This exists solely so tests can reach an httptest server on loopback.
	// It must never be set on a production path: the guard is what stops a
	// third-party registry from steering us at cluster-internal services or a
	// cloud metadata endpoint.
	AllowPrivateAddresses bool
}

// NewHTTPClient returns an HTTP client safe for querying third-party RDAP
// endpoints: HTTPS only, no connections to non-public addresses, bounded
// redirects, bounded response size, and a hard per-request timeout.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return NewHTTPClientWithOptions(timeout, HTTPClientOptions{})
}

// NewHTTPClientWithOptions is NewHTTPClient with the guard configurable.
func NewHTTPClientWithOptions(timeout time.Duration, opt HTTPClientOptions) *http.Client {
	control := netguard.Control
	if opt.AllowPrivateAddresses {
		control = nil
	}
	dialer := &net.Dialer{
		Timeout:   2 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   control,
	}
	base := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return &http.Client{
		Transport: &limitTransport{base: base},
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			if req.URL.Scheme != "https" && !opt.AllowPrivateAddresses {
				return fmt.Errorf("refusing redirect to non-https URL %q", req.URL.Redacted())
			}
			return nil
		},
	}
}
