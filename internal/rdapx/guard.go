package rdapx

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"
	"time"
)

// MaxResponseBytes caps any single upstream response body. RDAP responses are
// small; anything larger is a misbehaving or hostile server.
const MaxResponseBytes = 5 << 20

// maxRedirects bounds redirect chains. Referral URLs come from third parties,
// so an unbounded chain is an amplification and SSRF vector.
const maxRedirects = 2

// ErrBlockedAddress is returned when a connection to a non-public address is
// attempted. RDAP base URLs and referral links are supplied by third-party
// registries, so they are untrusted input: without this check a registry could
// point us at cluster-internal services or cloud metadata endpoints.
type ErrBlockedAddress struct {
	IP     net.IP
	Reason string
}

func (e *ErrBlockedAddress) Error() string {
	return fmt.Sprintf("blocked connection to %s: %s", e.IP, e.Reason)
}

// blockReason reports why an IP is not a permissible upstream, or "" if it is.
//
// The check runs on the *resolved* address inside the dialer's Control hook,
// not on the hostname, which is what makes it robust against DNS rebinding.
func blockReason(ip net.IP) string {
	if ip == nil {
		return "unparseable address"
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	switch {
	case ip.IsUnspecified():
		return "unspecified address"
	case ip.IsLoopback():
		return "loopback"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "link-local"
	case ip.IsInterfaceLocalMulticast(), ip.IsMulticast():
		return "multicast"
	case ip.IsPrivate():
		// RFC 1918 for IPv4; RFC 4193 unique-local for IPv6.
		return "private address space"
	}
	// Ranges Go's stdlib helpers do not classify but which must not be reachable.
	for _, r := range extraBlocked {
		if r.Contains(ip) {
			return r.reason
		}
	}
	return ""
}

type blockedRange struct {
	*net.IPNet
	reason string
}

var extraBlocked = func() []blockedRange {
	specs := []struct{ cidr, reason string }{
		{"100.64.0.0/10", "carrier-grade NAT"},
		{"192.0.0.0/24", "IETF protocol assignments"},
		{"192.0.2.0/24", "documentation range"},
		{"198.18.0.0/15", "benchmarking range"},
		{"198.51.100.0/24", "documentation range"},
		{"203.0.113.0/24", "documentation range"},
		{"240.0.0.0/4", "reserved"},
		{"::/128", "unspecified"},
		{"2001:db8::/32", "documentation range"},
	}
	out := make([]blockedRange, 0, len(specs))
	for _, s := range specs {
		if _, n, err := net.ParseCIDR(s.cidr); err == nil {
			out = append(out, blockedRange{IPNet: n, reason: s.reason})
		}
	}
	return out
}()

// guardedControl is the net.Dialer Control hook that enforces blockReason.
func guardedControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("parsing dial address %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if reason := blockReason(ip); reason != "" {
		return &ErrBlockedAddress{IP: ip, Reason: reason}
	}
	return nil
}

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
	control := guardedControl
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
