// Package whois implements the port-43 fallback path: the protocol that covers
// the ccTLDs with no RDAP service, which is the whole reason this path exists.
// See docs/MCP_DESIGN.md §8.4-§8.6.
//
// The protocol itself is trivial — connect, send a line, read until the server
// closes — and everything difficult about it is the response: free text with no
// schema, per-registry quirks, and servers that stall, truncate, or rate-limit
// rather than answering. So the transport's job is narrow and defensive: get
// bytes off the wire under a deadline, cap them, and never interpret them.
// Interpretation happens in the parsers.
package whois

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/qjam/whois-mcp/internal/netguard"
	"github.com/qjam/whois-mcp/internal/ratelimit"
)

// MaxResponseBytes caps a single port-43 response. Real WHOIS records are a few
// kilobytes; the largest legitimate responses (registries that dump every
// nameserver of a large zone) stay well under this. Anything bigger is a
// misbehaving or hostile server, and unlike HTTP there is no Content-Length to
// check first — the only defence is to stop reading.
const MaxResponseBytes = 1 << 20

// DefaultPort is the WHOIS port. It is not configurable per host: a "WHOIS
// server" on another port is not a thing registries publish.
const DefaultPort = "43"

// DefaultTimeout is the per-host ceiling. Port 43 is materially slower than
// RDAP — several ccTLD registries take seconds to answer a cold query — so this
// is more generous than rdapx.DefaultTimeout.
const DefaultTimeout = 10 * time.Second

// dialTimeout bounds the TCP handshake alone, so a black-holed host fails fast
// instead of consuming the whole response budget.
const dialTimeout = 3 * time.Second

// ErrNoHost is returned when a query is attempted with no server to ask.
var ErrNoHost = errors.New("no WHOIS host")

// Response is one raw port-43 exchange. The bytes are verbatim: the design
// requires the raw text be retained regardless of parse outcome so that
// whois_raw can answer even when structured parsing fails.
type Response struct {
	// Host is the server actually asked, as "host:port".
	Host string
	// Query is the exact line sent, without its CRLF. Quirks mean this is
	// often not just the domain, so recording it is what makes a surprising
	// answer diagnosable.
	Query string
	// Raw is the response as received.
	Raw []byte
	// Truncated is true if the response hit MaxResponseBytes and was cut.
	// The parse is still attempted — a truncated record usually still contains
	// the fields we want, which appear early — but confidence is reduced.
	Truncated bool
	// Elapsed is how long the exchange took, for rate-limit diagnosis.
	Elapsed time.Duration
}

// TransportOptions tunes the transport.
type TransportOptions struct {
	// AllowPrivateAddresses disables the address guard.
	//
	// This exists solely so tests can reach a fake listener on loopback. It
	// must never be set on a production path: WHOIS hosts are discovered from
	// whois.iana.org, so they are third-party input, and the guard is what
	// stops a compromised or hostile referral from steering us at
	// cluster-internal services or a cloud metadata endpoint.
	AllowPrivateAddresses bool

	// MaxBytes overrides MaxResponseBytes. Zero means the default.
	MaxBytes int64
}

// Transport performs port-43 exchanges. It is safe for concurrent use and
// holds no per-query state; it deliberately knows nothing about referrals,
// quirks, or parsing, all of which compose above it.
type Transport struct {
	dialer   *net.Dialer
	timeout  time.Duration
	maxBytes int64
	// guard is the per-host rate limit and circuit breaker. Nil means no
	// policy, which suits a unit test; cmd/whois-mcp always supplies one.
	guard *ratelimit.Guard
}

// WithGuard attaches the upstream policy.
func (t *Transport) WithGuard(g *ratelimit.Guard) *Transport {
	t.guard = g
	return t
}

// NewTransport returns a Transport with the SSRF guard in place.
func NewTransport(timeout time.Duration) *Transport {
	return NewTransportWithOptions(timeout, TransportOptions{})
}

// NewTransportWithOptions is NewTransport with the guard and cap configurable.
func NewTransportWithOptions(timeout time.Duration, opt TransportOptions) *Transport {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	control := netguard.Control
	if opt.AllowPrivateAddresses {
		control = nil
	}
	maxBytes := opt.MaxBytes
	if maxBytes <= 0 {
		maxBytes = MaxResponseBytes
	}
	return &Transport{
		dialer:   &net.Dialer{Timeout: dialTimeout, Control: control},
		timeout:  timeout,
		maxBytes: maxBytes,
	}
}

// Query sends one line to a WHOIS host and reads the reply to EOF.
//
// An empty reply is not an error: several registries answer an unknown domain
// with nothing at all, and the availability logic treats that as "unknown"
// rather than "free". Only a failure to complete the exchange — refused
// connection, blocked address, deadline, reset — returns a non-nil error.
func (t *Transport) Query(ctx context.Context, host, query string) (*Response, error) {
	addr, err := normalizeHost(host)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()

	// Port 43 has no status codes and no Retry-After, so the guard sees only
	// "worked" or "did not". That is enough: a registry that stops answering is
	// exactly what the breaker is for, and several ccTLD registries enforce
	// aggressive per-IP limits by simply refusing connections.
	var resp *Response
	err = t.guard.Do(ctx, addr, func(ctx context.Context) ratelimit.Outcome {
		r, e := t.exchange(ctx, addr, query)
		resp = r
		return ratelimit.Outcome{Err: e}
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// exchange performs one port-43 conversation, without policy.
func (t *Transport) exchange(ctx context.Context, addr, query string) (*Response, error) {
	started := time.Now()
	conn, err := t.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dialing %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	// Close the connection when the context ends. A deadline covers the common
	// case, but a caller cancelling mid-read would otherwise wait for it.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stop:
		}
	}()

	if dl, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(dl); err != nil {
			return nil, fmt.Errorf("setting deadline on %s: %w", addr, err)
		}
	}

	if _, err := io.WriteString(conn, query+"\r\n"); err != nil {
		return nil, fmt.Errorf("sending query to %s: %w", addr, wrapCtx(ctx, err))
	}

	// Read one byte past the cap so hitting it is distinguishable from a
	// response that merely happens to be exactly MaxResponseBytes long.
	raw, err := io.ReadAll(io.LimitReader(conn, t.maxBytes+1))
	resp := &Response{Host: addr, Query: query, Raw: raw, Elapsed: time.Since(started)}
	if int64(len(raw)) > t.maxBytes {
		resp.Raw = raw[:t.maxBytes]
		resp.Truncated = true
		return resp, nil
	}
	if err != nil {
		// A read error after bytes arrived still yields a usable record more
		// often than not, so surface the partial response and let the caller
		// decide; with nothing at all, it is a failure.
		if len(raw) == 0 {
			return nil, fmt.Errorf("reading from %s: %w", addr, wrapCtx(ctx, err))
		}
		resp.Truncated = true
	}
	return resp, nil
}

// normalizeHost appends the default port when absent and rejects input that is
// not a plausible host. WHOIS hosts arrive from IANA and from referral lines in
// other registries' output, so they are untrusted strings, not trusted config.
func normalizeHost(host string) (string, error) {
	h := strings.TrimSpace(host)
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return "", ErrNoHost
	}
	if strings.ContainsAny(h, " \t\r\n/\\") {
		return "", fmt.Errorf("%w: %q is not a hostname", ErrNoHost, host)
	}
	// An explicit port is preserved; a bare IPv6 literal is bracketed.
	if _, _, err := net.SplitHostPort(h); err == nil {
		return h, nil
	}
	if strings.Count(h, ":") > 1 { // bare IPv6 literal
		return net.JoinHostPort(h, DefaultPort), nil
	}
	return net.JoinHostPort(h, DefaultPort), nil
}

// wrapCtx prefers the context's error, so a timeout reads as a timeout rather
// than as the "use of closed network connection" our own watchdog caused.
func wrapCtx(ctx context.Context, err error) error {
	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}
	return err
}
