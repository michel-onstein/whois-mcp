package whois

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/qjam/whois-mcp/internal/netguard"
	"github.com/qjam/whois-mcp/internal/whois/whoistest"
)

// testTransport is the only transport the suite uses: the SSRF guard would
// otherwise refuse the loopback fake server, which is exactly what it is for.
func testTransport(t *testing.T, timeout time.Duration) *Transport {
	t.Helper()
	return NewTransportWithOptions(timeout, TransportOptions{AllowPrivateAddresses: true})
}

func TestQueryNormalResponse(t *testing.T) {
	const body = "Domain Name: example.org\nCreation Date: 2001-01-01T00:00:00Z\n"
	srv := whoistest.New(t, whoistest.ModeNormal, body)

	resp, err := testTransport(t, 5*time.Second).Query(context.Background(), srv.Addr, "example.org")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if string(resp.Raw) != body {
		t.Errorf("Raw = %q; want %q", resp.Raw, body)
	}
	if resp.Truncated {
		t.Error("Truncated = true for a complete response")
	}
	if resp.Host != srv.Addr {
		t.Errorf("Host = %q; want %q", resp.Host, srv.Addr)
	}
	if resp.Query != "example.org" {
		t.Errorf("Query = %q; want %q", resp.Query, "example.org")
	}
}

// TestQuerySendsCRLFTerminatedLine pins the wire format. Several registries
// ignore a bare LF and hang, which presents as a timeout rather than as a
// protocol error, so this is worth asserting directly.
func TestQuerySendsCRLFTerminatedLine(t *testing.T) {
	srv := whoistest.New(t, whoistest.ModeNormal, "ok\n")
	if _, err := testTransport(t, 5*time.Second).Query(context.Background(), srv.Addr, "example.org"); err != nil {
		t.Fatalf("Query: %v", err)
	}
	got := srv.Queries()
	if len(got) != 1 || got[0] != "example.org" {
		t.Fatalf("server received %q; want exactly [\"example.org\"]", got)
	}
}

// TestQueryPassesQueryVerbatim is what makes the quirks table possible: the
// transport must not rewrite the line it is given.
func TestQueryPassesQueryVerbatim(t *testing.T) {
	srv := whoistest.New(t, whoistest.ModeNormal, "ok\n")
	const q = "-T dn,ace example.de"
	if _, err := testTransport(t, 5*time.Second).Query(context.Background(), srv.Addr, q); err != nil {
		t.Fatalf("Query: %v", err)
	}
	if got := srv.Queries(); len(got) != 1 || got[0] != q {
		t.Errorf("server received %q; want %q", got, q)
	}
}

func TestQueryEmptyResponseIsNotAnError(t *testing.T) {
	srv := whoistest.New(t, whoistest.ModeRefuse, "")

	resp, err := testTransport(t, 5*time.Second).Query(context.Background(), srv.Addr, "example.org")
	if err != nil {
		t.Fatalf("an empty reply must not be an error, got: %v", err)
	}
	if len(resp.Raw) != 0 {
		t.Errorf("Raw = %q; want empty", resp.Raw)
	}
}

func TestQueryTruncatedResponseIsReturned(t *testing.T) {
	const body = "Domain Name: example.org\nRegistrar: Someone\n"
	srv := whoistest.New(t, whoistest.ModeTruncated, body)

	resp, err := testTransport(t, 5*time.Second).Query(context.Background(), srv.Addr, "example.org")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(resp.Raw) == 0 || len(resp.Raw) >= len(body) {
		t.Errorf("Raw length = %d; want a nonempty prefix of %d", len(resp.Raw), len(body))
	}
}

func TestQueryMalformedResponseIsReturnedVerbatim(t *testing.T) {
	srv := whoistest.New(t, whoistest.ModeMalformed, "")

	resp, err := testTransport(t, 5*time.Second).Query(context.Background(), srv.Addr, "example.org")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if !strings.Contains(string(resp.Raw), "503 Service Unavailable") {
		t.Errorf("Raw = %q; want the HTML error page verbatim", resp.Raw)
	}
}

func TestQueryRateLimitedResponseIsReturnedVerbatim(t *testing.T) {
	srv := whoistest.New(t, whoistest.ModeRateLimited, "")

	resp, err := testTransport(t, 5*time.Second).Query(context.Background(), srv.Addr, "example.org")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if !strings.Contains(string(resp.Raw), "Rate limit exceeded") {
		t.Errorf("Raw = %q; want the rate-limit notice", resp.Raw)
	}
}

// TestQueryCapsResponse proves the reader stops: without a cap, a server that
// streams indefinitely exhausts our memory, and port 43 has no Content-Length
// to check first.
func TestQueryCapsResponse(t *testing.T) {
	srv := whoistest.New(t, whoistest.ModeFlood, "")

	tr := NewTransportWithOptions(20*time.Second, TransportOptions{
		AllowPrivateAddresses: true,
		MaxBytes:              4 << 10,
	})
	resp, err := tr.Query(context.Background(), srv.Addr, "example.org")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if int64(len(resp.Raw)) != 4<<10 {
		t.Errorf("Raw length = %d; want exactly the 4096-byte cap", len(resp.Raw))
	}
	if !resp.Truncated {
		t.Error("Truncated = false after hitting the cap")
	}
}

func TestQueryTimesOutOnHangingServer(t *testing.T) {
	srv := whoistest.New(t, whoistest.ModeHang, "")

	start := time.Now()
	_, err := testTransport(t, 300*time.Millisecond).Query(context.Background(), srv.Addr, "example.org")
	if err == nil {
		t.Fatal("Query succeeded against a server that never replies")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("took %v; the timeout was not honoured", elapsed)
	}
}

func TestQueryHonoursCancelledContext(t *testing.T) {
	srv := whoistest.New(t, whoistest.ModeHang, "")

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	_, err := testTransport(t, 30*time.Second).Query(ctx, srv.Addr, "example.org")
	if err == nil {
		t.Fatal("Query ignored a cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v; want context.Canceled", err)
	}
}

// TestQuerySlowServerSucceedsWithinDeadline guards against a deadline applied
// per-read rather than per-exchange, which would kill a merely slow server.
func TestQuerySlowServerSucceedsWithinDeadline(t *testing.T) {
	const body = "Domain Name: slow.example\nRegistrar: Someone\n"
	srv := whoistest.New(t, whoistest.ModeSlow, body)

	resp, err := testTransport(t, 20*time.Second).Query(context.Background(), srv.Addr, "slow.example")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if string(resp.Raw) != body {
		t.Errorf("Raw = %q; want the whole body %q", resp.Raw, body)
	}
}

// TestGuardBlocksLoopbackInPractice proves the SSRF guard is wired into the
// dialer and not merely defined. WHOIS hosts come from whois.iana.org, so this
// is the check that stops a hostile referral reaching our own network.
func TestGuardBlocksLoopbackInPractice(t *testing.T) {
	srv := whoistest.New(t, whoistest.ModeNormal, "ok\n")

	_, err := NewTransport(2*time.Second).Query(context.Background(), srv.Addr, "example.org")
	if err == nil {
		t.Fatal("query to loopback succeeded; the SSRF guard is not wired into the dialer")
	}
	var blocked *netguard.ErrBlockedAddress
	if !errors.As(err, &blocked) {
		t.Errorf("error = %v; want *netguard.ErrBlockedAddress", err)
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{in: "whois.nic.uk", want: "whois.nic.uk:43"},
		{in: " whois.nic.uk ", want: "whois.nic.uk:43"},
		{in: "whois.nic.uk.", want: "whois.nic.uk:43"},
		{in: "whois.example:4343", want: "whois.example:4343"},
		{in: "127.0.0.1:1234", want: "127.0.0.1:1234"},
		{in: "2001:db8::1", want: "[2001:db8::1]:43"},
		{in: "", wantErr: true},
		{in: "   ", wantErr: true},
		{in: "whois.example/path", wantErr: true},
		{in: "whois example", wantErr: true},
		{in: "whois.example\nRegistrar: x", wantErr: true},
	}
	for _, c := range cases {
		got, err := normalizeHost(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("normalizeHost(%q) = %q; want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("normalizeHost(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("normalizeHost(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

func TestQueryRejectsEmptyHost(t *testing.T) {
	_, err := testTransport(t, time.Second).Query(context.Background(), "", "example.org")
	if !errors.Is(err, ErrNoHost) {
		t.Errorf("error = %v; want ErrNoHost", err)
	}
}

func TestQueryReportsDialFailure(t *testing.T) {
	// Bind and immediately release a port to get one nothing is listening on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	if _, err := testTransport(t, 2*time.Second).Query(context.Background(), addr, "example.org"); err == nil {
		t.Fatal("Query succeeded against a closed port")
	}
}
