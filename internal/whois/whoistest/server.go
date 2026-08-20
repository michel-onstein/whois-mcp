// Package whoistest provides a fake port-43 listener.
//
// It exists because the failure modes are the interesting part of WHOIS, and
// none of them are reproducible against real registries: you cannot ask
// Verisign to truncate a response, and a test that tried would be both flaky
// and rude. Every mode here corresponds to something a real registry has been
// observed to do. See docs/IMPLEMENTATION_PLAN.md task 1.11.
//
// No test in this repository may reach the network, so this is the only WHOIS
// server the suite ever talks to.
package whoistest

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// Mode selects how the fake server misbehaves.
type Mode int

const (
	// ModeNormal writes the response and closes cleanly.
	ModeNormal Mode = iota
	// ModeSlow writes the response one chunk at a time with a delay between
	// chunks, exercising read deadlines mid-response.
	ModeSlow
	// ModeTruncated writes a prefix of the response and closes abruptly,
	// which is what a registry under load does.
	ModeTruncated
	// ModeMalformed writes bytes that are not a WHOIS record — an HTML error
	// page or binary noise. Registries behind a misconfigured proxy do this,
	// and it must never parse into a confident answer.
	ModeMalformed
	// ModeRateLimited writes a rate-limit notice instead of a record. The text
	// is deliberately one that contains no "not found" signature, because
	// treating a rate-limit as "domain is free" is this server's worst
	// possible failure.
	ModeRateLimited
	// ModeHang accepts the connection and never writes, exercising timeouts.
	ModeHang
	// ModeRefuse accepts and immediately closes without writing.
	ModeRefuse
	// ModeFlood writes far more than the response cap, to prove the reader
	// stops.
	ModeFlood
)

// HTML is a stand-in for the error page a misconfigured registry proxy serves.
const HTML = "<!DOCTYPE html>\n<html><head><title>503 Service Unavailable</title></head>\n" +
	"<body><h1>Service Unavailable</h1></body></html>\n"

// RateLimitNotice is representative of what several ccTLD registries return
// when a client exceeds their per-IP budget.
const RateLimitNotice = "%% Rate limit exceeded. Please try again later.\n" +
	"%% WHOIS LIMIT EXCEEDED - see http://www.example/limit\n"

// Server is a fake WHOIS server listening on loopback.
type Server struct {
	// Addr is the "host:port" to hand to a transport.
	Addr string

	ln      net.Listener
	handler func(query string) (string, Mode)
	tb      testing.TB

	mu      sync.Mutex
	queries []string
	conns   int
}

// New starts a fake server that answers every query with response, behaving
// per mode. It is closed automatically when the test ends.
func New(tb testing.TB, mode Mode, response string) *Server {
	tb.Helper()
	return NewHandler(tb, func(string) (string, Mode) { return response, mode })
}

// NewHandler starts a fake server whose reply and mode depend on the query.
// This is what referral-chain and quirks tests need: the second hop must be a
// different server, and a quirks test must assert the exact bytes sent.
func NewHandler(tb testing.TB, h func(query string) (string, Mode)) *Server {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("whoistest: listen: %v", err)
	}
	s := &Server{Addr: ln.Addr().String(), ln: ln, handler: h, tb: tb}
	go s.serve()
	tb.Cleanup(s.Close)
	return s
}

// Close stops the listener. Safe to call more than once.
func (s *Server) Close() {
	_ = s.ln.Close()
}

// Queries returns the exact query lines received, in order, with the CRLF
// stripped. Tests assert on this to prove a quirk prefix was actually sent.
func (s *Server) Queries() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.queries...)
}

// Conns returns how many connections were accepted, which is how a test proves
// a referral was or was not followed.
func (s *Server) Conns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns
}

func (s *Server) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return // listener closed
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()

	s.mu.Lock()
	s.conns++
	s.mu.Unlock()

	// Read the request line. A client that never sends one gets no reply.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := readLine(conn)
	if err != nil {
		return
	}
	query := strings.TrimRight(line, "\r\n")

	s.mu.Lock()
	s.queries = append(s.queries, query)
	s.mu.Unlock()

	body, mode := s.handler(query)
	_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))

	switch mode {
	case ModeNormal:
		_, _ = conn.Write([]byte(body))
	case ModeSlow:
		for i := 0; i < len(body); i += 8 {
			end := min(i+8, len(body))
			if _, err := conn.Write([]byte(body[i:end])); err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	case ModeTruncated:
		cut := len(body) / 2
		_, _ = conn.Write([]byte(body[:cut]))
	case ModeMalformed:
		_, _ = conn.Write([]byte(HTML))
	case ModeRateLimited:
		_, _ = conn.Write([]byte(RateLimitNotice))
	case ModeHang:
		// Hold the connection open, writing nothing, until the client gives up.
		buf := make([]byte, 1)
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		_, _ = conn.Read(buf)
	case ModeRefuse:
		// Close immediately: EOF with no bytes.
	case ModeFlood:
		chunk := strings.Repeat("x", 64<<10)
		for i := 0; i < 32; i++ { // 2 MiB, over the 1 MiB cap
			if _, err := conn.Write([]byte(chunk)); err != nil {
				return
			}
		}
	default:
		s.tb.Errorf("whoistest: unknown mode %d", mode)
	}
}

// readLine reads up to the first LF, bounded so a client that never sends one
// cannot make the fake server allocate without limit.
func readLine(conn net.Conn) (string, error) {
	var sb strings.Builder
	buf := make([]byte, 1)
	for sb.Len() < 512 {
		n, err := conn.Read(buf)
		if n > 0 {
			sb.WriteByte(buf[0])
			if buf[0] == '\n' {
				return sb.String(), nil
			}
		}
		if err != nil {
			if sb.Len() > 0 {
				return sb.String(), nil
			}
			return "", err
		}
	}
	return "", errors.New("whoistest: request line too long")
}

// Referral renders the referral line a registry uses to point at a registrar's
// WHOIS server, so chain tests do not hand-write the label.
func Referral(host string) string {
	return fmt.Sprintf("Registrar WHOIS Server: %s\n", host)
}
