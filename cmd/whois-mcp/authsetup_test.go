package main

import (
	"strings"
	"testing"
)

// TestCheckExposure is the security gate of plan §7 as a table. Each row is a
// deployment someone will eventually attempt.
func TestCheckExposure(t *testing.T) {
	cases := []struct {
		name    string
		listen  string
		auth    authConfig
		wantErr string // substring; empty means the config must be accepted
	}{
		{
			name:   "loopback, no auth: the M0/M1 development shape",
			listen: "127.0.0.1:8080",
		},
		{
			name:    "off-host with no enrollment token is an open proxy",
			listen:  "0.0.0.0:8080",
			wantErr: "open proxy",
		},
		{
			name:    "off-host on a specific interface is equally exposed",
			listen:  "10.1.2.3:8080",
			wantErr: "open proxy",
		},
		{
			name:   "off-host with auth and a public URL is fine",
			listen: "0.0.0.0:8080",
			auth:   authConfig{enrollmentToken: "secret", publicURL: "https://whois.example"},
		},
		{
			name:    "off-host with auth but no public URL rejects every token",
			listen:  "0.0.0.0:8080",
			auth:    authConfig{enrollmentToken: "secret"},
			wantErr: "WHOIS_MCP_PUBLIC_URL",
		},
		{
			name:   "dev static bearer on loopback is the point of it",
			listen: "127.0.0.1:8080",
			auth:   authConfig{enrollmentToken: "secret", devStaticBearer: true},
		},
		{
			name:    "dev static bearer off-host turns the secret into a request credential",
			listen:  "0.0.0.0:8080",
			auth:    authConfig{enrollmentToken: "secret", publicURL: "https://whois.example", devStaticBearer: true},
			wantErr: "DEV_STATIC_BEARER",
		},
		{
			name:   "localhost counts as loopback",
			listen: "localhost:8080",
		},
		{
			name:   "ipv6 loopback counts as loopback",
			listen: "[::1]:8080",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkExposure(config{listen: c.listen}, c.auth)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("checkExposure rejected a valid config: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("checkExposure accepted %s with %+v", c.listen, c.auth)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("error %q does not mention %q", err, c.wantErr)
			}
		})
	}
}

func TestRequireHTTPSOffLoopback(t *testing.T) {
	ok := []string{
		"https://whois.example",
		"https://whois.example:8443",
		"http://127.0.0.1:8080",
		"http://localhost:8080",
		"http://[::1]:8080",
	}
	for _, u := range ok {
		if err := requireHTTPSOffLoopback(u); err != nil {
			t.Errorf("requireHTTPSOffLoopback(%q) = %v; want ok", u, err)
		}
	}
	// The enrollment token is submitted to this URL, so cleartext off-host is
	// not a warning-level problem.
	bad := []string{"http://whois.example", "http://10.1.2.3:8080", "ftp://whois.example", ""}
	for _, u := range bad {
		if err := requireHTTPSOffLoopback(u); err == nil {
			t.Errorf("requireHTTPSOffLoopback(%q) accepted cleartext off-loopback", u)
		}
	}
}

func TestRequireLoopback(t *testing.T) {
	ok := []string{"127.0.0.1:8080", "localhost:8080", "[::1]:8080", "127.15.2.9:1"}
	for _, a := range ok {
		if err := requireLoopback(a); err != nil {
			t.Errorf("requireLoopback(%q) = %v; want ok", a, err)
		}
	}
	bad := []string{":8080", "0.0.0.0:8080", "10.1.2.3:8080", "[::]:8080", "not-an-address"}
	for _, a := range bad {
		if err := requireLoopback(a); err == nil {
			t.Errorf("requireLoopback(%q) accepted a non-loopback address", a)
		}
	}
}

// TestLoadAuthConfigDefaults pins that auth is off unless explicitly turned on,
// and that the dev hatch needs the exact string "true" rather than any truthy
// value — a hatch enabled by a stray "0" would be a bad surprise.
func TestLoadAuthConfigDefaults(t *testing.T) {
	t.Setenv("WHOIS_MCP_ENROLLMENT_TOKEN", "")
	t.Setenv("WHOIS_MCP_SIGNING_KEY", "")
	t.Setenv("WHOIS_MCP_PUBLIC_URL", "")
	t.Setenv("WHOIS_MCP_DEV_STATIC_BEARER", "")

	got := loadAuthConfig()
	if got.enrollmentToken != "" || got.signingKey != "" || got.publicURL != "" || got.devStaticBearer {
		t.Errorf("defaults are not off: %+v", got)
	}

	for _, v := range []string{"0", "false", "yes", "TRUE", "1"} {
		t.Setenv("WHOIS_MCP_DEV_STATIC_BEARER", v)
		if loadAuthConfig().devStaticBearer {
			t.Errorf("WHOIS_MCP_DEV_STATIC_BEARER=%q enabled the hatch; only \"true\" should", v)
		}
	}
	t.Setenv("WHOIS_MCP_DEV_STATIC_BEARER", "true")
	if !loadAuthConfig().devStaticBearer {
		t.Error(`WHOIS_MCP_DEV_STATIC_BEARER="true" did not enable the hatch`)
	}
}

func TestLoadAuthConfigTrimsAndNormalizes(t *testing.T) {
	t.Setenv("WHOIS_MCP_ENROLLMENT_TOKEN", "  secret  ")
	t.Setenv("WHOIS_MCP_PUBLIC_URL", "https://whois.example/")
	got := loadAuthConfig()
	if got.enrollmentToken != "secret" {
		t.Errorf("enrollmentToken = %q; want it trimmed", got.enrollmentToken)
	}
	// A trailing slash would produce an audience of ".../mcp" appended to
	// ".../" — two slashes, and a token nobody can verify.
	if got.publicURL != "https://whois.example" {
		t.Errorf("publicURL = %q; want the trailing slash removed", got.publicURL)
	}
}
