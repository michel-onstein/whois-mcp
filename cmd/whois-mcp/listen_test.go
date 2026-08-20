package main

import (
	"flag"
	"io"
	"strings"
	"testing"
)

// envMap turns a map into a getenv function, so the precedence table can be
// exercised without mutating the process environment.
func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// parseFlags runs the real FlagSet, so the tests cover the flag wiring rather
// than a hand-built struct that could drift from it.
func parseFlags(t *testing.T, args ...string) *listenFlags {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	lf := registerListenFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parsing %v: %v", args, err)
	}
	return lf
}

func TestResolveListenPrecedence(t *testing.T) {
	cases := []struct {
		name string
		args []string
		env  map[string]string
		want string
	}{
		{
			name: "nothing set is loopback 8080",
			want: "127.0.0.1:8080",
		},
		{
			// The form the Dockerfile, compose and the Helm chart all use. It has
			// to keep working exactly as before.
			name: "WHOIS_MCP_LISTEN alone",
			env:  map[string]string{"WHOIS_MCP_LISTEN": "0.0.0.0:9000"},
			want: "0.0.0.0:9000",
		},
		{
			name: "bare :port in WHOIS_MCP_LISTEN means all interfaces",
			env:  map[string]string{"WHOIS_MCP_LISTEN": ":9000"},
			want: ":9000",
		},
		{
			name: "WHOIS_MCP_PORT alone keeps the default address",
			env:  map[string]string{"WHOIS_MCP_PORT": "9999"},
			want: "127.0.0.1:9999",
		},
		{
			name: "WHOIS_MCP_ADDRESS alone keeps the default port",
			env:  map[string]string{"WHOIS_MCP_ADDRESS": "10.0.0.5"},
			want: "10.0.0.5:8080",
		},
		{
			name: "part-wise environment overrides the combined form",
			env: map[string]string{
				"WHOIS_MCP_LISTEN": "10.0.0.1:8080",
				"WHOIS_MCP_PORT":   "9000",
			},
			want: "10.0.0.1:9000",
		},
		{
			name: "--port alone",
			args: []string{"--port", "9000"},
			want: "127.0.0.1:9000",
		},
		{
			name: "--address alone",
			args: []string{"--address", "192.0.2.10"},
			want: "192.0.2.10:8080",
		},
		{
			name: "--address and --port together",
			args: []string{"--address", "192.0.2.10", "--port", "9000"},
			want: "192.0.2.10:9000",
		},
		{
			name: "--listen alone",
			args: []string{"--listen", "192.0.2.10:9000"},
			want: "192.0.2.10:9000",
		},
		{
			// The reading that makes both flags useful together.
			name: "--port overrides --listen's port",
			args: []string{"--listen", "0.0.0.0:8080", "--port", "9000"},
			want: "0.0.0.0:9000",
		},
		{
			name: "--address overrides --listen's address",
			args: []string{"--listen", "0.0.0.0:8080", "--address", "127.0.0.1"},
			want: "127.0.0.1:8080",
		},
		{
			name: "flags beat the environment",
			args: []string{"--port", "7000"},
			env:  map[string]string{"WHOIS_MCP_LISTEN": "10.0.0.1:8080", "WHOIS_MCP_PORT": "9000"},
			want: "10.0.0.1:7000",
		},
		{
			name: "--listen beats every environment variable",
			args: []string{"--listen", "127.0.0.1:1234"},
			env: map[string]string{
				"WHOIS_MCP_LISTEN":  "10.0.0.1:8080",
				"WHOIS_MCP_ADDRESS": "10.0.0.2",
				"WHOIS_MCP_PORT":    "9000",
			},
			want: "127.0.0.1:1234",
		},
		{
			name: "single flag can override a whole environment listen",
			args: []string{"--address", "127.0.0.1"},
			env:  map[string]string{"WHOIS_MCP_LISTEN": "0.0.0.0:9000"},
			want: "127.0.0.1:9000",
		},
		{
			name: "ipv6 literal",
			args: []string{"--address", "::1", "--port", "9000"},
			want: "[::1]:9000",
		},
		{
			name: "whitespace is trimmed",
			env:  map[string]string{"WHOIS_MCP_PORT": "  9000  "},
			want: "127.0.0.1:9000",
		},
		{
			name: "a hostname is accepted as an address",
			args: []string{"--address", "localhost"},
			want: "localhost:8080",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lf := parseFlags(t, c.args...)
			got, err := resolveListen(lf, envMap(c.env))
			if err != nil {
				t.Fatalf("resolveListen: %v", err)
			}
			if got != c.want {
				t.Errorf("resolveListen = %q; want %q", got, c.want)
			}
		})
	}
}

func TestResolveListenRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		args []string
		env  map[string]string
		want string // substring of the error
	}{
		{
			name: "port out of range",
			args: []string{"--port", "70000"},
			want: "outside 1-65535",
		},
		{
			name: "negative port",
			args: []string{"--port", "-1"},
			want: "outside 1-65535",
		},
		{
			// Accepted by the kernel, but it leaves the served address unknowable
			// and WHOIS_MCP_PUBLIC_URL has to name a real port.
			name: "port zero",
			args: []string{"--port", "0"},
			want: "unknowable",
		},
		{
			name: "non-numeric port",
			args: []string{"--port", "http"},
			want: "not a port number",
		},
		{
			name: "non-numeric port in the environment",
			env:  map[string]string{"WHOIS_MCP_PORT": "http"},
			want: "WHOIS_MCP_PORT",
		},
		{
			name: "address with a port in it",
			args: []string{"--address", "127.0.0.1:8080"},
			want: "not an address",
		},
		{
			name: "address with a scheme",
			args: []string{"--address", "http://localhost"},
			want: "not an address",
		},
		{
			name: "listen without a port",
			args: []string{"--listen", "127.0.0.1"},
			want: "not host:port",
		},
		{
			// A common slip worth its own message rather than the library's.
			name: "listen given a bare port",
			args: []string{"--listen", "9000"},
			want: "is a port, not an address",
		},
		{
			name: "malformed environment listen",
			env:  map[string]string{"WHOIS_MCP_LISTEN": "not::valid::at::all"},
			want: "WHOIS_MCP_LISTEN",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lf := parseFlags(t, c.args...)
			got, err := resolveListen(lf, envMap(c.env))
			if err == nil {
				t.Fatalf("resolveListen accepted it and returned %q", got)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

// TestNewConfigPathsStillHitTheSecurityGate is the point of this whole feature
// being reviewable.
//
// Before, there was one way to choose an address, and checkExposure guarded it.
// There are now six. Every one of them must still be refused when it lands
// off-host without an enrollment token — a new way to configure something must
// not become a way around the gate.
func TestNewConfigPathsStillHitTheSecurityGate(t *testing.T) {
	offHost := []struct {
		name string
		args []string
		env  map[string]string
	}{
		{name: "--address 0.0.0.0", args: []string{"--address", "0.0.0.0"}},
		{name: "--address a routable IP", args: []string{"--address", "10.1.2.3"}},
		{name: "--listen all interfaces", args: []string{"--listen", "0.0.0.0:8080"}},
		{name: "--listen bare port", args: []string{"--listen", ":8080"}},
		{name: "WHOIS_MCP_ADDRESS", env: map[string]string{"WHOIS_MCP_ADDRESS": "0.0.0.0"}},
		{name: "WHOIS_MCP_LISTEN", env: map[string]string{"WHOIS_MCP_LISTEN": "0.0.0.0:8080"}},
		{name: "ipv6 all interfaces", args: []string{"--address", "::"}},
		{
			name: "loopback in the environment overridden off-host by a flag",
			args: []string{"--address", "10.1.2.3"},
			env:  map[string]string{"WHOIS_MCP_LISTEN": "127.0.0.1:8080"},
		},
	}

	for _, c := range offHost {
		t.Run(c.name, func(t *testing.T) {
			lf := parseFlags(t, c.args...)
			listen, err := resolveListen(lf, envMap(c.env))
			if err != nil {
				t.Fatalf("resolveListen: %v", err)
			}
			// No enrollment token: this must be refused.
			if err := checkExposure(config{listen: listen}, authConfig{}); err == nil {
				t.Errorf("checkExposure accepted %q with no authentication configured", listen)
			}
			// With authentication it is allowed, which is what makes the refusal
			// above about exposure rather than about the address form.
			ok := authConfig{enrollmentToken: "secret", publicURL: "https://whois.example"}
			if err := checkExposure(config{listen: listen}, ok); err != nil {
				t.Errorf("checkExposure refused %q even with authentication configured: %v", listen, err)
			}
		})
	}
}

// TestLoopbackPathsAreStillAllowedUnauthenticated is the control: without it,
// a gate that refused everything would pass the test above.
func TestLoopbackPathsAreStillAllowedUnauthenticated(t *testing.T) {
	loopback := []struct {
		name string
		args []string
		env  map[string]string
	}{
		{name: "default"},
		{name: "--port only", args: []string{"--port", "9000"}},
		{name: "--address 127.0.0.1", args: []string{"--address", "127.0.0.1"}},
		{name: "--address localhost", args: []string{"--address", "localhost"}},
		{name: "--address ::1", args: []string{"--address", "::1"}},
		{name: "WHOIS_MCP_PORT only", env: map[string]string{"WHOIS_MCP_PORT": "9000"}},
		{
			name: "off-host environment pulled back to loopback by a flag",
			args: []string{"--address", "127.0.0.1"},
			env:  map[string]string{"WHOIS_MCP_LISTEN": "0.0.0.0:8080"},
		},
	}

	for _, c := range loopback {
		t.Run(c.name, func(t *testing.T) {
			lf := parseFlags(t, c.args...)
			listen, err := resolveListen(lf, envMap(c.env))
			if err != nil {
				t.Fatalf("resolveListen: %v", err)
			}
			if err := checkExposure(config{listen: listen}, authConfig{}); err != nil {
				t.Errorf("checkExposure refused loopback %q: %v", listen, err)
			}
		})
	}
}

func TestValidatePortCanonicalises(t *testing.T) {
	got, err := validatePort(" 08080 ")
	if err != nil {
		t.Fatalf("validatePort: %v", err)
	}
	if got != "8080" {
		t.Errorf("validatePort(\" 08080 \") = %q; want %q", got, "8080")
	}
}

func TestListenUsageMentionsThePrecedenceAndTheGate(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	registerListenFlags(fs)
	var b strings.Builder
	listenUsage(&b, fs)
	out := b.String()

	for _, want := range []string{
		"--address", "--port", "--listen",
		"WHOIS_MCP_ADDRESS", "WHOIS_MCP_PORT", "WHOIS_MCP_LISTEN",
		"127.0.0.1:8080",
		// The one thing someone must not discover by trial and error.
		"WHOIS_MCP_ENROLLMENT_TOKEN",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("usage does not mention %q:\n%s", want, out)
		}
	}
}
