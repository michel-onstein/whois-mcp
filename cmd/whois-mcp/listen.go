package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// Defaults for the listener. Loopback, because an unauthenticated instance
// reachable off-host is an open proxy onto the registries (design §7) — so the
// safe address is the one you get by not choosing.
const (
	DefaultAddress = "127.0.0.1"
	DefaultPort    = 8080
)

// listenFlags holds the command-line values for the listener.
//
// Every field is a pointer-ish sentinel rather than a plain value, because
// "unset" and "set to the default" have to be distinguishable: an explicit
// `--port 8080` must override WHOIS_MCP_PORT, while an absent flag must not.
type listenFlags struct {
	listen  string
	address string
	port    string
}

// registerListenFlags declares the listener flags on a FlagSet.
//
// The flags mirror the environment variables one-for-one. Both exist because
// they suit different deployments: a container sets environment, and a person
// running the binary by hand reaches for a flag.
func registerListenFlags(fs *flag.FlagSet) *listenFlags {
	lf := &listenFlags{}
	fs.StringVar(&lf.listen, "listen", "",
		"address and port to serve on, as host:port (overrides --address and --port)")
	fs.StringVar(&lf.address, "address", "",
		"address to bind to; empty binds all interfaces, which requires authentication")
	fs.StringVar(&lf.port, "port", "",
		"port to serve on")
	return lf
}

// resolveListen works out the final listen address.
//
// Precedence, and the reason for it:
//
//  1. flags beat environment — a flag is the more immediate, more deliberate
//     statement, and it is what someone debugging a container override reaches
//     for.
//  2. within each tier, a specific part beats the combined form — --port 9000
//     next to --listen 0.0.0.0:8080 means "that address, but this port", which
//     is the only reading that makes both flags useful together.
//  3. the default is loopback:8080.
//
// getenv is injected so the precedence table can be tested without touching the
// process environment.
func resolveListen(lf *listenFlags, getenv func(string) string) (string, error) {
	host, port := DefaultAddress, strconv.Itoa(DefaultPort)

	// Tier 1: the combined environment variable, which predates the rest and is
	// what the Dockerfile, the compose stack and the Helm chart all set.
	if v := strings.TrimSpace(getenv("WHOIS_MCP_LISTEN")); v != "" {
		h, p, err := splitListen(v)
		if err != nil {
			return "", fmt.Errorf("WHOIS_MCP_LISTEN: %w", err)
		}
		host, port = h, p
	}
	// Tier 2: the part-wise environment variables.
	if v := strings.TrimSpace(getenv("WHOIS_MCP_ADDRESS")); v != "" {
		if err := validateAddress(v); err != nil {
			return "", fmt.Errorf("WHOIS_MCP_ADDRESS: %w", err)
		}
		host = v
	}
	if v := strings.TrimSpace(getenv("WHOIS_MCP_PORT")); v != "" {
		p, err := validatePort(v)
		if err != nil {
			return "", fmt.Errorf("WHOIS_MCP_PORT: %w", err)
		}
		port = p
	}
	// Tier 3: the combined flag.
	if lf != nil && strings.TrimSpace(lf.listen) != "" {
		h, p, err := splitListen(strings.TrimSpace(lf.listen))
		if err != nil {
			return "", fmt.Errorf("--listen: %w", err)
		}
		host, port = h, p
	}
	// Tier 4: the part-wise flags, the most specific statement available.
	if lf != nil && strings.TrimSpace(lf.address) != "" {
		v := strings.TrimSpace(lf.address)
		if err := validateAddress(v); err != nil {
			return "", fmt.Errorf("--address: %w", err)
		}
		host = v
	}
	if lf != nil && strings.TrimSpace(lf.port) != "" {
		p, err := validatePort(strings.TrimSpace(lf.port))
		if err != nil {
			return "", fmt.Errorf("--port: %w", err)
		}
		port = p
	}

	return net.JoinHostPort(host, port), nil
}

// AllInterfaces is the sentinel meaning "bind every interface".
//
// An empty address and 0.0.0.0 mean the same thing to the kernel, and both are
// spelled out here so the security gate can recognise either. It refuses both
// without authentication configured.
const AllInterfaces = "0.0.0.0"

// splitListen parses a host:port pair, tolerating the bare ":8080" form that
// means "all interfaces".
func splitListen(v string) (host, port string, err error) {
	h, p, err := net.SplitHostPort(v)
	if err != nil {
		// A bare port with no colon is a common slip; name it rather than
		// echoing the library's message about a missing port.
		if _, perr := strconv.Atoi(v); perr == nil {
			return "", "", fmt.Errorf("%q is a port, not an address; use --port, or write it as :%s", v, v)
		}
		return "", "", fmt.Errorf("%q is not host:port: %w", v, err)
	}
	if h != "" {
		if verr := validateAddress(h); verr != nil {
			return "", "", verr
		}
	}
	p, err = validatePort(p)
	if err != nil {
		return "", "", err
	}
	return h, p, nil
}

// validateAddress accepts an IP literal, a hostname, or the empty string.
//
// An unresolvable hostname is not rejected here: the failure belongs to
// net.Listen, which reports it far better than a pre-flight lookup would, and a
// DNS check at startup would make the server's own start depend on a resolver.
func validateAddress(v string) error {
	if v == "" || v == AllInterfaces || v == "::" {
		return nil
	}
	if ip := net.ParseIP(v); ip != nil {
		return nil
	}
	// Hostnames only: anything with a scheme, port, path or space is a
	// misunderstanding of the field rather than an exotic address.
	if strings.ContainsAny(v, "/:@ \t") {
		return fmt.Errorf("%q is not an address; give an IP or a hostname, with the port in --port", v)
	}
	if strings.HasPrefix(v, "-") {
		return fmt.Errorf("%q looks like a flag, not an address", v)
	}
	return nil
}

// validatePort accepts 1-65535 and returns it canonicalised.
//
// Port 0 is refused even though the kernel accepts it as "any free port". It
// would work, but the resulting port is unknowable to the operator, and
// WHOIS_MCP_PUBLIC_URL — the OAuth audience — has to name the port clients
// actually reach. A server nobody can address is not a useful server.
func validatePort(v string) (string, error) {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return "", fmt.Errorf("%q is not a port number", v)
	}
	if n == 0 {
		return "", errors.New("port 0 asks the kernel for any free port, which leaves the served address unknowable; choose one")
	}
	if n < 1 || n > 65535 {
		return "", fmt.Errorf("port %d is outside 1-65535", n)
	}
	return strconv.Itoa(n), nil
}

// listenUsage is the flag usage text, kept here so it stays next to the
// precedence rules it describes.
func listenUsage(w io.Writer, fs *flag.FlagSet) {
	_, _ = fmt.Fprintf(w, `whois-mcp — domain registration lookups over the Model Context Protocol.

Usage:
  whois-mcp [flags]

Flags:
`)
	fs.SetOutput(w)
	fs.PrintDefaults()
	_, _ = fmt.Fprintf(w, `
Listener configuration, highest precedence last:

  default                       %s:%d
  WHOIS_MCP_LISTEN              host:port
  WHOIS_MCP_ADDRESS             address only
  WHOIS_MCP_PORT                port only
  --listen host:port
  --address, --port

A specific part overrides the combined form in the same tier, so
--listen 0.0.0.0:8080 --port 9000 serves on 0.0.0.0:9000.

Binding anything but loopback requires WHOIS_MCP_ENROLLMENT_TOKEN: an
unauthenticated instance reachable off-host is an open proxy that queries
registries from your egress IP, and the resulting block reads as a total
outage for the affected TLD.

Everything else is configured by environment variable; see README.md and
docs/MCP_DESIGN.md §10.
`, DefaultAddress, DefaultPort)
}
