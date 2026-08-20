// Package netguard decides which addresses this server may connect to.
//
// Both upstream protocols take their endpoints from third parties: RDAP base
// URLs and referral links come from the IANA bootstrap registry and from
// registry responses, and WHOIS hosts come from whois.iana.org. All of it is
// untrusted input, so without this check a registry could steer us at
// cluster-internal services or a cloud metadata endpoint.
//
// It lives in its own package because the RDAP and WHOIS transports must apply
// exactly the same rule. Two copies of an SSRF guard is one copy that rots.
package netguard

import (
	"fmt"
	"net"
	"syscall"
)

// ErrBlockedAddress is returned when a connection to a non-public address is
// attempted.
type ErrBlockedAddress struct {
	IP     net.IP
	Reason string
}

func (e *ErrBlockedAddress) Error() string {
	return fmt.Sprintf("blocked connection to %s: %s", e.IP, e.Reason)
}

// BlockReason reports why an IP is not a permissible upstream, or "" if it is.
//
// Callers apply this to the *resolved* address inside a dialer's Control hook,
// not to the hostname, which is what makes it robust against DNS rebinding:
// the name may resolve to a public address at check time and a private one at
// connect time, so only the address actually being dialled can be trusted.
func BlockReason(ip net.IP) string {
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

// Control is a net.Dialer Control hook that enforces BlockReason.
func Control(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("parsing dial address %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if reason := BlockReason(ip); reason != "" {
		return &ErrBlockedAddress{IP: ip, Reason: reason}
	}
	return nil
}
