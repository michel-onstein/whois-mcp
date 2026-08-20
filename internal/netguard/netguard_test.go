package netguard

import (
	"net"
	"testing"
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
		if r := BlockReason(net.ParseIP(s)); r == "" {
			t.Errorf("BlockReason(%s) = allowed; want blocked", s)
		}
	}

	allowed := []string{"1.1.1.1", "8.8.8.8", "199.7.83.42", "2606:4700::1111"}
	for _, s := range allowed {
		if r := BlockReason(net.ParseIP(s)); r != "" {
			t.Errorf("BlockReason(%s) = %q; want allowed", s, r)
		}
	}

	if BlockReason(nil) == "" {
		t.Error("nil IP must be blocked")
	}
}

func TestControlRejectsLoopbackAddress(t *testing.T) {
	if err := Control("tcp", "127.0.0.1:43", nil); err == nil {
		t.Fatal("Control allowed a loopback address")
	}
	var blocked *ErrBlockedAddress
	if err := Control("tcp", "10.1.2.3:43", nil); err == nil {
		t.Fatal("Control allowed a private address")
	} else if !asBlocked(err, &blocked) {
		t.Errorf("error %v is not *ErrBlockedAddress", err)
	}
	if err := Control("tcp", "1.1.1.1:43", nil); err != nil {
		t.Errorf("Control blocked a public address: %v", err)
	}
}

// TestControlRejectsMalformedAddress guards the parse path: a Control hook that
// returns nil on input it could not understand would fail open.
func TestControlRejectsMalformedAddress(t *testing.T) {
	for _, addr := range []string{"", "not-an-address", "1.1.1.1", "[::1"} {
		if err := Control("tcp", addr, nil); err == nil {
			t.Errorf("Control(%q) = nil; want error", addr)
		}
	}
}

func asBlocked(err error, target **ErrBlockedAddress) bool {
	e, ok := err.(*ErrBlockedAddress)
	if ok {
		*target = e
	}
	return ok
}
