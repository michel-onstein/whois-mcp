package whois

import (
	"strings"
	"testing"
)

// TestQuirkKeysAreRealTLDShapes catches the mistake of adding a descriptive key
// that can never match.
//
// QueryFor looks a quirk up by a TLD's last label, so a key like "jp-alt" or
// "co.uk" is dead data that reads as live configuration. The existing
// table-shape test would not notice, because such a key is still lowercase and
// trimmed — it just never matches anything.
func TestQuirkKeysAreRealTLDShapes(t *testing.T) {
	for _, tld := range QuirkTLDs() {
		if tld == "" {
			t.Error("empty quirk key")
			continue
		}
		for _, r := range tld {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				t.Errorf("quirk key %q contains %q; QueryFor matches a TLD's last label, so this can never match", tld, r)
			}
		}
		// A hyphen is only legitimate inside an IDN A-label.
		if strings.Contains(tld, "-") && !strings.HasPrefix(tld, "xn--") {
			t.Errorf("quirk key %q has a hyphen but is not an A-label; it looks descriptive rather than real", tld)
		}
	}
}

// TestNoReferralQuirksActuallySuppress pins the behaviour rather than the data:
// every NoReferral entry must stop a referral being followed.
func TestNoReferralQuirksActuallySuppress(t *testing.T) {
	for _, tld := range QuirkTLDs() {
		q, _ := QuirkFor(tld)
		if !q.NoReferral {
			continue
		}
		if ReferralsAllowed(tld) {
			t.Errorf("%s is marked NoReferral but ReferralsAllowed says otherwise", tld)
		}
	}
	// A TLD with no quirk allows referrals, which is the default that matters.
	if !ReferralsAllowed("org") {
		t.Error("ReferralsAllowed(org) = false; a TLD with no quirk must allow referrals")
	}
}
