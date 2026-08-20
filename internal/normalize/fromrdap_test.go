package normalize

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openrdap/rdap"
)

// loadFixture decodes a captured registry response into an rdap.Domain, the
// same way the client does at runtime.
func loadFixture(t *testing.T, name string) *rdap.Domain {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "rdap", name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	var d rdap.Domain
	dec := rdap.NewDecoder(raw)
	obj, err := dec.Decode()
	if err != nil {
		t.Fatalf("decoding fixture %s: %v", name, err)
	}
	dom, ok := obj.(*rdap.Domain)
	if !ok {
		t.Fatalf("fixture %s decoded to %T, want *rdap.Domain", name, obj)
	}
	d = *dom
	return &d
}

func q(ascii string) Query {
	return Query{Input: ascii, RegistrableDomain: ascii, ASCII: ascii, TLD: "com", PublicSuffix: "com"}
}

func TestFromRDAPComRegistered(t *testing.T) {
	d := loadFixture(t, "com-registered.json")
	rep := FromRDAP(q("example.com"), d, []string{"https://rdap.verisign.com/com/v1/"}, time.Unix(1_700_000_000, 0), "miss")

	if rep.Registered != Yes {
		t.Errorf("Registered = %q, want yes", rep.Registered)
	}
	if rep.Source.Protocol != ProtoRDAP || rep.Source.ParseConfidence != 1.0 {
		t.Errorf("Source = %+v; want rdap with confidence 1.0", rep.Source)
	}
	if rep.Dates.Created == nil || rep.Dates.Created.Year() != 1995 {
		t.Errorf("Created = %v, want 1995", rep.Dates.Created)
	}
	if rep.Dates.Expires == nil {
		t.Error("Expires not populated")
	}
	if rep.Dates.TimezoneAssumed {
		t.Error("TimezoneAssumed = true, but the fixture carries explicit Z offsets")
	}
	if len(rep.Nameservers) != 2 {
		t.Errorf("got %d nameservers, want 2", len(rep.Nameservers))
	}
	for _, ns := range rep.Nameservers {
		if ns.Host != lower(ns.Host) {
			t.Errorf("nameserver %q not lowercased", ns.Host)
		}
	}
	if rep.DNSSEC == nil || !rep.DNSSEC.Signed || rep.DNSSEC.DSRecords != 1 {
		t.Errorf("DNSSEC = %+v; want signed with 1 DS record", rep.DNSSEC)
	}
	if rep.Registrar == nil || rep.Registrar.Name == "" {
		t.Errorf("Registrar = %+v; want a name", rep.Registrar)
	}
	// The .com registry publishes RDAP-style space-separated statuses; the
	// meanings map must still resolve them.
	if len(rep.Statuses) == 0 {
		t.Fatal("no statuses parsed")
	}
	if len(rep.StatusMeaning) == 0 {
		t.Errorf("StatusMeaning empty for statuses %v — RDAP/EPP spelling mismatch?", rep.Statuses)
	}
}

func TestFromRDAPRedactedRegistrant(t *testing.T) {
	d := loadFixture(t, "uk-registered.json")
	rep := FromRDAP(q("nominet.uk"), d, nil, time.Unix(1_700_000_000, 0), "miss")

	var registrant *Entity
	for i := range rep.Entities {
		if rep.Entities[i].Role == "registrant" {
			registrant = &rep.Entities[i]
		}
	}
	if registrant == nil {
		t.Fatalf("no registrant entity in %+v", rep.Entities)
	}
	if !registrant.Redacted {
		t.Error("registrant.Redacted = false; fixture is marked REDACTED FOR PRIVACY")
	}
	// Placeholder text must not survive as if it were real contact data.
	if registrant.Name != "" || registrant.Email != "" {
		t.Errorf("redacted registrant still carries data: name=%q email=%q", registrant.Name, registrant.Email)
	}
	if registrant.Reason == "" {
		t.Error("redaction reason not recorded")
	}
}

func TestFromRDAPNilDomainIsUnknown(t *testing.T) {
	rep := FromRDAP(q("example.com"), nil, nil, time.Now(), "miss")
	if rep.Registered != Unknown {
		t.Errorf("Registered = %q, want unknown for a nil domain", rep.Registered)
	}
}

func TestStatusMeaningsAcceptsBothSpellings(t *testing.T) {
	rdapStyle := StatusMeanings([]string{"client transfer prohibited"})
	eppStyle := StatusMeanings([]string{"clientTransferProhibited"})
	if len(rdapStyle) != 1 || len(eppStyle) != 1 {
		t.Fatalf("rdap=%v epp=%v; both spellings must resolve", rdapStyle, eppStyle)
	}
	if rdapStyle["client transfer prohibited"] != eppStyle["clientTransferProhibited"] {
		t.Error("the two spellings resolved to different meanings")
	}
	if got := StatusMeanings([]string{"notARealStatus"}); got != nil {
		t.Errorf("unknown status invented a meaning: %v", got)
	}
}

func TestParseRDAPTime(t *testing.T) {
	tests := []struct {
		in         string
		wantOK     bool
		wantAssume bool
	}{
		{"1995-08-14T04:00:00Z", true, false},
		{"2026-08-14T08:01:43Z", true, false},
		{"2026-08-14T08:01:43+02:00", true, false},
		{"2026-08-14T08:01:43", true, true}, // no zone: UTC assumed
		{"2026-08-14", true, true},
		{"", false, false},
		{"not a date", false, false},
	}
	for _, tc := range tests {
		_, assumed, ok := parseRDAPTime(tc.in)
		if ok != tc.wantOK {
			t.Errorf("parseRDAPTime(%q) ok = %v, want %v", tc.in, ok, tc.wantOK)
		}
		if ok && assumed != tc.wantAssume {
			t.Errorf("parseRDAPTime(%q) assumedTZ = %v, want %v", tc.in, assumed, tc.wantAssume)
		}
	}
}

func TestReportRoundTripsJSON(t *testing.T) {
	d := loadFixture(t, "org-registered.json")
	rep := FromRDAP(q("example.org"), d, []string{"https://x/"}, time.Unix(1_700_000_000, 0).UTC(), "miss")
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back DomainReport
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Registered != rep.Registered || back.Query.ASCII != rep.Query.ASCII {
		t.Error("report did not survive a JSON round trip")
	}
	if !back.Source.FetchedAt.Equal(rep.Source.FetchedAt) {
		t.Errorf("FetchedAt drifted: %v -> %v", rep.Source.FetchedAt, back.Source.FetchedAt)
	}
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
