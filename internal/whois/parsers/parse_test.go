package parsers

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const fixtureDir = "../../../testdata/whois"

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return b
}

func date(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("bad want-date %q: %v", s, err)
	}
	return ts.UTC()
}

// TestGoldenFixtures is the per-registry golden test: one row per templated
// host, asserting the fields an agent actually asks for. A template change that
// breaks a registry fails here rather than in production.
func TestGoldenFixtures(t *testing.T) {
	cases := []struct {
		name        string
		file        string
		host        string
		wantDomain  string
		wantRegistr string
		wantCreated string
		wantExpires string
		wantNS      []string
		wantStatus  bool
		minConf     float64
	}{
		{
			name: "verisign com", file: "com-registered.txt", host: "whois.verisign-grs.com",
			wantDomain: "example.com", wantRegistr: "Example Registrar, LLC",
			wantCreated: "1997-09-15T04:00:00Z", wantExpires: "2028-09-14T04:00:00Z",
			wantNS:     []string{"ns1.example-dns.test", "ns2.example-dns.test"},
			wantStatus: true, minConf: 0.9,
		},
		{
			name: "nominet uk", file: "uk-registered.txt", host: "whois.nic.uk",
			wantDomain: "example.co.uk", wantRegistr: "Example Registrar Ltd [Tag = EXAMPLE-TAG]",
			wantCreated: "1999-03-12T00:00:00Z", wantExpires: "2027-03-12T00:00:00Z",
			wantNS:     []string{"ns1.example-dns.test", "ns2.example-dns.test"},
			wantStatus: true, minConf: 0.7,
		},
		{
			name: "denic de", file: "de-registered.txt", host: "whois.denic.de",
			wantDomain: "example.de",
			wantNS:     []string{"ns1.example-dns.test", "ns2.example-dns.test"},
			wantStatus: true, minConf: 0.3, // DENIC publishes no dates at all
		},
		{
			name: "jprs jp", file: "jp-registered.txt", host: "whois.jprs.jp",
			wantDomain:  "example.jp",
			wantCreated: "2001-04-01T00:00:00Z", wantExpires: "2027-04-30T00:00:00Z",
			wantNS:     []string{"ns1.example-dns.test", "ns2.example-dns.test"},
			wantStatus: true, minConf: 0.5,
		},
		{
			name: "registro br", file: "br-registered.txt", host: "whois.registro.br",
			wantDomain:  "example.com.br",
			wantCreated: "1999-03-15T00:00:00Z", wantExpires: "2027-03-15T00:00:00Z",
			wantNS:     []string{"ns1.example-dns.test", "ns2.example-dns.test"},
			wantStatus: true, minConf: 0.5,
		},
		{
			name: "afnic fr", file: "fr-registered.txt", host: "whois.nic.fr",
			wantDomain: "example.fr", wantRegistr: "EXAMPLE REGISTRAR SAS",
			wantCreated: "1995-01-01T00:00:00Z", wantExpires: "2027-01-01T00:00:00Z",
			wantNS:     []string{"ns1.example-dns.test", "ns2.example-dns.test"},
			wantStatus: true, minConf: 0.8,
		},
		{
			name: "iis se", file: "se-registered.txt", host: "whois.iis.se",
			wantDomain: "example.se", wantRegistr: "Example Registrar AB",
			wantCreated: "1998-06-01T00:00:00Z", wantExpires: "2027-05-31T00:00:00Z",
			wantNS:     []string{"ns1.example-dns.test", "ns2.example-dns.test"},
			wantStatus: true, minConf: 0.8,
		},
		{
			name: "tcinet ru", file: "ru-registered.txt", host: "whois.tcinet.ru",
			wantDomain: "example.ru", wantRegistr: "EXAMPLE-RU",
			wantCreated: "2003-09-30T09:14:14Z", wantExpires: "2027-09-30T21:00:00Z",
			wantNS:     []string{"ns1.example-dns.test", "ns2.example-dns.test"},
			wantStatus: true, minConf: 0.8,
		},
		{
			// No template: the heuristic tier must still recover the record,
			// and must score below a templated parse for doing so.
			name: "heuristic, no template", file: "unknown-host-registered.txt", host: "whois.unknown.test",
			wantDomain: "example.unknown", wantRegistr: "Some Registrar",
			wantCreated: "2010-05-04T00:00:00Z", wantExpires: "2027-05-04T00:00:00Z",
			wantNS:     []string{"ns1.example-dns.test", "ns2.example-dns.test"},
			wantStatus: true, minConf: 0.5,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := Parse(c.host, fixture(t, c.file))

			if c.wantDomain != "" && p.DomainName != c.wantDomain {
				t.Errorf("DomainName = %q; want %q", p.DomainName, c.wantDomain)
			}
			if c.wantRegistr != "" && p.RegistrarName != c.wantRegistr {
				t.Errorf("RegistrarName = %q; want %q", p.RegistrarName, c.wantRegistr)
			}
			if c.wantCreated != "" {
				if p.Created == nil {
					t.Errorf("Created = nil; want %s", c.wantCreated)
				} else if !p.Created.Equal(date(t, c.wantCreated)) {
					t.Errorf("Created = %s; want %s", p.Created.Format(time.RFC3339), c.wantCreated)
				}
			}
			if c.wantExpires != "" {
				if p.Expires == nil {
					t.Errorf("Expires = nil; want %s", c.wantExpires)
				} else if !p.Expires.Equal(date(t, c.wantExpires)) {
					t.Errorf("Expires = %s; want %s", p.Expires.Format(time.RFC3339), c.wantExpires)
				}
			}
			if len(c.wantNS) > 0 {
				if len(p.Nameservers) != len(c.wantNS) {
					t.Errorf("Nameservers = %v; want %v", p.Nameservers, c.wantNS)
				} else {
					for i, want := range c.wantNS {
						if p.Nameservers[i] != want {
							t.Errorf("Nameservers[%d] = %q; want %q", i, p.Nameservers[i], want)
						}
					}
				}
			}
			if c.wantStatus && len(p.Statuses) == 0 {
				t.Error("Statuses is empty; want at least one")
			}
			if p.Confidence < c.minConf {
				t.Errorf("Confidence = %.2f; want >= %.2f", p.Confidence, c.minConf)
			}
			// Every fixture above is a registered domain.
			if got := Classify(c.host, fixture(t, c.file)); got != Registered {
				t.Errorf("Classify = %q; want %q", got, Registered)
			}
		})
	}
}

// TestClassifyNegativeFixtures is the other half: the not-found variants must
// come back as a confident "no".
func TestClassifyNegativeFixtures(t *testing.T) {
	cases := []struct{ file, host string }{
		{"com-notfound.txt", "whois.verisign-grs.com"},
		{"uk-notfound.txt", "whois.nic.uk"},
		{"de-free.txt", "whois.denic.de"},
		{"jp-notfound.txt", "whois.jprs.jp"},
		{"fr-notfound.txt", "whois.nic.fr"},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			if got := Classify(c.host, fixture(t, c.file)); got != Unregistered {
				t.Errorf("Classify(%s) = %q; want %q", c.file, got, Unregistered)
			}
		})
	}
}

// TestClassifyNeverGuessesFree is the safety test. Every input here is a
// non-answer, and every one of them must be Unknown: reporting a taken domain
// as free is this server's worst possible failure.
func TestClassifyNeverGuessesFree(t *testing.T) {
	cases := []struct {
		name string
		host string
		raw  []byte
	}{
		{"empty", "whois.verisign-grs.com", nil},
		{"rate limited", "whois.verisign-grs.com", fixture(t, "ratelimited.txt")},
		{"html error page", "whois.verisign-grs.com", fixture(t, "html-error.txt")},
		{"banner only", "whois.unknown.test", fixture(t, "banner-only.txt")},
		{"whitespace", "whois.unknown.test", []byte("   \r\n\r\n")},
		{"truncated preamble", "whois.unknown.test", []byte("% This is a WHOIS server\r\n% Terms")},
		{"access denied", "whois.unknown.test", []byte("Access denied. Your IP has been blocked.\r\n")},
		{"connection throttled", "whois.unknown.test", []byte("Query limit exceeded, try again later\r\n")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Classify(c.host, c.raw); got != Unknown {
				t.Errorf("Classify = %q; want %q — a non-answer must never become an availability claim", got, Unknown)
			}
		})
	}
}

// TestClassifyContradictionIsUnknown covers a record that also carries negative
// boilerplate. "Probably registered" is not good enough to assert.
func TestClassifyContradictionIsUnknown(t *testing.T) {
	raw := []byte("Domain Name: example.test\r\nRegistry Expiry Date: 2030-01-01T00:00:00Z\r\n" +
		"NOTICE: no match for other queries is reported as NOT FOUND\r\n")
	if got := Classify("whois.unknown.test", raw); got != Unknown {
		t.Errorf("Classify = %q; want %q for a contradictory response", got, Unknown)
	}
}

func TestParseRedaction(t *testing.T) {
	p := Parse("whois.publicinterestregistry.org", fixture(t, "redacted-gdpr.txt"))
	if p.Registrant == nil {
		t.Fatal("Registrant = nil; want a redacted contact")
	}
	if !p.Registrant.Redacted {
		t.Error("Registrant.Redacted = false; the record says REDACTED FOR PRIVACY")
	}
	if p.Registrant.Name != "" {
		t.Errorf("Registrant.Name = %q; the redaction marker must not be reported as a name", p.Registrant.Name)
	}
	// Organization was not redacted in this record, so it survives — the whole
	// point of tracking redaction per field.
	if p.Registrant.Organization != "Example Organization" {
		t.Errorf("Registrant.Organization = %q; want it preserved", p.Registrant.Organization)
	}
	if p.Registrant.Country != "US" {
		t.Errorf("Registrant.Country = %q; want US", p.Registrant.Country)
	}
	if !p.DNSSECStated || !p.DNSSECSigned {
		t.Errorf("DNSSEC stated=%v signed=%v; want both true for signedDelegation", p.DNSSECStated, p.DNSSECSigned)
	}
}

func TestParseDNSSEC(t *testing.T) {
	cases := []struct {
		in     string
		signed bool
	}{
		{"unsigned", false},
		{"Unsigned", false},
		{"no", false},
		{"unsigned delegation", false},
		{"signedDelegation", true},
		{"signed delegation", true},
		{"yes", true},
		{"Signed", true},
	}
	for _, c := range cases {
		if got := dnssecSigned(c.in); got != c.signed {
			t.Errorf("dnssecSigned(%q) = %v; want %v", c.in, got, c.signed)
		}
	}
}

func TestParseDateLayouts(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		assumed bool
		layouts []string
	}{
		{in: "2024-08-14T07:01:44Z", want: "2024-08-14T07:01:44Z"},
		{in: "1997-09-15T04:00:00-0400", want: "1997-09-15T08:00:00Z"},
		{in: "12-Mar-1999", want: "1999-03-12T00:00:00Z", assumed: true},
		{in: "2001/04/01", want: "2001-04-01T00:00:00Z", assumed: true},
		{in: "19990315", want: "1999-03-15T00:00:00Z", assumed: true},
		{in: "2026-02-10 UTC", want: "2026-02-10T00:00:00Z", assumed: true},
		{in: "2026-05-01 01:05:03 (JST)", want: "2026-05-01T01:05:03Z", assumed: true},
		{in: "2025-11-02T09:15:22+01:00", want: "2025-11-02T08:15:22Z"},
		// A host layout wins over the generic list, which is the point of
		// having one: day-first and month-first both parse.
		{in: "02.03.2006", want: "2006-03-02T00:00:00Z", assumed: true, layouts: []string{"02.01.2006"}},
		{in: "not a date", want: ""},
		{in: "", want: ""},
	}
	for _, c := range cases {
		got, assumed, ok := ParseDate(c.in, c.layouts...)
		if c.want == "" {
			if ok {
				t.Errorf("ParseDate(%q) parsed to %s; want failure", c.in, got)
			}
			continue
		}
		if !ok {
			t.Errorf("ParseDate(%q) failed; want %s", c.in, c.want)
			continue
		}
		if got.Format(time.RFC3339) != c.want {
			t.Errorf("ParseDate(%q) = %s; want %s", c.in, got.Format(time.RFC3339), c.want)
		}
		if assumed != c.assumed {
			t.Errorf("ParseDate(%q) assumed = %v; want %v", c.in, assumed, c.assumed)
		}
	}
}

// TestTemplatedParseScoresHigherThanHeuristic pins the confidence contract: the
// same record read with a template must not score lower than without one.
func TestTemplatedParseScoresHigherThanHeuristic(t *testing.T) {
	raw := fixture(t, "com-registered.txt")
	templated := Parse("whois.verisign-grs.com", raw)
	heuristic := Parse("whois.no-template.test", raw)
	if templated.Confidence <= heuristic.Confidence {
		t.Errorf("templated confidence %.2f is not above heuristic %.2f",
			templated.Confidence, heuristic.Confidence)
	}
	if heuristic.Template != "heuristic" {
		t.Errorf("Template = %q; want %q", heuristic.Template, "heuristic")
	}
	if templated.Template != "whois.verisign-grs.com" {
		t.Errorf("Template = %q; want the host", templated.Template)
	}
}

func TestParseEmptyAndGarbage(t *testing.T) {
	if p := Parse("whois.unknown.test", nil); p.Confidence != 0 {
		t.Errorf("Confidence = %.2f for an empty response; want 0", p.Confidence)
	}
	p := Parse("whois.unknown.test", fixture(t, "html-error.txt"))
	if p.Confidence > 0.3 {
		t.Errorf("Confidence = %.2f for an HTML error page; want a low score", p.Confidence)
	}
	if p.DomainName != "" {
		t.Errorf("DomainName = %q parsed out of an HTML error page", p.DomainName)
	}
}

// TestSplitLineRejectsProse keeps boilerplate out of the field map. A terms-of-
// use sentence with a colon is not a field, and counting it as one would both
// pollute the record and depress every chatty registry's confidence.
func TestSplitLineRejectsProse(t *testing.T) {
	rejected := []string{
		"% This is the registry WHOIS server.",
		"# comment: value",
		">>> Last update of whois database: 2026-08-19T12:00:00Z <<<",
		"NOTICE: The expiration date displayed in this record is the date the",
		"no colon here",
		"",
		"   ",
		":leading colon",
	}
	for _, line := range rejected {
		if label, _, ok := splitLine(line); ok && canonical(label, Template{}) != "" {
			t.Errorf("splitLine(%q) produced a usable field label %q", line, label)
		}
	}

	label, value, ok := splitLine("   Creation Date: 1997-09-15T04:00:00Z")
	if !ok || label != "Creation Date" || value != "1997-09-15T04:00:00Z" {
		t.Errorf("splitLine of a real field = (%q, %q, %v)", label, value, ok)
	}
}

// TestTemplateTableIsWellFormed keeps the table maintainable, the same contract
// the quirks table has.
func TestTemplateTableIsWellFormed(t *testing.T) {
	for _, host := range Hosts() {
		tpl, _ := Lookup(host)
		if host != normalizeHostKey(host) {
			t.Errorf("template key %q is not normalised", host)
		}
		for label, field := range tpl.Labels {
			if label != normalizeLabel(label) {
				t.Errorf("%s: label %q is not lowercased", host, label)
			}
			if field == "" {
				continue // deliberately dropped
			}
			if !knownField(field) {
				t.Errorf("%s: label %q maps to unknown field %q", host, label, field)
			}
		}
		for _, l := range tpl.DateLayouts {
			if _, err := time.Parse(l, l); err != nil && l == "" {
				t.Errorf("%s: empty date layout", host)
			}
		}
		for _, s := range tpl.NotFound {
			if s != normalizeLabel(s) {
				t.Errorf("%s: NotFound signature %q must be lowercase for matching", host, s)
			}
		}
	}
	if len(Hosts()) < 30 {
		t.Errorf("only %d templated hosts; the design calls for ~40 covering most traffic", len(Hosts()))
	}
}

func normalizeLabel(s string) string {
	return lower([]string{s})[0]
}

func knownField(f string) bool {
	for _, k := range []string{
		FDomain, FRegistryDomainID, FRegistrar, FRegistrarIANAID, FRegistrarURL,
		FAbuseEmail, FAbusePhone, FStatus, FNameserver, FDNSSEC,
		FCreated, FUpdated, FExpires, FTransferred,
		FRegistrantName, FRegistrantOrg, FRegistrantEmail, FRegistrantPhone, FRegistrantCountry,
		FAdminName, FAdminEmail, FTechName, FTechEmail,
	} {
		if f == k {
			return true
		}
	}
	return false
}

// TestSynonymTableTargetsKnownFields catches a typo in the synonym map, which
// would otherwise silently drop a field for every registry using that label.
func TestSynonymTableTargetsKnownFields(t *testing.T) {
	for label, field := range synonyms {
		if label != normalizeLabel(label) {
			t.Errorf("synonym %q is not lowercased", label)
		}
		if !knownField(field) {
			t.Errorf("synonym %q maps to unknown field %q", label, field)
		}
	}
}
