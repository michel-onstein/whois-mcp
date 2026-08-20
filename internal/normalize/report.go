// Package normalize defines the canonical DomainReport and maps upstream RDAP
// and WHOIS shapes onto it. The report is the contract between the two
// upstream protocols, the tool schemas, and the agent's mental model; see
// docs/MCP_DESIGN.md §7 before changing anything here.
package normalize

import "time"

// Tristate answers "is this domain registered?" without ever guessing.
//
// An RDAP 404 usually means "not registered", but it also occurs when a server
// is misconfigured, blocks us, or returns a generic error page. Reporting
// Unknown when the signal is ambiguous is deliberate: confidently telling a
// user that a taken domain is free is this server's worst failure mode.
type Tristate string

// The three answers. Unknown is not a failure: it is the honest report when
// the upstream signal was ambiguous.
const (
	Yes     Tristate = "yes"
	No      Tristate = "no"
	Unknown Tristate = "unknown"
)

// Protocol identifies which upstream answered.
type Protocol string

// The two upstream protocols.
const (
	ProtoRDAP  Protocol = "rdap"
	ProtoWHOIS Protocol = "whois"
)

// Query echoes how the caller's raw input was interpreted, so an agent can
// show the user what was actually looked up.
type Query struct {
	Input             string `json:"input" jsonschema:"the raw input as supplied by the caller"`
	RegistrableDomain string `json:"registrable_domain" jsonschema:"the eTLD+1 actually queried, as a Unicode U-label"`
	ASCII             string `json:"ascii" jsonschema:"the same domain as an IDNA2008 A-label (Punycode)"`
	TLD               string `json:"tld" jsonschema:"the effective top-level domain"`
	PublicSuffix      string `json:"public_suffix" jsonschema:"the public suffix from the Public Suffix List"`
}

// Dates holds registration lifecycle timestamps, always RFC 3339 UTC.
type Dates struct {
	Created     *time.Time `json:"created" jsonschema:"when the domain was first registered"`
	Updated     *time.Time `json:"updated" jsonschema:"when the registration was last changed"`
	Expires     *time.Time `json:"expires" jsonschema:"when the registration expires"`
	Transferred *time.Time `json:"transferred" jsonschema:"when the domain last changed registrar"`
	// TimezoneAssumed is true when an upstream supplied a bare date with no
	// offset and UTC was assumed.
	TimezoneAssumed bool `json:"timezone_assumed" jsonschema:"true if an upstream date carried no timezone and UTC was assumed"`
}

// Registrar identifies the sponsoring registrar.
type Registrar struct {
	Name       string `json:"name,omitempty"`
	IANAID     int    `json:"iana_id,omitempty" jsonschema:"IANA registrar ID, 0 if unknown"`
	URL        string `json:"url,omitempty"`
	AbuseEmail string `json:"abuse_email,omitempty"`
	AbusePhone string `json:"abuse_phone,omitempty"`
}

// Nameserver is a delegated nameserver, with glue if the registry published it.
type Nameserver struct {
	Host string   `json:"host"`
	IPv4 []string `json:"ipv4,omitempty"`
	IPv6 []string `json:"ipv6,omitempty"`
}

// DNSSEC reports delegation signing.
type DNSSEC struct {
	Signed    bool `json:"signed"`
	DSRecords int  `json:"ds_records"`
}

// Entity is a contact record. Post-GDPR most gTLD contacts are withheld, so
// Redacted distinguishes "the data exists but is withheld" from "there is no
// such contact" — a different fact, and one an agent must not conflate.
type Entity struct {
	Role         string `json:"role" jsonschema:"registrant, administrative, technical, abuse, registrar, or reseller"`
	Redacted     bool   `json:"redacted" jsonschema:"true if the registry withheld this contact's details"`
	Reason       string `json:"reason,omitempty" jsonschema:"why the data was withheld, when stated"`
	Name         string `json:"name,omitempty"`
	Organization string `json:"organization,omitempty"`
	Email        string `json:"email,omitempty"`
	Phone        string `json:"phone,omitempty"`
	Country      string `json:"country,omitempty"`
}

// Source records how the answer was obtained and how much to trust it.
type Source struct {
	Protocol  Protocol  `json:"protocol" jsonschema:"rdap or whois"`
	Servers   []string  `json:"servers" jsonschema:"the upstream endpoints consulted, in order"`
	FetchedAt time.Time `json:"fetched_at"`
	Cache     string    `json:"cache" jsonschema:"hit or miss"`
	// ParseConfidence is 1.0 for RDAP, which is structured. WHOIS text is
	// parsed heuristically and scores lower, so an agent can decide whether to
	// trust the parse or fall back to quoting the raw response.
	ParseConfidence float64 `json:"parse_confidence" jsonschema:"1.0 for RDAP; 0.0-1.0 for heuristically parsed WHOIS text"`
	RawAvailable    bool    `json:"raw_available" jsonschema:"true if the raw upstream payload can be fetched via rdap_raw or whois_raw"`
}

// DomainReport is the canonical, source-agnostic registration record.
type DomainReport struct {
	Query            Query             `json:"query"`
	Registered       Tristate          `json:"registered" jsonschema:"yes, no, or unknown - never guess when the signal is ambiguous"`
	RegistryDomainID string            `json:"registry_domain_id,omitempty"`
	Dates            Dates             `json:"dates"`
	Registrar        *Registrar        `json:"registrar,omitempty"`
	Statuses         []string          `json:"statuses,omitempty" jsonschema:"EPP status codes"`
	StatusMeaning    map[string]string `json:"status_meaning,omitempty" jsonschema:"plain-language expansion of each EPP status code"`
	Nameservers      []Nameserver      `json:"nameservers,omitempty"`
	DNSSEC           *DNSSEC           `json:"dnssec,omitempty"`
	Entities         []Entity          `json:"entities,omitempty"`
	Source           Source            `json:"source"`
	Warnings         []string          `json:"warnings,omitempty" jsonschema:"non-fatal problems, such as a registrar referral that timed out"`
}
