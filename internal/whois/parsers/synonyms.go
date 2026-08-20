// Package parsers turns WHOIS free text into fields.
//
// WHOIS has no schema. Every registry emits "label: value" lines in its own
// vocabulary, its own date format, and its own order, and a meaningful minority
// emit something else entirely. So parsing is two tiers (design §8.5):
//
//  1. A per-host template, for the hosts that serve most real traffic. Each is
//     a table of label to canonical field plus date layouts — not code — so
//     adding a registry is a data change and a fixture.
//  2. A heuristic fallback for everything else: generic label/value extraction
//     against a synonym map, scoring parse_confidence by how much of the
//     expected field set was recovered.
//
// The tiers share all their machinery; a template only supplies labels the
// synonym map does not already know, and overrides where a registry reuses a
// common label for an uncommon meaning.
//
// Nothing here decides whether a domain is registered. That is availability
// (design §8.6, notfound.go), and conflating the two is how a rate-limit
// notice becomes "this domain is free".
package parsers

// Canonical field names. These are the keys a template maps onto and the keys
// the report builder reads; they are deliberately not the WHOIS labels, which
// vary per registry.
const (
	FDomain            = "domain"
	FRegistryDomainID  = "registry_domain_id"
	FRegistrar         = "registrar"
	FRegistrarIANAID   = "registrar_iana_id"
	FRegistrarURL      = "registrar_url"
	FAbuseEmail        = "abuse_email"
	FAbusePhone        = "abuse_phone"
	FStatus            = "status"
	FNameserver        = "nameserver"
	FDNSSEC            = "dnssec"
	FCreated           = "created"
	FUpdated           = "updated"
	FExpires           = "expires"
	FTransferred       = "transferred"
	FRegistrantName    = "registrant_name"
	FRegistrantOrg     = "registrant_org"
	FRegistrantEmail   = "registrant_email"
	FRegistrantPhone   = "registrant_phone"
	FRegistrantCountry = "registrant_country"
	FAdminName         = "admin_name"
	FAdminEmail        = "admin_email"
	FTechName          = "tech_name"
	FTechEmail         = "tech_email"
)

// coreFields are the fields parse_confidence is scored against: the ones an
// agent asking "who owns this and when does it expire" actually needs. Contact
// data is excluded because it is redacted for most gTLDs, so its absence says
// nothing about parse quality.
var coreFields = []string{
	FDomain, FRegistrar, FStatus, FNameserver, FCreated, FExpires,
}

// synonyms maps a lowercased WHOIS label to a canonical field.
//
// One canonical field has many labels because registries disagree about
// everything: "Creation Date", "created", "Registered on", "Domain Record
// Activated" and "[Created on]" are all the same fact. Getting this table right
// is most of what the heuristic tier is.
var synonyms = map[string]string{
	// Domain
	"domain name":   FDomain,
	"domain":        FDomain,
	"domainname":    FDomain,
	"domain_name":   FDomain,
	"the domain":    FDomain,
	"query":         FDomain,
	"[domain name]": FDomain,

	// Registry identifiers
	"registry domain id": FRegistryDomainID,
	"domain id":          FRegistryDomainID,
	"roid":               FRegistryDomainID,
	"nic-hdl":            FRegistryDomainID,

	// Registrar
	"registrar":                     FRegistrar,
	"sponsoring registrar":          FRegistrar,
	"registrar name":                FRegistrar,
	"registrar organization":        FRegistrar,
	"registrar handle":              FRegistrar,
	"[registrar]":                   FRegistrar,
	"registrar iana id":             FRegistrarIANAID,
	"sponsoring registrar iana id":  FRegistrarIANAID,
	"registrar ianaid":              FRegistrarIANAID,
	"registrar url":                 FRegistrarURL,
	"registrar website":             FRegistrarURL,
	"registrar web":                 FRegistrarURL,
	"url":                           FRegistrarURL,
	"registrar abuse contact email": FAbuseEmail,
	"abuse contact email":           FAbuseEmail,
	"registrar abuse contact phone": FAbusePhone,
	"abuse contact phone":           FAbusePhone,

	// Status
	"domain status": FStatus,
	"status":        FStatus,
	"state":         FStatus,
	"eppstatus":     FStatus,
	"epp status":    FStatus,
	"[status]":      FStatus,

	// Nameservers
	"name server":   FNameserver,
	"nameserver":    FNameserver,
	"nserver":       FNameserver,
	"name servers":  FNameserver,
	"nameservers":   FNameserver,
	"dns":           FNameserver,
	"[name server]": FNameserver,
	"host name":     FNameserver,

	// DNSSEC
	"dnssec":        FDNSSEC,
	"dnssec status": FDNSSEC,
	"signed":        FDNSSEC,
	"dnssec signed": FDNSSEC,

	// Dates
	"creation date":            FCreated,
	"created":                  FCreated,
	"created on":               FCreated,
	"created date":             FCreated,
	"registered":               FCreated,
	"registered on":            FCreated,
	"registration date":        FCreated,
	"domain registration date": FCreated,
	"registration time":        FCreated,
	"domain record activated":  FCreated,
	"[created on]":             FCreated,
	"activated":                FCreated,

	"updated date":               FUpdated,
	"updated":                    FUpdated,
	"last updated":               FUpdated,
	"last modified":              FUpdated,
	"changed":                    FUpdated,
	"modified":                   FUpdated,
	"domain record last updated": FUpdated,
	"last update":                FUpdated,
	"[last updated]":             FUpdated,

	"registry expiry date":   FExpires,
	"expiry date":            FExpires,
	"expiration date":        FExpires,
	"expires":                FExpires,
	"expires on":             FExpires,
	"expire date":            FExpires,
	"paid-till":              FExpires,
	"paid till":              FExpires,
	"renewal date":           FExpires,
	"domain expiration date": FExpires,
	"valid until":            FExpires,
	"[expires on]":           FExpires,

	"transfer date": FTransferred,
	"transferred":   FTransferred,

	// Contacts. Only the roles the report models; everything else is retained
	// in Fields but not promoted.
	"registrant name":          FRegistrantName,
	"registrant":               FRegistrantName,
	"registrant contact name":  FRegistrantName,
	"[registrant]":             FRegistrantName,
	"registrant organization":  FRegistrantOrg,
	"registrant organisation":  FRegistrantOrg,
	"registrant org":           FRegistrantOrg,
	"organisation":             FRegistrantOrg,
	"organization":             FRegistrantOrg,
	"registrant email":         FRegistrantEmail,
	"registrant contact email": FRegistrantEmail,
	"registrant e-mail":        FRegistrantEmail,
	"registrant phone":         FRegistrantPhone,
	"registrant country":       FRegistrantCountry,
	"country":                  FRegistrantCountry,

	"admin name":             FAdminName,
	"administrative contact": FAdminName,
	"admin contact":          FAdminName,
	"admin email":            FAdminEmail,
	"admin contact email":    FAdminEmail,

	"tech name":          FTechName,
	"technical contact":  FTechName,
	"tech contact":       FTechName,
	"tech email":         FTechEmail,
	"tech contact email": FTechEmail,
}

// multiValued fields legitimately repeat. Everything else keeps its first
// occurrence, because a repeated single-valued label is usually a second
// object in the same response (a registrar block after a domain block) and
// overwriting with it corrupts the record.
var multiValued = map[string]bool{
	FNameserver: true,
	FStatus:     true,
}

// redactionMarkers are the values registries use to mean "withheld", as
// opposed to "absent". The difference is information an agent must not lose:
// the design models it as Entity.Redacted.
var redactionMarkers = []string{
	"redacted for privacy",
	"redacted for gdpr",
	"redacted",
	"data protected",
	"gdpr masked",
	"not disclosed",
	"non-public data",
	"withheld for privacy",
	"privacy protected",
	"statutory masking enabled",
	"information unavailable",
}
