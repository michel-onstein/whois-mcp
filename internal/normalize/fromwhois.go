package normalize

import (
	"time"

	"github.com/qjam/whois-mcp/internal/whois/parsers"
)

// FromWHOIS maps a parsed WHOIS record onto the canonical report.
//
// The whole point of the report existing is that a caller cannot tell from its
// shape which protocol answered — only Source.Protocol and ParseConfidence say
// so, and those are the honest signals rather than a different schema.
//
// As with FromRDAP it never invents data: a field the registry did not publish
// stays at its zero value. DENIC, for instance, publishes no creation date at
// all, and the correct report has no creation date rather than a plausible one.
func FromWHOIS(q Query, p *parsers.Parsed, registered Tristate, servers []string, fetchedAt time.Time, cacheState string, rawAvailable bool) *DomainReport {
	rep := &DomainReport{
		Query:      q,
		Registered: registered,
		Source: Source{
			Protocol:     ProtoWHOIS,
			Servers:      servers,
			FetchedAt:    fetchedAt.UTC(),
			Cache:        cacheState,
			RawAvailable: rawAvailable,
		},
	}
	if p == nil {
		rep.Registered = Unknown
		return rep
	}

	rep.Source.ParseConfidence = p.Confidence
	rep.RegistryDomainID = p.RegistryDomainID

	rep.Statuses = p.Statuses
	rep.StatusMeaning = StatusMeanings(p.Statuses)

	rep.Dates = Dates{
		Created:         p.Created,
		Updated:         p.Updated,
		Expires:         p.Expires,
		Transferred:     p.Transferred,
		TimezoneAssumed: p.TimezoneAssumed,
	}

	for _, host := range p.Nameservers {
		rep.Nameservers = append(rep.Nameservers, Nameserver{Host: host})
	}

	// DNSSEC is only reported when the registry actually said something. A
	// missing field is not "unsigned": plenty of registries never mention it,
	// and reporting Signed=false there would assert something unverified.
	if p.DNSSECStated {
		rep.DNSSEC = &DNSSEC{Signed: p.DNSSECSigned}
	}

	if p.RegistrarName != "" || p.RegistrarIANAID != 0 || p.AbuseEmail != "" {
		rep.Registrar = &Registrar{
			Name:       p.RegistrarName,
			IANAID:     p.RegistrarIANAID,
			URL:        p.RegistrarURL,
			AbuseEmail: p.AbuseEmail,
			AbusePhone: p.AbusePhone,
		}
	}

	for _, c := range []*parsers.Contact{p.Registrant, p.Admin, p.Tech} {
		if c == nil {
			continue
		}
		rep.Entities = append(rep.Entities, Entity{
			Role:         c.Role,
			Redacted:     c.Redacted,
			Reason:       c.Reason,
			Name:         c.Name,
			Organization: c.Organization,
			Email:        c.Email,
			Phone:        c.Phone,
			Country:      c.Country,
		})
	}

	// A low-confidence parse is worth saying out loud. An agent that sees
	// confidence 0.3 and no warning may well trust the fields anyway.
	if p.Confidence < 0.5 {
		rep.Warnings = append(rep.Warnings,
			"WHOIS response parsed with low confidence; prefer the raw text via whois_raw for anything load-bearing")
	}
	if p.TimezoneAssumed {
		rep.Warnings = append(rep.Warnings,
			"at least one date carried no timezone and was read as UTC")
	}
	return rep
}
