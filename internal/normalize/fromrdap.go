package normalize

import (
	"strconv"
	"strings"
	"time"

	"github.com/openrdap/rdap"
)

// redactionMarkers are the strings registries substitute for withheld contact
// data. Detecting them lets the report say "withheld" rather than "absent",
// which are different facts.
var redactionMarkers = []string{
	"redacted",
	"data redacted",
	"not disclosed",
	"withheld",
	"privacy",
	"gdpr masked",
	"statutory masking enabled",
}

// FromRDAP maps a decoded RDAP domain onto the canonical report.
//
// It never invents data: a field the response does not carry is left at its
// zero value, and dates that cannot be parsed are dropped with a warning
// rather than guessed.
func FromRDAP(q Query, d *rdap.Domain, servers []string, fetchedAt time.Time, cacheState string) *DomainReport {
	rep := &DomainReport{
		Query:      q,
		Registered: Yes,
		Source: Source{
			Protocol:        ProtoRDAP,
			Servers:         servers,
			FetchedAt:       fetchedAt.UTC(),
			Cache:           cacheState,
			ParseConfidence: 1.0, // RDAP is structured; there is nothing to guess
			RawAvailable:    true,
		},
	}
	if d == nil {
		rep.Registered = Unknown
		return rep
	}

	rep.RegistryDomainID = d.Handle
	rep.Statuses = d.Status
	rep.StatusMeaning = StatusMeanings(d.Status)

	rep.Dates, rep.Warnings = datesFromEvents(d.Events, rep.Warnings)

	for _, ns := range d.Nameservers {
		n := Nameserver{Host: strings.ToLower(firstNonEmpty(ns.LDHName, ns.UnicodeName))}
		if n.Host == "" {
			continue
		}
		if ns.IPAddresses != nil {
			n.IPv4 = ns.IPAddresses.V4
			n.IPv6 = ns.IPAddresses.V6
		}
		rep.Nameservers = append(rep.Nameservers, n)
	}

	if d.SecureDNS != nil {
		ds := DNSSEC{DSRecords: len(d.SecureDNS.DS)}
		if d.SecureDNS.DelegationSigned != nil {
			ds.Signed = *d.SecureDNS.DelegationSigned
		}
		rep.DNSSEC = &ds
	}

	for _, e := range d.Entities {
		ent, registrar := entityFromRDAP(e)
		if registrar != nil && rep.Registrar == nil {
			rep.Registrar = registrar
		}
		if ent != nil {
			rep.Entities = append(rep.Entities, *ent)
		}
	}

	return rep
}

// datesFromEvents maps RFC 9083 eventAction values onto the report's dates.
func datesFromEvents(events []rdap.Event, warnings []string) (Dates, []string) {
	var out Dates
	for _, ev := range events {
		t, assumedTZ, ok := parseRDAPTime(ev.Date)
		if !ok {
			if ev.Date != "" {
				warnings = append(warnings, "unparseable "+ev.Action+" date from registry: "+ev.Date)
			}
			continue
		}
		if assumedTZ {
			out.TimezoneAssumed = true
		}
		switch strings.ToLower(strings.TrimSpace(ev.Action)) {
		case "registration":
			out.Created = &t
		case "expiration":
			out.Expires = &t
		case "last changed":
			out.Updated = &t
		case "transfer":
			out.Transferred = &t
		}
	}
	return out, warnings
}

// rdapTimeLayouts covers the formats registries actually emit. RFC 9083
// requires RFC 3339, but not every registry complies.
var rdapTimeLayouts = []struct {
	layout  string
	hasZone bool
}{
	{time.RFC3339, true},
	{"2006-01-02T15:04:05Z0700", true},
	{"2006-01-02T15:04:05", false},
	{"2006-01-02 15:04:05", false},
	{"2006-01-02", false},
}

// parseRDAPTime returns the instant, whether a timezone had to be assumed, and
// whether parsing succeeded at all.
func parseRDAPTime(s string) (time.Time, bool, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false, false
	}
	for _, l := range rdapTimeLayouts {
		if t, err := time.Parse(l.layout, s); err == nil {
			return t.UTC(), !l.hasZone, true
		}
	}
	return time.Time{}, false, false
}

// entityFromRDAP converts an RDAP entity, and additionally returns registrar
// details when the entity holds the registrar role.
func entityFromRDAP(e rdap.Entity) (*Entity, *Registrar) {
	role := primaryRole(e.Roles)
	if role == "" {
		return nil, nil
	}

	ent := &Entity{Role: role}
	if e.VCard != nil {
		ent.Name = e.VCard.Name()
		ent.Organization = e.VCard.Org()
		ent.Email = e.VCard.Email()
		ent.Phone = e.VCard.Tel()
		ent.Country = e.VCard.Country()
	}

	if reason, redacted := detectRedaction(ent, e.Remarks); redacted {
		ent.Redacted = true
		ent.Reason = reason
		// Keep the shape, drop the placeholder text: "REDACTED FOR PRIVACY" is
		// not a name, and an agent must not repeat it back as one.
		ent.Name, ent.Organization, ent.Email, ent.Phone = "", "", "", ""
	}

	var reg *Registrar
	if role == "registrar" {
		reg = &Registrar{
			Name:   firstNonEmpty(ent.Organization, ent.Name),
			IANAID: ianaIDFrom(e.PublicIDs),
		}
		if e.VCard != nil && reg.Name == "" {
			reg.Name = e.VCard.Name()
		}
		// Abuse contact is a nested entity with the "abuse" role.
		for _, sub := range e.Entities {
			if !hasRole(sub.Roles, "abuse") || sub.VCard == nil {
				continue
			}
			reg.AbuseEmail = sub.VCard.Email()
			reg.AbusePhone = sub.VCard.Tel()
		}
		for _, l := range e.Links {
			if strings.EqualFold(l.Rel, "about") && strings.HasPrefix(l.Href, "http") {
				reg.URL = l.Href
				break
			}
		}
	}
	return ent, reg
}

// detectRedaction reports whether a contact's details were withheld, and why
// if the registry said.
func detectRedaction(ent *Entity, remarks []rdap.Remark) (string, bool) {
	for _, r := range remarks {
		blob := strings.ToLower(r.Title + " " + strings.Join(r.Description, " ") + " " + r.Type)
		for _, m := range redactionMarkers {
			if strings.Contains(blob, m) {
				return firstNonEmpty(r.Title, "withheld by the registry"), true
			}
		}
	}
	for _, v := range []string{ent.Name, ent.Organization, ent.Email} {
		lv := strings.ToLower(v)
		for _, m := range redactionMarkers {
			if strings.Contains(lv, m) {
				return "withheld by the registry", true
			}
		}
	}
	return "", false
}

// primaryRole picks the most meaningful role when an entity claims several.
func primaryRole(roles []string) string {
	if len(roles) == 0 {
		return ""
	}
	priority := []string{"registrant", "administrative", "technical", "abuse", "registrar", "reseller", "billing"}
	for _, p := range priority {
		if hasRole(roles, p) {
			return p
		}
	}
	return strings.ToLower(roles[0])
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if strings.EqualFold(strings.TrimSpace(r), want) {
			return true
		}
	}
	return false
}

func ianaIDFrom(ids []rdap.PublicID) int {
	for _, p := range ids {
		if !strings.Contains(strings.ToLower(p.Type), "iana") {
			continue
		}
		if n, err := strconv.Atoi(strings.TrimSpace(p.Identifier)); err == nil {
			return n
		}
	}
	return 0
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}
