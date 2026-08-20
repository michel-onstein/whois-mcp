package parsers

import "strings"

// Template is one registry's deviations from the generic parse.
//
// It is data, not code, for the same reason the quirks table is: forty
// registries expressed as forty functions is forty places to look, while forty
// rows are auditable at a glance and testable against a fixture each.
//
// A template never has to be complete. The synonym map already knows the common
// labels, so a template only carries what is host-specific: labels nobody else
// uses, a date order that would otherwise be misread, and the exact phrases
// that registry uses to say "no such domain".
type Template struct {
	// Labels maps a lowercased host-specific label to a canonical field. It is
	// consulted before the shared synonym map, so it can also override a label
	// this registry uses to mean something unusual.
	Labels map[string]string
	// DateLayouts are tried before the generic list. Present when a registry
	// uses an order the generic list would misread — day-first versus
	// month-first being the dangerous case, since both parse.
	DateLayouts []string
	// NotFound are this registry's exact "no such domain" phrases.
	NotFound []string
	// Registered are phrases that confirm a record exists, for registries whose
	// output is otherwise too sparse for the generic signals.
	Registered []string
	// Why documents anything surprising. As with quirks, an unexplained entry
	// cannot be retired safely.
	Why string
}

// templates is keyed by WHOIS host, lowercase, without a port.
//
// The set covers the hosts that serve the overwhelming majority of real
// queries: the gTLD registries, plus the ccTLDs large enough that someone will
// look them up on the first day. Anything not listed still parses through the
// heuristic tier — a missing template lowers parse_confidence, it does not fail
// the lookup.
var templates = map[string]Template{
	// ---------- gTLD registries ----------
	"whois.verisign-grs.com": {
		NotFound:   []string{"no match for"},
		Registered: []string{"registry expiry date"},
		Why:        "Verisign serves .com/.net; its negative is a single fixed phrase.",
	},
	"whois.publicinterestregistry.org": {
		NotFound: []string{"not found:", "nothing found for this query"},
		Why:      "PIR serves .org.",
	},
	"whois.nic.google": {
		NotFound: []string{"domain not found"},
		Why:      "Google Registry serves .dev/.app and many brand TLDs.",
	},
	"whois.nic.io": {
		NotFound: []string{"not found", "no match for"},
		Why:      "Identity Digital platform, shared with several small gTLDs.",
	},
	"whois.afilias.net": {
		NotFound: []string{"not found:", "not found"},
		Why:      "Afilias/Identity Digital platform for .info and others.",
	},
	"whois.nic.biz": {
		NotFound: []string{"not found:", "no data found"},
	},
	"whois.donuts.co": {
		NotFound: []string{"domain not found"},
		Why:      "Donuts platform, many new gTLDs.",
	},
	"whois.rrpproxy.net": {
		NotFound: []string{"domain not found"},
	},
	"whois.centralnic.com": {
		NotFound: []string{"domain not found", "no match for"},
		Why:      "CentralNic platform, many new gTLDs and delegated ccTLDs.",
	},

	// ---------- ccTLDs, Europe ----------
	"whois.nic.uk": {
		Labels: map[string]string{
			"registered on":       FCreated,
			"expiry date":         FExpires,
			"last updated":        FUpdated,
			"registrar":           FRegistrar,
			"name servers":        FNameserver,
			"registration status": FStatus,
		},
		DateLayouts: []string{"02-Jan-2006", "Mon Jan 02 2006"},
		NotFound:    []string{"no match for", "this domain name has not been registered"},
		Registered:  []string{"registered on:"},
		Why: "Nominet uses its own labels and a day-first date; the generic list " +
			"would read 02-03-2006 as February.",
	},
	"whois.denic.de": {
		Labels: map[string]string{
			"changed": FUpdated,
			"domain":  FDomain,
			"nserver": FNameserver,
			"status":  FStatus,
		},
		NotFound:   []string{"status: free", "status:             free"},
		Registered: []string{"status: connect", "changed:"},
		Why: "DENIC publishes no creation date at all and signals availability " +
			"with 'Status: free' rather than a not-found phrase.",
	},
	"whois.domain-registry.nl": {
		Labels: map[string]string{
			"date registered":      FCreated,
			"record maintained by": "",
			"domain nameservers":   FNameserver,
			"reseller":             "",
		},
		NotFound: []string{"is free", "not a registered .nl domain"},
		Why:      "SIDN says 'is free'; its referral points at a web form (see the .nl quirk).",
	},
	"whois.nic.fr": {
		Labels: map[string]string{
			"created":     FCreated,
			"last-update": FUpdated,
			"expiry-date": FExpires,
			"holder-c":    FRegistrantName,
			"nsl-id":      "",
			"hostname":    FNameserver,
		},
		NotFound: []string{"no entries found in the afnic database", "%% no entries found"},
		Why:      "AFNIC uses hyphenated labels and an RPSL-ish layout.",
	},
	"whois.dk-hostmaster.dk": {
		Labels: map[string]string{
			"registered": FCreated,
			"expires":    FExpires,
			"hostname":   FNameserver,
		},
		DateLayouts: []string{"2006-01-02"},
		NotFound:    []string{"no entries found for the selected source"},
	},
	"whois.iis.se": {
		Labels: map[string]string{
			"created":  FCreated,
			"modified": FUpdated,
			"expires":  FExpires,
			"nserver":  FNameserver,
			"holder":   FRegistrantName,
			"state":    FStatus,
		},
		DateLayouts: []string{"2006-01-02"},
		NotFound:    []string{"not found", "domain not found"},
		Why:         "IIS serves .se and .nu with identical output.",
	},
	"whois.nic.ch": {
		NotFound: []string{"do not have an entry", "we do not have an entry in our database matching your query"},
		Why:      "SWITCH phrases its negative as a sentence with no standard keyword.",
	},
	"whois.eu": {
		Labels:   map[string]string{"name servers": FNameserver, "registrant": FRegistrantName},
		NotFound: []string{"status:      available", "status: available"},
		Why:      "EURid reports availability as a status rather than an error.",
	},
	"whois.nic.it": {
		Labels: map[string]string{
			"created":     FCreated,
			"last update": FUpdated,
			"expire date": FExpires,
			"nameservers": FNameserver,
			"status":      FStatus,
		},
		NotFound: []string{"available", "status:             available"},
		Why:      "IIT-CNR reports AVAILABLE as a status value.",
	},
	"whois.dns.pt": {
		NotFound: []string{"no match", "nao existe"},
		Why:      "DNS.PT answers in Portuguese for some paths.",
	},
	"whois.nic.at": {
		Labels:   map[string]string{"changed": FUpdated, "nserver": FNameserver},
		NotFound: []string{"nothing found", "% nothing found"},
	},
	"whois.norid.no": {
		Labels:      map[string]string{"created": FCreated, "last updated": FUpdated, "name server handle": FNameserver},
		DateLayouts: []string{"2006-01-02"},
		NotFound:    []string{"no matches for query"},
	},
	"whois.fi": {
		Labels:      map[string]string{"created": FCreated, "expires": FExpires, "modified": FUpdated, "nserver": FNameserver},
		DateLayouts: []string{"2.1.2006", "02.01.2006"},
		NotFound:    []string{"domain not found"},
		Why:         "Traficom uses a day-first dotted date that the generic list reads correctly only by luck.",
	},
	"whois.nic.cz": {
		Labels:      map[string]string{"registered": FCreated, "changed": FUpdated, "expire": FExpires, "nserver": FNameserver},
		DateLayouts: []string{"02.01.2006 15:04:05"},
		NotFound:    []string{"no entries found", "%% no entries found"},
	},
	"whois.dns.be": {
		Labels:   map[string]string{"registered": FCreated, "nameservers": FNameserver},
		NotFound: []string{"status:	available", "status: available", "free"},
		Why:      "DNS Belgium uses a tab after the label, which the generic splitter handles.",
	},
	"whois.nic.es": {
		NotFound: []string{"not found", "el dominio no existe"},
	},
	"whois.tcinet.ru": {
		Labels:      map[string]string{"created": FCreated, "paid-till": FExpires, "nserver": FNameserver, "state": FStatus},
		DateLayouts: []string{"2006-01-02T15:04:05Z0700", "2006.01.02"},
		NotFound:    []string{"no entries found"},
		Why:         "TCI uses 'paid-till' for expiry, a label no other registry uses.",
	},
	"whois.registry.in": {
		NotFound: []string{"no data found", "not found"},
	},

	// ---------- ccTLDs, Asia-Pacific ----------
	"whois.jprs.jp": {
		Labels: map[string]string{
			"[created on]":        FCreated,
			"[expires on]":        FExpires,
			"[last updated]":      FUpdated,
			"[status]":            FStatus,
			"[name server]":       FNameserver,
			"[registrant]":        FRegistrantName,
			"[domain name]":       FDomain,
			"[organization]":      FRegistrantOrg,
			"[last update]":       FUpdated,
			"[registration date]": FCreated,
			"[signing key]":       "",
			"[web page]":          "",
			"[email address]":     "",
		},
		DateLayouts: []string{"2006/01/02", "2006/01/02 15:04:05 (JST)"},
		NotFound:    []string{"no match!!", "no match"},
		Why: "JPRS brackets every label and uses slash dates; the /e query suffix " +
			"(see quirks) is what makes this output English at all.",
	},
	"whois.auda.org.au": {
		Labels:   map[string]string{"last modified": FUpdated, "name server": FNameserver, "registrant": FRegistrantName},
		NotFound: []string{"no data found"},
		Why:      "auDA publishes no creation or expiry date, by policy.",
	},
	"whois.twnic.net.tw": {
		DateLayouts: []string{"2006-01-02 15:04:05"},
		NotFound:    []string{"no found", "not found"},
	},
	"whois.kr": {
		Labels:      map[string]string{"registered date": FCreated, "last updated date": FUpdated, "expiration date": FExpires},
		DateLayouts: []string{"2006. 01. 02.", "2006-01-02"},
		NotFound:    []string{"above domain name is not registered"},
		Why:         "KISA uses a spaced dotted date found nowhere else.",
	},
	"whois.cnnic.cn": {
		Labels:      map[string]string{"registration time": FCreated, "expiration time": FExpires},
		DateLayouts: []string{"2006-01-02 15:04:05"},
		NotFound:    []string{"no matching record"},
	},
	"whois.sgnic.sg": {
		DateLayouts: []string{"02-Jan-2006 15:04:05"},
		NotFound:    []string{"domain not found", "not found"},
	},
	"whois.nic.net.nz": {
		Labels:   map[string]string{"domain_dateregistered": FCreated, "domain_datelastmodified": FUpdated, "ns_name_01": FNameserver},
		NotFound: []string{"query_status: 220 available"},
		Why:      "InternetNZ uses an underscore-keyed protocol unlike anything else.",
	},

	// ---------- ccTLDs, Americas & Africa ----------
	"whois.registro.br": {
		Labels:      map[string]string{"created": FCreated, "changed": FUpdated, "expires": FExpires, "nserver": FNameserver, "owner": FRegistrantOrg},
		DateLayouts: []string{"20060102"},
		NotFound:    []string{"no match for", "% no match for"},
		Why:         "NIC.br uses a bare YYYYMMDD date, which only parses with an explicit layout.",
	},
	"whois.cira.ca": {
		Labels:   map[string]string{"creation date": FCreated, "expiry date": FExpires, "name servers": FNameserver},
		NotFound: []string{"not found", "domain status: available"},
		Why:      "CIRA reports availability through Domain status.",
	},
	"whois.nic.cl": {
		DateLayouts: []string{"2006-01-02 15:04:05 MST"},
		NotFound:    []string{"no entries found"},
	},
	"whois.nic.mx": {
		DateLayouts: []string{"2006-01-02"},
		NotFound:    []string{"object_not_found", "no_se_encontro_el_objeto"},
	},
	"whois.registry.co.za": {
		NotFound: []string{"available", "not found"},
	},
	"whois.nic.ar": {
		DateLayouts: []string{"2006-01-02 15:04:05"},
		NotFound:    []string{"el dominio no se encuentra registrado", "no entries found"},
	},
}

// Lookup returns the template for a WHOIS host.
//
// The host may carry a port, since that is the form the transport records.
func Lookup(host string) (Template, bool) {
	h := normalizeHostKey(host)
	if h == "" {
		return Template{}, false
	}
	if t, ok := templates[h]; ok {
		return t, true
	}
	return Template{}, false
}

// Hosts lists every templated host, for tld_info and for table-shape tests.
func Hosts() []string {
	out := make([]string, 0, len(templates))
	for h := range templates {
		out = append(out, h)
	}
	return out
}

func normalizeHostKey(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".")
	// Strip a port. An IPv6 literal has no template, so the simple rule is safe.
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h, "]") {
		h = h[:i]
	}
	return h
}
