package parsers

import (
	"strconv"
	"strings"
	"time"
)

// Contact is a parsed contact record. Redacted distinguishes "withheld" from
// "absent", which are different facts an agent must not conflate.
type Contact struct {
	Role         string
	Redacted     bool
	Reason       string
	Name         string
	Organization string
	Email        string
	Phone        string
	Country      string
}

// Parsed is the structured result of reading a WHOIS response.
type Parsed struct {
	// Template names the host template used, or "heuristic" when none matched.
	// Surfacing it makes a bad parse diagnosable without re-running the query.
	Template string
	// Confidence is 0.0-1.0: the share of core fields recovered, adjusted for
	// whether a host template was available. RDAP is always 1.0 by comparison,
	// which is the point of reporting it at all.
	Confidence float64

	DomainName       string
	RegistryDomainID string
	RegistrarName    string
	RegistrarIANAID  int
	RegistrarURL     string
	AbuseEmail       string
	AbusePhone       string
	Statuses         []string
	Nameservers      []string
	DNSSECSigned     bool
	DNSSECStated     bool

	Created     *time.Time
	Updated     *time.Time
	Expires     *time.Time
	Transferred *time.Time
	// TimezoneAssumed is true if any date arrived without a zone.
	TimezoneAssumed bool

	Registrant *Contact
	Admin      *Contact
	Tech       *Contact

	// Fields holds every canonical field seen, including ones not promoted to a
	// typed member. Retained so a caller can answer a question the report shape
	// does not model without re-parsing.
	Fields map[string][]string
	// UnknownLabels counts labels no tier recognised. A host that accumulates
	// these is one whose template is missing or has drifted.
	UnknownLabels []string
}

// Parse reads a WHOIS response into fields.
//
// It never fails: a response it cannot make sense of yields a Parsed with a low
// Confidence and whatever was recovered, because the raw text is always
// retained and a partial answer with an honest score beats an error.
func Parse(host string, raw []byte) *Parsed {
	p := &Parsed{Template: "heuristic", Fields: make(map[string][]string, 16)}
	if len(raw) == 0 {
		return p
	}

	tpl, hasTpl := Lookup(host)
	if hasTpl {
		p.Template = normalizeHostKey(host)
	}

	lines := strings.Split(string(raw), "\n")
	for i := 0; i < len(lines); i++ {
		label, value, ok := splitLine(lines[i])
		if !ok {
			continue
		}
		key := canonical(label, tpl)
		if key == "" {
			if isProseLabel(label) {
				continue
			}
			p.UnknownLabels = append(p.UnknownLabels, label)
			continue
		}
		if value == "" {
			// A bare "Label:" introduces an indented block, which is how
			// Nominet and several others lay out every field. Without this the
			// value silently vanishes and the parse looks merely incomplete.
			vals, consumed := continuationValues(lines[i+1:])
			for _, v := range vals {
				p.record(key, v)
			}
			i += consumed
			continue
		}
		p.record(key, value)
	}

	p.promote(tpl)
	p.Confidence = p.score(hasTpl)
	return p
}

// record stores a value, honouring the single- versus multi-valued rule.
func (p *Parsed) record(key, value string) {
	if value == "" {
		return
	}
	if multiValued[key] {
		p.Fields[key] = appendUnique(p.Fields[key], value)
		return
	}
	if _, seen := p.Fields[key]; !seen {
		p.Fields[key] = []string{value}
	}
}

// continuationValues collects the indented, colon-free lines that form the body
// of a bare "Label:" block, and reports how many lines were consumed.
//
// It stops at the first line that is unindented, empty, or contains a colon,
// because any of those starts something new — a section header, the next field,
// or the end of the block.
func continuationValues(rest []string) ([]string, int) {
	var vals []string
	consumed := 0
	for _, line := range rest {
		raw := strings.TrimRight(line, "\r")
		if strings.TrimSpace(raw) == "" {
			break
		}
		if !strings.HasPrefix(raw, " ") && !strings.HasPrefix(raw, "\t") {
			break
		}
		trimmed := strings.TrimSpace(raw)
		if strings.Contains(trimmed, ":") || strings.HasPrefix(trimmed, "%") || strings.HasPrefix(trimmed, "#") {
			break
		}
		vals = append(vals, trimmed)
		consumed++
		if consumed >= 20 { // a block this long is not a field
			break
		}
	}
	return vals, consumed
}

// promote copies the flat field map into typed members.
func (p *Parsed) promote(tpl Template) {
	p.DomainName = strings.ToLower(p.first(FDomain))
	p.RegistryDomainID = p.first(FRegistryDomainID)
	p.RegistrarName = p.first(FRegistrar)
	p.RegistrarURL = p.first(FRegistrarURL)
	p.AbuseEmail = strings.ToLower(p.first(FAbuseEmail))
	p.AbusePhone = p.first(FAbusePhone)

	if id := p.first(FRegistrarIANAID); id != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(id)); err == nil {
			p.RegistrarIANAID = n
		}
	}

	p.Statuses = p.Fields[FStatus]
	p.Nameservers = normalizeNameservers(p.Fields[FNameserver])

	if v := p.first(FDNSSEC); v != "" {
		p.DNSSECStated = true
		p.DNSSECSigned = dnssecSigned(v)
	}

	p.Created, p.Expires = p.date(FCreated, tpl), p.date(FExpires, tpl)
	p.Updated, p.Transferred = p.date(FUpdated, tpl), p.date(FTransferred, tpl)

	p.Registrant = p.contact("registrant", FRegistrantName, FRegistrantOrg, FRegistrantEmail, FRegistrantPhone, FRegistrantCountry)
	p.Admin = p.contact("administrative", FAdminName, "", FAdminEmail, "", "")
	p.Tech = p.contact("technical", FTechName, "", FTechEmail, "", "")
}

func (p *Parsed) date(field string, tpl Template) *time.Time {
	v := p.first(field)
	if v == "" {
		return nil
	}
	t, assumed, ok := ParseDate(v, tpl.DateLayouts...)
	if !ok {
		return nil
	}
	if assumed {
		p.TimezoneAssumed = true
	}
	return &t
}

func (p *Parsed) contact(role string, nameF, orgF, emailF, phoneF, countryF string) *Contact {
	get := func(f string) string {
		if f == "" {
			return ""
		}
		return p.first(f)
	}
	name, org := get(nameF), get(orgF)
	email, phone, country := get(emailF), get(phoneF), get(countryF)
	if name == "" && org == "" && email == "" && phone == "" && country == "" {
		return nil
	}
	c := &Contact{
		Role: role, Name: name, Organization: org,
		Email: strings.ToLower(email), Phone: phone, Country: strings.ToUpper(country),
	}
	// A redaction marker in any field means the registry is withholding, and
	// the marker itself is not a value: reporting "REDACTED FOR PRIVACY" as a
	// registrant name would be worse than reporting nothing.
	for _, v := range []string{name, org, email} {
		if marker, ok := redactionMarker(v); ok {
			c.Redacted = true
			c.Reason = marker
		}
	}
	if c.Redacted {
		if _, ok := redactionMarker(c.Name); ok {
			c.Name = ""
		}
		if _, ok := redactionMarker(c.Organization); ok {
			c.Organization = ""
		}
		if _, ok := redactionMarker(c.Email); ok {
			c.Email = ""
		}
	}
	return c
}

func (p *Parsed) first(field string) string {
	if vs := p.Fields[field]; len(vs) > 0 {
		return vs[0]
	}
	return ""
}

// score computes parse_confidence.
//
// The share of core fields recovered is the honest signal. A host template
// raises the ceiling because a template match means the labels were understood
// rather than guessed, and the floor is never zero for a response that yielded
// anything at all — a caller distinguishing "nothing parsed" from "a little
// parsed" needs those to differ.
func (p *Parsed) score(hasTemplate bool) float64 {
	found := 0
	for _, f := range coreFields {
		if len(p.Fields[f]) > 0 {
			found++
		}
	}
	if found == 0 {
		return 0
	}
	base := float64(found) / float64(len(coreFields))
	if hasTemplate {
		// Templated hosts get credit for being understood, capped at 1.0.
		base = base*0.9 + 0.1
	} else {
		// Heuristic parses are capped below 1.0: without a template we cannot
		// claim certainty even when every core field appeared.
		base *= 0.85
	}
	// Unrecognised labels suggest a drifted or missing template.
	if n := len(p.UnknownLabels); n > 0 {
		penalty := float64(n) * 0.01
		if penalty > 0.15 {
			penalty = 0.15
		}
		base -= penalty
	}
	if base < 0.05 {
		base = 0.05
	}
	if base > 1 {
		base = 1
	}
	return round2(base)
}

// canonical resolves a label to a canonical field, template first.
//
// A template entry mapping to "" means "recognised but deliberately dropped",
// which is how a registry's bookkeeping labels are silenced without them
// counting as unknown.
func canonical(label string, tpl Template) string {
	l := strings.ToLower(strings.TrimSpace(label))
	if tpl.Labels != nil {
		if f, ok := tpl.Labels[l]; ok {
			return f
		}
	}
	if f, ok := synonyms[l]; ok {
		return f
	}
	// Registries prefix labels with their own namespace ("Domain Name" vs
	// "domain name:"), and several use a leading "registrar " or "registry "
	// qualifier the synonym map already covers unqualified.
	for _, prefix := range []string{"registry ", "registrar ", "domain "} {
		if strings.HasPrefix(l, prefix) {
			if f, ok := synonyms[strings.TrimPrefix(l, prefix)]; ok {
				return f
			}
		}
	}
	return ""
}

// splitLine parses "label: value", rejecting the comment and banner lines that
// make up most of a WHOIS response.
func splitLine(line string) (label, value string, ok bool) {
	s := strings.TrimRight(line, "\r")
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return "", "", false
	}
	// % and # are comment markers; >>> wraps Verisign's timestamp footer.
	if strings.HasPrefix(trimmed, "%") || strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, ">>>") || strings.HasPrefix(trimmed, "--") {
		return "", "", false
	}
	// JPRS and a few others bracket the label and separate it from the value
	// with whitespace rather than a colon. Without this the whole response
	// yields nothing and the parse looks like an unreachable registry.
	if strings.HasPrefix(trimmed, "[") {
		if end := strings.Index(trimmed, "]"); end > 0 {
			return trimmed[:end+1], strings.TrimSpace(trimmed[end+1:]), true
		}
	}

	i := strings.Index(trimmed, ":")
	if i <= 0 {
		return "", "", false
	}
	label = strings.TrimSpace(trimmed[:i])
	value = strings.TrimSpace(trimmed[i+1:])
	// A label containing sentence punctuation is prose that happens to have a
	// colon, not a field.
	if strings.ContainsAny(label, ".!?") && !strings.HasPrefix(label, "[") {
		return "", "", false
	}
	if len(label) > 60 {
		return "", "", false
	}
	return label, value, true
}

// isProseLabel recognises the boilerplate sentences that survive splitLine —
// terms-of-use paragraphs whose first clause ends in a colon. Counting these as
// unknown labels would penalise every chatty registry's confidence score.
func isProseLabel(label string) bool {
	l := strings.ToLower(label)
	if strings.Count(l, " ") >= 5 {
		return true
	}
	for _, w := range []string{"notice", "terms of use", "by submitting", "important",
		"disclaimer", "copyright", "http", "https", "www", "for more information",
		"the data in", "this data is provided", "note", "warning"} {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}

// normalizeNameservers lowercases hosts and strips the glue addresses several
// registries append on the same line, which are not part of the hostname.
func normalizeNameservers(vs []string) []string {
	var out []string
	for _, v := range vs {
		h := strings.TrimSpace(v)
		// "ns1.example.com 192.0.2.1" or "ns1.example.com [192.0.2.1]"
		if i := strings.IndexAny(h, " \t["); i > 0 {
			h = h[:i]
		}
		h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
		if h == "" || !strings.Contains(h, ".") {
			continue
		}
		out = appendUnique(out, h)
	}
	return out
}

func dnssecSigned(v string) bool {
	l := strings.ToLower(strings.TrimSpace(v))
	switch {
	case strings.HasPrefix(l, "unsigned"), l == "no", l == "false", l == "unsigneddelegation",
		strings.Contains(l, "unsigned"), strings.Contains(l, "not signed"):
		return false
	case strings.HasPrefix(l, "signed"), l == "yes", l == "true", strings.Contains(l, "signeddelegation"),
		strings.Contains(l, "signed"):
		return true
	}
	return false
}

func redactionMarker(v string) (string, bool) {
	l := strings.ToLower(strings.TrimSpace(v))
	if l == "" {
		return "", false
	}
	for _, m := range redactionMarkers {
		if strings.Contains(l, m) {
			return m, true
		}
	}
	return "", false
}

func appendUnique(dst []string, v string) []string {
	for _, existing := range dst {
		if strings.EqualFold(existing, v) {
			return dst
		}
	}
	return append(dst, v)
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}
