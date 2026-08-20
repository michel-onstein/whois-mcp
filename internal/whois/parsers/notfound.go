package parsers

import "strings"

// Availability is the tri-state answer to "is this registered?", duplicated
// here rather than imported so this package stays free of the report types.
// The caller maps it onto normalize.Tristate.
type Availability string

// The three availability answers, mirroring normalize.Tristate.
const (
	Registered   Availability = "yes"
	Unregistered Availability = "no"
	Unknown      Availability = "unknown"
)

// notFoundSignatures are the phrases registries use to say "no such domain".
//
// This list is the most safety-critical data in the package. Matching too
// loosely turns a rate-limit notice or an error page into "this domain is
// free", which is the worst thing this server can tell anyone: someone acts on
// it, tries to register a domain that is taken, and at best wastes their time.
// So every entry is a phrase that only appears in a genuine negative answer,
// and anything unmatched falls through to Unknown rather than to a guess.
var notFoundSignatures = []string{
	"no match for",
	"no match",
	"not found",
	"no entries found",
	"no data found",
	"no object found",
	"nothing found",
	"domain not found",
	"domain is available",
	"is free",
	"status: free",
	"status: available",
	"status:             free",
	"object does not exist",
	"no such domain",
	"not registered",
	"no information available about",
	"domain unknown",
	"this domain name has not been registered",
	"the queried object does not exist",
	"available for registration",
	"free for registration",
	"no matching record",
	"we do not have an entry",
	"%% no entries found",
}

// registeredSignals are phrases that only appear when a record exists. They
// are checked first: several registries include the word "free" or a "not
// found" hint in boilerplate footers even while returning a real record, and a
// naive negative match on those responses would invert the answer.
var registeredSignals = []string{
	"registry expiry date",
	"expiry date",
	"expiration date",
	"creation date",
	"registered on",
	"registrar:",
	"sponsoring registrar",
	"name server",
	"nserver",
	"nameserver",
	"domain status",
	"registrant",
	"paid-till",
	"changed:",
}

// rateLimitSignatures mark a response that is a refusal, not an answer. These
// must never reach the not-found matcher: "query limit exceeded" contains no
// negative phrase today, but a future signature could overlap, and an explicit
// check documents that a throttled response is Unknown by intent.
var rateLimitSignatures = []string{
	"rate limit",
	"rate-limit",
	"limit exceeded",
	"too many requests",
	"query limit",
	"exceeded the maximum",
	"try again later",
	"access denied",
	"connection refused by",
	"blocked",
	"quota exceeded",
	"excessive querying",
}

// Classify determines registration status from a raw WHOIS response.
//
// Order matters and is the whole design: a rate-limit or an empty body is
// Unknown; a response carrying real record fields is Registered even if its
// footer contains stray negative wording; only a response with a genuine
// not-found phrase and no record fields is Unregistered. Anything else is
// Unknown, never a guess. See design §8.6.
func Classify(host string, raw []byte) Availability {
	if len(raw) == 0 {
		return Unknown
	}
	body := strings.ToLower(string(raw))

	if containsAny(body, rateLimitSignatures) {
		return Unknown
	}

	// Host-specific signatures win, because a registry that phrases its
	// negative unusually is exactly what the generic list misses.
	if tpl, ok := Lookup(host); ok {
		if containsAny(body, lower(tpl.NotFound)) {
			return Unregistered
		}
		if len(tpl.NotFound) > 0 && containsAny(body, lower(tpl.Registered)) {
			return Registered
		}
	}

	hasRecord := containsAny(body, registeredSignals)
	hasNegative := containsAny(body, notFoundSignatures)

	switch {
	case hasRecord && !hasNegative:
		return Registered
	case hasNegative && !hasRecord:
		return Unregistered
	case hasRecord && hasNegative:
		// Contradictory. A record plus negative boilerplate is far more often a
		// real record with a chatty footer than a free domain, but "far more
		// often" is not good enough to assert either way.
		return Unknown
	default:
		// Neither: an HTML error page, a banner with no data, a truncated
		// preamble. Nothing was learned.
		return Unknown
	}
}

func containsAny(haystack string, needles []string) bool {
	for _, n := range needles {
		if n != "" && strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

func lower(ss []string) []string {
	if len(ss) == 0 {
		return nil
	}
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strings.ToLower(s)
	}
	return out
}
