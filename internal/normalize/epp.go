package normalize

import (
	"strings"
	"unicode"
)

// eppStatusMeaning expands EPP status codes into plain language. Agents
// otherwise have to guess what "clientTransferProhibited" implies, and the
// guess is often wrong in a way that misleads a user (it is a normal lock, not
// a sign of a problem).
var eppStatusMeaning = map[string]string{
	"ok":                       "Standard status: the domain is active with no pending operations or restrictions",
	"active":                   "The domain is active",
	"inactive":                 "The domain has no nameservers delegated and will not resolve",
	"clientHold":               "Registrar has asked the registry to not activate the domain in DNS; it will not resolve",
	"serverHold":               "Registry is not activating the domain in DNS; it will not resolve",
	"clientDeleteProhibited":   "Registrar has locked the domain against deletion",
	"serverDeleteProhibited":   "Registry has locked the domain against deletion",
	"clientRenewProhibited":    "Registrar has locked the domain against renewal",
	"serverRenewProhibited":    "Registry has locked the domain against renewal",
	"clientTransferProhibited": "Registrar has locked the domain against transfer to another registrar (a normal anti-hijacking default, not a problem)",
	"serverTransferProhibited": "Registry has locked the domain against transfer",
	"clientUpdateProhibited":   "Registrar has locked the domain against updates",
	"serverUpdateProhibited":   "Registry has locked the domain against updates",
	"pendingCreate":            "A create request is pending at the registry",
	"pendingDelete":            "The domain is scheduled for deletion; it may be in redemption or the pending-delete window",
	"pendingRenew":             "A renewal request is pending",
	"pendingRestore":           "A restore request from redemption is pending",
	"pendingTransfer":          "A transfer to another registrar is pending",
	"pendingUpdate":            "An update request is pending",
	"redemption period":        "The domain has been deleted and is in the redemption grace period; the previous registrant may still restore it",
	"renew period":             "The domain is within the grace period following a renewal",
	"transfer period":          "The domain is within the grace period following a transfer",
	"add period":               "The domain is within the grace period following initial registration",
	"auto renew period":        "The domain is within the grace period following an automatic renewal",
	"associated":               "The object is associated with another object",
	"validated":                "The registrant's contact details have been validated",
}

// statusKey collapses the two spellings of the same status into one lookup
// key. RFC 9083 §10.2.2 defines RDAP status values as space-separated
// lowercase ("client transfer prohibited"), while EPP and most WHOIS output
// use camelCase ("clientTransferProhibited"). They mean the same thing, and a
// map keyed on only one form silently matches nothing for half the sources.
func statusKey(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == ' ' || r == '_' || r == '-' {
			continue
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

// normalizedStatusMeaning is eppStatusMeaning re-keyed by statusKey.
var normalizedStatusMeaning = func() map[string]string {
	out := make(map[string]string, len(eppStatusMeaning))
	for k, v := range eppStatusMeaning {
		out[statusKey(k)] = v
	}
	return out
}()

// StatusMeanings returns plain-language expansions for the status codes it
// recognises, accepting either the RDAP or the EPP spelling. Unknown codes are
// omitted rather than invented.
func StatusMeanings(statuses []string) map[string]string {
	if len(statuses) == 0 {
		return nil
	}
	out := make(map[string]string, len(statuses))
	for _, s := range statuses {
		if m, ok := normalizedStatusMeaning[statusKey(s)]; ok {
			out[s] = m
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
