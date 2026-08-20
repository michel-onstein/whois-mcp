package parsers

import (
	"strings"
	"time"
)

// dateLayouts are tried in order. The list is long because WHOIS dates are the
// least standardised part of an unstandardised format, and it is ordered
// most-specific-first: a layout with an offset must win over one that would
// silently assume UTC for the same string.
//
// Layouts carrying no zone are last, and matching one sets TimezoneAssumed on
// the result. That flag matters — an expiry date silently shifted by up to a
// day is exactly the kind of quiet wrongness an agent will act on.
var dateLayouts = []struct {
	layout string
	hasTZ  bool
}{
	{time.RFC3339Nano, true},
	{time.RFC3339, true},
	{"2006-01-02T15:04:05Z0700", true},
	{"2006-01-02T15:04:05-0700", true},
	{"2006-01-02 15:04:05-07", true},
	{"2006-01-02 15:04:05 MST", true},
	{"02-Jan-2006 15:04:05 MST", true},
	{"2006.01.02 15:04:05", false},
	{"2006-01-02T15:04:05", false},
	{"2006-01-02 15:04:05", false},
	{"2006-01-02 15:04", false},
	{"02-Jan-2006 15:04:05", false},
	{"02-Jan-2006", false},
	{"2-Jan-2006", false},
	{"02 Jan 2006", false},
	{"Mon Jan 2 15:04:05 2006", false},
	{"Mon Jan  2 15:04:05 2006", false},
	{"20060102", false},
	{"2006-01-02", false},
	{"2006/01/02", false},
	{"02.01.2006", false},
	{"02/01/2006", false},
	{"01/02/2006", false}, // US order, last: ambiguous with the line above
	{"2006-Jan-02", false},
}

// ParseDate interprets a WHOIS date value.
//
// The second return reports whether a timezone had to be assumed. A caller that
// ignores it will present a date it cannot actually justify to the hour.
func ParseDate(v string, extra ...string) (time.Time, bool, bool) {
	s := cleanDate(v)
	if s == "" {
		return time.Time{}, false, false
	}
	// Host-specific layouts first: a registry that uses an unusual order is
	// exactly the case the generic list gets wrong.
	for _, l := range extra {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), !hasZone(l), true
		}
	}
	for _, l := range dateLayouts {
		if t, err := time.Parse(l.layout, s); err == nil {
			if !l.hasTZ {
				// Reinterpret as UTC rather than shifting: time.Parse already
				// treats a zoneless value as UTC, so this is only about
				// reporting the assumption.
				return t.UTC(), true, true
			}
			return t.UTC(), false, true
		}
	}
	return time.Time{}, false, false
}

// cleanDate strips the noise registries append to dates: trailing annotations
// in parentheses, "(UTC)" suffixes that are not parseable zones, stray commas,
// and the "#" comments DENIC adds.
func cleanDate(v string) string {
	s := strings.TrimSpace(v)
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "#"); i >= 0 {
		s = s[:i]
	}
	// A parenthesised suffix is commentary, never part of the timestamp.
	if i := strings.Index(s, "("); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ",")
	// Some registries write "2020-01-02 UTC"; drop a bare UTC marker so the
	// zoneless layouts match, since UTC is what they mean and what we assume.
	for _, suffix := range []string{" UTC", " utc", " GMT", " gmt", " Z"} {
		if strings.HasSuffix(s, suffix) {
			s = strings.TrimSpace(strings.TrimSuffix(s, suffix))
			break
		}
	}
	return strings.TrimSpace(s)
}

func hasZone(layout string) bool {
	return strings.ContainsAny(layout, "Z") || strings.Contains(layout, "-07") ||
		strings.Contains(layout, "MST")
}
