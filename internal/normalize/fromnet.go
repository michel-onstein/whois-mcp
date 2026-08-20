package normalize

import (
	"strconv"
	"strings"
	"time"

	"github.com/openrdap/rdap"
)

// NetReport is the canonical record for an IP network or an autonomous system.
//
// It is a separate type from DomainReport rather than a widened version of it,
// because almost nothing overlaps: an IP allocation has no registrar, no
// nameservers, no DNSSEC and no expiry, while it does have a parent range and an
// allocation type that a domain has no analogue for. Forcing both into one shape
// would mean most fields being empty most of the time, and an agent unable to
// tell "absent" from "not applicable".
type NetReport struct {
	Query NetQuery `json:"query"`
	// Kind is ip, prefix, or asn.
	Kind string `json:"kind"`
	// Handle is the RIR's identifier for the registration.
	Handle string `json:"handle,omitempty"`
	// Name is the network or AS name the holder chose.
	Name string `json:"name,omitempty"`
	// StartAddress and EndAddress bound an IP allocation.
	StartAddress string `json:"start_address,omitempty"`
	EndAddress   string `json:"end_address,omitempty"`
	// ASNRange is the allocation for an ASN lookup, as "start-end".
	ASNRange string `json:"asn_range,omitempty"`
	// IPVersion is v4 or v6 for an address lookup.
	IPVersion string `json:"ip_version,omitempty"`
	// Type is the RIR's allocation type: ALLOCATED PA, ASSIGNED PI, and so on.
	Type string `json:"type,omitempty"`
	// Country is the registered country, which is administrative rather than
	// geographic: it says who registered the range, not where the addresses are
	// used. Worth saying, because it is routinely misread as geolocation.
	Country  string   `json:"country,omitempty"`
	Statuses []string `json:"statuses,omitempty"`
	// ParentHandle names the covering allocation, which is what makes a
	// sub-allocation's context visible.
	ParentHandle string `json:"parent_handle,omitempty"`

	Dates    Dates    `json:"dates"`
	Entities []Entity `json:"entities,omitempty"`
	Source   Source   `json:"source"`
	Warnings []string `json:"warnings,omitempty"`
}

// NetQuery echoes how the input was interpreted.
type NetQuery struct {
	Input string `json:"input" jsonschema:"the raw input as supplied by the caller"`
	// Normalized is what was actually queried: an address, a CIDR, or ASnnnn.
	Normalized string `json:"normalized"`
}

// FromRDAPIPNetwork maps an RDAP IP network onto the report.
func FromRDAPIPNetwork(q NetQuery, kind string, n *rdap.IPNetwork, servers []string, fetchedAt time.Time, cacheState string) *NetReport {
	rep := &NetReport{
		Query: q, Kind: kind,
		Source: Source{
			Protocol: ProtoRDAP, Servers: servers,
			FetchedAt: fetchedAt.UTC(), Cache: cacheState,
			ParseConfidence: 1.0, RawAvailable: true,
		},
	}
	if n == nil {
		rep.Warnings = append(rep.Warnings, "the RIR returned no network object")
		return rep
	}

	rep.Handle = n.Handle
	rep.Name = n.Name
	rep.StartAddress = n.StartAddress
	rep.EndAddress = n.EndAddress
	rep.IPVersion = n.IPVersion
	rep.Type = n.Type
	rep.Country = strings.ToUpper(n.Country)
	rep.Statuses = n.Status
	rep.ParentHandle = n.ParentHandle
	rep.Dates, rep.Warnings = datesFromEvents(n.Events, rep.Warnings)
	rep.Entities = entitiesFrom(n.Entities)
	return rep
}

// FromRDAPAutnum maps an RDAP autnum onto the report.
func FromRDAPAutnum(q NetQuery, a *rdap.Autnum, servers []string, fetchedAt time.Time, cacheState string) *NetReport {
	rep := &NetReport{
		Query: q, Kind: "asn",
		Source: Source{
			Protocol: ProtoRDAP, Servers: servers,
			FetchedAt: fetchedAt.UTC(), Cache: cacheState,
			ParseConfidence: 1.0, RawAvailable: true,
		},
	}
	if a == nil {
		rep.Warnings = append(rep.Warnings, "the RIR returned no autnum object")
		return rep
	}

	rep.Handle = a.Handle
	rep.Name = a.Name
	rep.Type = a.Type
	rep.Country = strings.ToUpper(a.Country)
	rep.Statuses = a.Status
	if a.StartAutnum != nil && a.EndAutnum != nil {
		rep.ASNRange = formatASNRange(*a.StartAutnum, *a.EndAutnum)
	}

	rep.Dates, rep.Warnings = datesFromEvents(a.Events, rep.Warnings)
	rep.Entities = entitiesFrom(a.Entities)
	return rep
}

// entitiesFrom maps RDAP entities, reusing the domain path's vCard handling so
// redaction is detected identically. An IP allocation's contacts are as much
// personal data as a domain's, and are withheld just as often.
func entitiesFrom(in []rdap.Entity) []Entity {
	var out []Entity
	for _, e := range in {
		ent, _ := entityFromRDAP(e)
		if ent != nil {
			out = append(out, *ent)
		}
	}
	return out
}

func formatASNRange(start, end uint32) string {
	if start == end {
		return strconv.FormatUint(uint64(start), 10)
	}
	return strconv.FormatUint(uint64(start), 10) + "-" + strconv.FormatUint(uint64(end), 10)
}
