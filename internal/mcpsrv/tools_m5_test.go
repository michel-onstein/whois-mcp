package mcpsrv

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/qjam/whois-mcp/internal/cache"
	"github.com/qjam/whois-mcp/internal/normalize"
	"github.com/qjam/whois-mcp/internal/rdapx"
	"github.com/qjam/whois-mcp/internal/resolve"
)

// netTestServer builds a server with ip_lookup enabled, pointing the RIR
// lookups at a local fake.
func netTestServer(t *testing.T, handler http.HandlerFunc) (*mcp.Server, Options) {
	t.Helper()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	upstream := httptest.NewServer(handler)
	t.Cleanup(upstream.Close)

	reg, err := rdapx.NewRegistryForTest(map[string][]string{"uk": {"https://rdap.invalid/"}})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	netReg, err := rdapx.NewNetRegistryForTest(upstream.URL + "/")
	if err != nil {
		t.Fatalf("net registry: %v", err)
	}
	hc := rdapx.NewHTTPClientWithOptions(5*time.Second, rdapx.HTTPClientOptions{AllowPrivateAddresses: true})
	res := resolve.New(rdapx.NewClient(reg, hc, "test"), nil, cache.NewMemory(), quiet).
		WithNetRegistry(netReg)

	opt := Options{Resolver: res, Registry: reg, Log: quiet, NetLookups: true}
	return New(opt), opt
}

const ipNetworkJSON = `{
  "objectClassName": "ip network",
  "handle": "NET-8-8-8-0-1",
  "startAddress": "8.8.8.0",
  "endAddress": "8.8.8.255",
  "ipVersion": "v4",
  "name": "GOGL",
  "type": "DIRECT ALLOCATION",
  "country": "us",
  "parentHandle": "NET-8-0-0-0-0",
  "status": ["active"],
  "events": [{"eventAction": "registration", "eventDate": "2009-03-30T00:00:00Z"}],
  "entities": [{"objectClassName": "entity", "handle": "GOGL", "roles": ["registrant"]}]
}`

const autnumJSON = `{
  "objectClassName": "autnum",
  "handle": "AS15169",
  "startAutnum": 15169,
  "endAutnum": 15169,
  "name": "GOOGLE",
  "type": "DIRECT ALLOCATION",
  "country": "us",
  "status": ["active"],
  "events": [{"eventAction": "registration", "eventDate": "2000-03-30T00:00:00Z"}]
}`

func rdapJSON(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = io.WriteString(w, body)
	}
}

func TestIPLookupAddress(t *testing.T) {
	_, opt := netTestServer(t, rdapJSON(ipNetworkJSON))

	_, rep, err := ipLookupHandler(opt)(context.Background(), nil, IPLookupInput{Resource: "8.8.8.8"})
	if err != nil {
		t.Fatalf("ip_lookup: %v", err)
	}
	if rep == nil {
		t.Fatal("no report")
	}
	if rep.Kind != string(rdapx.KindIP) {
		t.Errorf("Kind = %q; want ip", rep.Kind)
	}
	if rep.Handle != "NET-8-8-8-0-1" || rep.Name != "GOGL" {
		t.Errorf("handle/name = %q/%q", rep.Handle, rep.Name)
	}
	if rep.StartAddress != "8.8.8.0" || rep.EndAddress != "8.8.8.255" {
		t.Errorf("range = %s-%s", rep.StartAddress, rep.EndAddress)
	}
	if rep.Country != "US" {
		t.Errorf("Country = %q; want it upper-cased", rep.Country)
	}
	if rep.ParentHandle != "NET-8-0-0-0-0" {
		t.Errorf("ParentHandle = %q", rep.ParentHandle)
	}
	if rep.Dates.Created == nil || rep.Dates.Created.Year() != 2009 {
		t.Errorf("Created = %v", rep.Dates.Created)
	}
	if rep.Source.Protocol != normalize.ProtoRDAP || rep.Source.ParseConfidence != 1.0 {
		t.Errorf("Source = %+v; RDAP is structured and should score 1.0", rep.Source)
	}
}

func TestIPLookupASN(t *testing.T) {
	_, opt := netTestServer(t, rdapJSON(autnumJSON))

	for _, input := range []string{"AS15169", "as15169", "15169"} {
		t.Run(input, func(t *testing.T) {
			_, rep, err := ipLookupHandler(opt)(context.Background(), nil, IPLookupInput{Resource: input})
			if err != nil {
				t.Fatalf("ip_lookup: %v", err)
			}
			if rep.Kind != "asn" {
				t.Errorf("Kind = %q; want asn", rep.Kind)
			}
			if rep.ASNRange != "15169" {
				t.Errorf("ASNRange = %q; want 15169 for a single-value allocation", rep.ASNRange)
			}
			if rep.Query.Normalized != "AS15169" {
				t.Errorf("Normalized = %q; want AS15169 regardless of input spelling", rep.Query.Normalized)
			}
		})
	}
}

func TestIPLookupPrefix(t *testing.T) {
	_, opt := netTestServer(t, rdapJSON(ipNetworkJSON))
	_, rep, err := ipLookupHandler(opt)(context.Background(), nil, IPLookupInput{Resource: "8.8.8.0/24"})
	if err != nil {
		t.Fatalf("ip_lookup: %v", err)
	}
	if rep.Kind != string(rdapx.KindPrefix) {
		t.Errorf("Kind = %q; want prefix", rep.Kind)
	}
	if rep.Query.Normalized != "8.8.8.0/24" {
		t.Errorf("Normalized = %q", rep.Query.Normalized)
	}
}

// TestIPLookupRejectsPrivateSpaceWithoutAnUpstreamCall is the behaviour the
// IANA data drove: private ranges fall inside broader RIR entries, so without
// the local check we would spend a request on a third party to learn nothing.
func TestIPLookupRejectsPrivateSpaceWithoutAnUpstreamCall(t *testing.T) {
	var calls int
	_, opt := netTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = io.WriteString(w, ipNetworkJSON)
	})

	for _, s := range []string{"192.168.1.1", "10.0.0.1", "127.0.0.1", "169.254.169.254", "fd00::1"} {
		t.Run(s, func(t *testing.T) {
			res, rep, err := ipLookupHandler(opt)(context.Background(), nil, IPLookupInput{Resource: s})
			if err != nil {
				t.Fatalf("unexpected transport error: %v", err)
			}
			if rep != nil {
				t.Errorf("got a report for %s: %+v", s, rep)
			}
			if res == nil || !res.IsError {
				t.Fatalf("%s did not produce an error result", s)
			}
			assertToolErrorCode(t, res, "unallocated_resource")
		})
	}
	if calls != 0 {
		t.Errorf("%d upstream requests made for private space; want 0", calls)
	}
}

func TestIPLookupInvalidInput(t *testing.T) {
	_, opt := netTestServer(t, rdapJSON(ipNetworkJSON))
	for _, s := range []string{"", "   ", "example.com", "not an address", "999.999.999.999"} {
		res, rep, err := ipLookupHandler(opt)(context.Background(), nil, IPLookupInput{Resource: s})
		if err != nil {
			t.Fatalf("unexpected transport error for %q: %v", s, err)
		}
		if rep != nil {
			t.Errorf("got a report for %q", s)
		}
		if res == nil || !res.IsError {
			t.Fatalf("%q did not produce an error result", s)
		}
	}
}

// TestIPLookupNotRegisteredWithoutNetRegistry: an absent tool is better than a
// present one that always fails.
func TestIPLookupNotRegisteredWithoutNetRegistry(t *testing.T) {
	srv, _ := newTestServer(t) // NetLookups is false there
	ctx := context.Background()

	client := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer cs.Close()

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	for _, tl := range tools.Tools {
		if tl.Name == "ip_lookup" {
			t.Error("ip_lookup is registered with no IP/ASN registry configured")
		}
	}
}

func TestIPLookupIsRegisteredWhenEnabled(t *testing.T) {
	srv, _ := netTestServer(t, rdapJSON(ipNetworkJSON))
	ctx := context.Background()

	client := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer cs.Close()

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var found *mcp.Tool
	for _, tl := range tools.Tools {
		if tl.Name == "ip_lookup" {
			found = tl
		}
	}
	if found == nil {
		t.Fatal("ip_lookup is not registered")
	}
	// The country caveat belongs in the description, because that is what a
	// model reads before deciding how to present the field.
	if !strings.Contains(strings.ToLower(found.Description), "not geolocation") {
		t.Errorf("description does not warn that country is not geolocation: %q", found.Description)
	}
}

// TestSummarizeNetLabelsCountryHonestly: the registered country is
// administrative, and an agent that presents it as a host's location is wrong.
func TestSummarizeNetLabelsCountryHonestly(t *testing.T) {
	created := time.Date(2009, 3, 30, 0, 0, 0, 0, time.UTC)
	rep := &normalize.NetReport{
		Query: normalize.NetQuery{Input: "8.8.8.8", Normalized: "8.8.8.8"},
		Kind:  "ip", Name: "GOGL", Country: "US",
		StartAddress: "8.8.8.0", EndAddress: "8.8.8.255", IPVersion: "v4",
		Type: "DIRECT ALLOCATION", Statuses: []string{"active"},
		Dates:  normalize.Dates{Created: &created},
		Source: normalize.Source{Protocol: normalize.ProtoRDAP, Servers: []string{"https://rdap.arin.net/"}, Cache: "miss"},
	}
	got := summarizeNet(rep)

	if !strings.Contains(got, "administrative, not the location") {
		t.Errorf("summary presents country without the caveat:\n%s", got)
	}
	for _, want := range []string{"8.8.8.8", "GOGL", "8.8.8.0", "DIRECT ALLOCATION", "active"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary lacks %q:\n%s", want, got)
		}
	}
}

func TestNetErrorResultCodes(t *testing.T) {
	cases := map[string]error{
		"invalid_resource":     fmt.Errorf("%w: x", rdapx.ErrInvalidResource),
		"unallocated_resource": fmt.Errorf("%w: x", rdapx.ErrNoRDAPForResource),
		"not_configured":       resolve.ErrNoNetRegistry,
		"upstream_timeout":     context.DeadlineExceeded,
		"cancelled":            context.Canceled,
		"internal_error":       errors.New("something else"),
	}
	for want, err := range cases {
		res := netErrorResult("8.8.8.8", err)
		if res == nil || !res.IsError {
			t.Fatalf("%v did not produce an error result", err)
		}
		assertToolErrorCode(t, res, want)
	}
}
