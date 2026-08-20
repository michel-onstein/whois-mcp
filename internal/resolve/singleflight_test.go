package resolve

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qjam/whois-mcp/internal/normalize"
)

func TestTTLPolicyFor(t *testing.T) {
	p := DefaultTTLPolicy
	if got := p.For(normalize.Yes); got != time.Hour {
		t.Errorf("registered TTL = %v; want 1h", got)
	}
	if got := p.For(normalize.No); got != 5*time.Minute {
		t.Errorf("unregistered TTL = %v; want 5m", got)
	}
	if got := p.For(normalize.Unknown); got != time.Minute {
		t.Errorf("unknown TTL = %v; want 1m", got)
	}
}

// TestDefaultTTLPolicyIsOrdered guards the relationship rather than the
// numbers: caching "unknown" as long as "registered" would pin a transient
// rate-limit as the answer, and nothing downstream would complain.
func TestDefaultTTLPolicyIsOrdered(t *testing.T) {
	if !DefaultTTLPolicy.Valid() {
		t.Error("the default policy has a non-positive entry")
	}
	if !DefaultTTLPolicy.Ordered() {
		t.Error("the default policy caches an ambiguous answer longer than a certain one")
	}
}

func TestWithTTLPolicyRejectsBadPolicies(t *testing.T) {
	r := &Resolver{policy: DefaultTTLPolicy}

	if err := r.WithTTLPolicy(TTLPolicy{}); err == nil {
		t.Error("an all-zero policy was accepted; that disables caching")
	}
	// Inverted: unknown cached longer than registered.
	inverted := TTLPolicy{
		Registered: time.Minute, Unregistered: time.Minute, Unknown: time.Hour,
		Raw: time.Minute, Bootstrap: time.Hour,
	}
	if err := r.WithTTLPolicy(inverted); err == nil {
		t.Error("an inverted policy was accepted")
	}
	// A valid override is applied.
	good := TTLPolicy{
		Registered: 2 * time.Hour, Unregistered: 10 * time.Minute, Unknown: 30 * time.Second,
		Raw: 5 * time.Minute, Bootstrap: 12 * time.Hour,
	}
	if err := r.WithTTLPolicy(good); err != nil {
		t.Fatalf("a valid policy was refused: %v", err)
	}
	if got := r.policy.For(normalize.Yes); got != 2*time.Hour {
		t.Errorf("override not applied: %v", got)
	}
}

func TestFlightKeySeparatesWhatMustNotBeShared(t *testing.T) {
	fresh := Options{MaxAge: 0}
	cached := Options{MaxAge: time.Hour}
	if flightKey("example.com", fresh) == flightKey("example.com", cached) {
		t.Error("a forced-fresh lookup shares a key with a cache-tolerant one; that defeats max_age_seconds=0")
	}

	withRef := Options{MaxAge: time.Hour}
	noRef := Options{MaxAge: time.Hour, SkipRegistrarReferral: true}
	if flightKey("example.com", withRef) == flightKey("example.com", noRef) {
		t.Error("availability and full lookups share a key; one would get the other's answer")
	}
	if flightKey("a.com", cached) == flightKey("b.com", cached) {
		t.Error("different domains share a key")
	}
	// Options that do not change the upstream answer must not split the key, or
	// collapsing never happens for the common case.
	contacts := Options{MaxAge: time.Hour, IncludeContacts: true}
	if flightKey("example.com", contacts) != flightKey("example.com", cached) {
		t.Error("IncludeContacts split the flight key; it only filters the response")
	}
}

// TestSingleflightCollapsesConcurrentLookups is the behaviour design §9 asks
// for: an agent fanning out across overlapping candidate names must not produce
// duplicate queries to the same registry in the same second.
func TestSingleflightCollapsesConcurrentLookups(t *testing.T) {
	var upstreamCalls atomic.Int64
	release := make(chan struct{})

	registry := whoisServerFunc(t, func() string {
		upstreamCalls.Add(1)
		<-release // hold the call open so the others pile up behind it
		return "Domain Name: collapse.test\r\nRegistrar: Someone\r\n" +
			"Creation Date: 2020-01-01T00:00:00Z\r\nDomain Status: ok\r\n" +
			"Name Server: ns1.example-dns.test\r\n"
	})
	r := fallbackResolver(t, ianaFake(t, registry))

	const callers = 8
	var wg sync.WaitGroup
	results := make([]*normalize.DomainReport, callers)
	errs := make([]error, callers)
	for i := range callers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = r.Lookup(context.Background(), "collapse.test",
				Options{MaxAge: time.Hour, IncludeContacts: true})
		}(i)
	}
	// Give every caller time to arrive before letting the upstream answer.
	time.Sleep(150 * time.Millisecond)
	close(release)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
		if results[i] == nil {
			t.Fatalf("caller %d got no report", i)
		}
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Errorf("%d upstream calls for %d concurrent identical lookups; want 1", got, callers)
	}
}

// TestSingleflightGivesEachCallerItsOwnCopy guards a real aliasing bug:
// collapsed callers must not share one report, or one caller's
// include_contacts=false would blank the entities the others asked for.
func TestSingleflightGivesEachCallerItsOwnCopy(t *testing.T) {
	release := make(chan struct{})
	registry := whoisServerFunc(t, func() string {
		<-release
		return "Domain Name: shared.test\r\nRegistrant Name: Someone Real\r\n" +
			"Registrar: R\r\nCreation Date: 2020-01-01T00:00:00Z\r\n" +
			"Domain Status: ok\r\nName Server: ns1.example-dns.test\r\n"
	})
	r := fallbackResolver(t, ianaFake(t, registry))

	var wg sync.WaitGroup
	var withContacts, withoutContacts *normalize.DomainReport
	wg.Add(2)
	go func() {
		defer wg.Done()
		withContacts, _ = r.Lookup(context.Background(), "shared.test",
			Options{MaxAge: time.Hour, IncludeContacts: true})
	}()
	go func() {
		defer wg.Done()
		withoutContacts, _ = r.Lookup(context.Background(), "shared.test",
			Options{MaxAge: time.Hour, IncludeContacts: false})
	}()
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()

	if withContacts == nil || withoutContacts == nil {
		t.Fatal("a caller got no report")
	}
	if withContacts == withoutContacts {
		t.Fatal("both callers received the same report pointer")
	}
	if len(withContacts.Entities) == 0 {
		t.Error("the include_contacts caller lost its entities to the other caller's filtering")
	}
	if len(withoutContacts.Entities) != 0 {
		t.Error("the exclude_contacts caller received entities")
	}
}
