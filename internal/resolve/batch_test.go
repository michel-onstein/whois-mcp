package resolve

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qjam/whois-mcp/internal/normalize"
	"github.com/qjam/whois-mcp/internal/whois/whoistest"
)

// TestBatchDeduplicatesBeforeDispatch is M5's batch tuning. A candidate-name
// batch routinely repeats entries; singleflight would collapse concurrent
// duplicates anyway, but deduplicating first also stops them consuming batch
// concurrency slots.
func TestBatchDeduplicatesBeforeDispatch(t *testing.T) {
	var queries atomic.Int64
	registry := whoisServerFunc(t, func() string {
		queries.Add(1)
		return "Domain Name: dup.test\r\nRegistrar: R\r\n" +
			"Creation Date: 2020-01-01T00:00:00Z\r\nDomain Status: ok\r\n" +
			"Name Server: ns1.example-dns.test\r\n"
	})
	r := fallbackResolver(t, ianaFake(t, registry))

	// The same name six ways, plus one distinct name.
	domains := []string{
		"dup.test", "dup.test", " dup.test ", "DUP.TEST", "dup.test", "dup.test",
		"other.test",
	}
	out := r.CheckAvailability(context.Background(), domains, 0)

	if len(out) != len(domains) {
		t.Fatalf("got %d results for %d inputs; the caller aligns them positionally", len(out), len(domains))
	}
	// Two distinct names: the IANA fake is asked per TLD, and the registry once
	// per distinct domain.
	if got := queries.Load(); got > 2 {
		t.Errorf("%d registry queries for 2 distinct names; deduplication is not working", got)
	}
	// Every duplicate carries the same answer.
	for i, res := range out[:6] {
		if res.Registered != out[0].Registered {
			t.Errorf("result %d = %q; want the same answer as its duplicates (%q)", i, res.Registered, out[0].Registered)
		}
	}
	// And the echoed domain is per-input rather than blanked.
	for i, res := range out {
		if res.Domain == "" && res.Error == "" {
			t.Errorf("result %d has neither a domain nor an error", i)
		}
	}
}

func TestBatchPreservesOrderAndCap(t *testing.T) {
	registry := whoisServerFunc(t, func() string {
		return "No match for \"x\".\r\n"
	})
	r := fallbackResolver(t, ianaFake(t, registry))

	domains := make([]string, MaxBatch+10)
	for i := range domains {
		domains[i] = "name" + strings.Repeat("x", i%3) + ".test"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out := r.CheckAvailability(ctx, domains, 0)
	if len(out) != MaxBatch {
		t.Errorf("got %d results; want the %d cap", len(out), MaxBatch)
	}
}

// TestBatchOneBadNameDoesNotFailTheRest: a typo in a fifty-name batch must not
// force the caller to bisect their own request.
func TestBatchOneBadNameDoesNotFailTheRest(t *testing.T) {
	registry := whoisServerFunc(t, func() string {
		return "No match for \"free\".\r\n"
	})
	r := fallbackResolver(t, ianaFake(t, registry))

	out := r.CheckAvailability(context.Background(),
		[]string{"good.test", "not a domain at all", "alsogood.test"}, 0)

	if len(out) != 3 {
		t.Fatalf("got %d results; want 3", len(out))
	}
	if out[1].Error == "" {
		t.Error("the bad name carries no error")
	}
	if out[1].Registered != normalize.Unknown {
		t.Errorf("bad name Registered = %q; want unknown", out[1].Registered)
	}
	for _, i := range []int{0, 2} {
		if out[i].Error != "" {
			t.Errorf("result %d failed because of an unrelated bad input: %s", i, out[i].Error)
		}
		if out[i].Registered != normalize.No {
			t.Errorf("result %d Registered = %q; want no", i, out[i].Registered)
		}
	}
}

func TestBatchEmptyStringIsItsOwnError(t *testing.T) {
	registry := whoisServerFunc(t, func() string { return "No match.\r\n" })
	r := fallbackResolver(t, ianaFake(t, registry))

	out := r.CheckAvailability(context.Background(), []string{"", "   "}, 0)
	if len(out) != 2 {
		t.Fatalf("got %d results; want 2", len(out))
	}
	for i, res := range out {
		if res.Error == "" {
			t.Errorf("result %d: an empty input produced no error", i)
		}
	}
}

var _ = whoistest.ModeNormal // keep the import meaningful if helpers move
