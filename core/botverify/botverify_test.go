// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package botverify

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/store"
)

// fakeResolver serves PTR and forward lookups from maps and counts calls.
type fakeResolver struct {
	ptr     map[string][]string // ip -> PTR hostnames (as returned, may have trailing dot)
	fwd     map[string][]string // hostname (lowercase, no dot) -> IPs
	ptrErr  map[string]error
	fwdErr  map[string]error
	ptrCall atomic.Int64
	delay   time.Duration
}

func (f *fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	f.ptrCall.Add(1)
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	if err, ok := f.ptrErr[addr]; ok {
		return nil, err
	}
	hosts, ok := f.ptr[addr]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
	}
	return hosts, nil
}

func (f *fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if err, ok := f.fwdErr[host]; ok {
		return nil, err
	}
	ips, ok := f.fwd[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	out := make([]net.IPAddr, len(ips))
	for i, s := range ips {
		out[i] = net.IPAddr{IP: net.ParseIP(s)}
	}
	return out, nil
}

func newTestVerifier(t *testing.T, r Resolver) *Verifier {
	t.Helper()
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	v := New(st, slog.Default())
	v.SetResolver(r)
	return v
}

func TestVerifyConfirmed(t *testing.T) {
	r := &fakeResolver{
		ptr: map[string][]string{"66.249.66.1": {"Crawl-66-249-66-1.Googlebot.com."}},
		fwd: map[string][]string{"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"}},
	}
	v := newTestVerifier(t, r)

	res := v.Verify(context.Background(), "66.249.66.1", Options{})
	if res.Status != StatusConfirmed {
		t.Fatalf("status = %v, want confirmed", res.Status)
	}
	if len(res.Hostnames) != 1 || res.Hostnames[0] != "crawl-66-249-66-1.googlebot.com" {
		t.Fatalf("hostnames = %v", res.Hostnames)
	}
	if !res.MatchesDomains([]string{"googlebot.com", "google.com"}) {
		t.Error("should match googlebot.com")
	}
	if res.MatchesDomains([]string{"search.msn.com"}) {
		t.Error("should not match search.msn.com")
	}
	// "oglebot.com" is not a parent domain of the hostname, only a suffix.
	if res.MatchesDomains([]string{"oglebot.com"}) {
		t.Error("suffix match must be label-aligned")
	}
}

func TestVerifyForwardMismatchIsDefinitive(t *testing.T) {
	// Attacker controls their PTR and points it at googlebot.com, but the
	// forward record resolves elsewhere.
	r := &fakeResolver{
		ptr: map[string][]string{"203.0.113.9": {"fake.googlebot.com."}},
		fwd: map[string][]string{"fake.googlebot.com": {"198.51.100.1"}},
	}
	v := newTestVerifier(t, r)
	if res := v.Verify(context.Background(), "203.0.113.9", Options{}); res.Status != StatusNone {
		t.Fatalf("status = %v, want none", res.Status)
	}
}

func TestVerifyNoPTRIsDefinitive(t *testing.T) {
	v := newTestVerifier(t, &fakeResolver{})
	if res := v.Verify(context.Background(), "203.0.113.9", Options{}); res.Status != StatusNone {
		t.Fatalf("status = %v, want none", res.Status)
	}
}

// TestVerifyInvalidIP: a garbage RemoteAddr means the transport is
// misconfigured, not that the client is an impostor. Unknown identity, so
// the pipeline falls through instead of spoof-denying (matching the
// denylist stage, which fails open on an unparseable IP).
func TestVerifyInvalidIP(t *testing.T) {
	v := newTestVerifier(t, &fakeResolver{})
	if res := v.Verify(context.Background(), "not-an-ip", Options{}); res.Status != StatusError {
		t.Fatalf("status = %v, want error (unknown identity)", res.Status)
	}
}

func TestVerifyTransientErrors(t *testing.T) {
	timeout := &net.DNSError{Err: "i/o timeout", IsTimeout: true}
	t.Run("ptr", func(t *testing.T) {
		r := &fakeResolver{ptrErr: map[string]error{"203.0.113.9": timeout}}
		v := newTestVerifier(t, r)
		if res := v.Verify(context.Background(), "203.0.113.9", Options{}); res.Status != StatusError {
			t.Fatalf("status = %v, want error", res.Status)
		}
	})
	t.Run("forward", func(t *testing.T) {
		r := &fakeResolver{
			ptr:    map[string][]string{"203.0.113.9": {"crawl.googlebot.com."}},
			fwdErr: map[string]error{"crawl.googlebot.com": timeout},
		}
		v := newTestVerifier(t, r)
		// A flaky forward lookup must not brand the IP an impostor.
		if res := v.Verify(context.Background(), "203.0.113.9", Options{}); res.Status != StatusError {
			t.Fatalf("status = %v, want error", res.Status)
		}
	})
}

func TestVerifyCaches(t *testing.T) {
	r := &fakeResolver{
		ptr: map[string][]string{"66.249.66.1": {"crawl.googlebot.com."}},
		fwd: map[string][]string{"crawl.googlebot.com": {"66.249.66.1"}},
	}
	v := newTestVerifier(t, r)
	ctx := context.Background()

	for range 3 {
		if res := v.Verify(ctx, "66.249.66.1", Options{}); res.Status != StatusConfirmed {
			t.Fatalf("status = %v, want confirmed", res.Status)
		}
	}
	if n := r.ptrCall.Load(); n != 1 {
		t.Errorf("PTR lookups = %d, want 1 (cache hit expected)", n)
	}

	// Negative results are cached too.
	for range 3 {
		if res := v.Verify(ctx, "203.0.113.9", Options{}); res.Status != StatusNone {
			t.Fatalf("status = %v, want none", res.Status)
		}
	}
	if n := r.ptrCall.Load(); n != 2 {
		t.Errorf("PTR lookups = %d, want 2", n)
	}
}

func TestVerifyDeduplicatesConcurrentLookups(t *testing.T) {
	r := &fakeResolver{
		ptr:   map[string][]string{"66.249.66.1": {"crawl.googlebot.com."}},
		fwd:   map[string][]string{"crawl.googlebot.com": {"66.249.66.1"}},
		delay: 50 * time.Millisecond,
	}
	v := newTestVerifier(t, r)

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if res := v.Verify(context.Background(), "66.249.66.1", Options{}); res.Status != StatusConfirmed {
				t.Errorf("status = %v, want confirmed", res.Status)
			}
		})
	}
	wg.Wait()
	if n := r.ptrCall.Load(); n != 1 {
		t.Errorf("PTR lookups = %d, want 1 (in-flight dedup expected)", n)
	}
}

func TestVerifyMappedIPv4Forward(t *testing.T) {
	// Forward lookups often return the 16-byte IPv4-in-IPv6 form; the
	// comparison must unmap both sides.
	r := &fakeResolver{
		ptr: map[string][]string{"66.249.66.1": {"crawl.googlebot.com."}},
		fwd: map[string][]string{"crawl.googlebot.com": {"::ffff:66.249.66.1"}},
	}
	v := newTestVerifier(t, r)
	if res := v.Verify(context.Background(), "66.249.66.1", Options{}); res.Status != StatusConfirmed {
		t.Fatalf("status = %v, want confirmed", res.Status)
	}
}
