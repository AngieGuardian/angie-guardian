// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/botverify"
	"github.com/melroy89/angie-guardian/core/enforce"
	"github.com/melroy89/angie-guardian/core/store"
)

type botShedStore struct {
	store.Store
	fail bool
}

func (s *botShedStore) Get(ctx context.Context, key string) ([]byte, bool, error) {
	if s.fail {
		return nil, false, errors.New("offline")
	}
	return s.Store.Get(ctx, key)
}
func (s *botShedStore) GetWithExpiry(ctx context.Context, key string) (store.KV, bool, error) {
	if s.fail {
		return store.KV{}, false, errors.New("offline")
	}
	return s.Store.(store.ExpiryReader).GetWithExpiry(ctx, key)
}
func (s *botShedStore) Set(ctx context.Context, key string, v []byte, ttl time.Duration) error {
	if s.fail {
		return errors.New("offline")
	}
	return s.Store.Set(ctx, key, v, ttl)
}

type botShedOps struct{ calls atomic.Int64 }

func (r *botShedOps) StoreOp(string, float64, error) { r.calls.Add(1) }

type botShedResolver struct {
	botverify.Resolver
	calls atomic.Int64
}

func (r *botShedResolver) LookupAddr(ctx context.Context, ip string) ([]string, error) {
	r.calls.Add(1)
	return r.Resolver.LookupAddr(ctx, ip)
}
func (r *botShedResolver) LookupIPAddr(ctx context.Context, h string) ([]net.IPAddr, error) {
	r.calls.Add(1)
	return r.Resolver.LookupIPAddr(ctx, h)
}

func attachSeededBotMirror(t *testing.T, e *Engine) {
	t.Helper()
	enf := enforce.New(e.Config().EnforceConfig(), e.store, nil, slog.Default())
	t.Cleanup(func() { enf.Close() })
	e.SetEnforcer(enf)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	enf.Start(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for !enf.Status().Mirror.Seeded {
		if time.Now().After(deadline) {
			t.Fatal("mirror not seeded")
		}
		time.Sleep(time.Millisecond)
	}
	if enf.ReadThrough() {
		t.Fatal("mirror not authoritative")
	}
}

func TestVerifiedCrawlerShedEnforcement(t *testing.T) {
	for _, host := range []string{"site.test", "lenient.test"} {
		for _, tc := range []struct {
			suffix string
			want   ShedVerdict
		}{
			{"items", ShedPass}, {"challenge-secret", ShedDeny}, {"challenge-scanner", ShedDeny}, {"trap", ShedDeny}, {"deny-path", ShedDeny}, {"explicit-allow-secret", ShedPass},
		} {
			t.Run(host+"/"+tc.suffix, func(t *testing.T) {
				raw := &botShedStore{Store: store.NewMemory()}
				ops := &botShedOps{}
				e := allowlistExemptionEngineWithStore(t, true, false, store.Instrument(raw, ops))
				attachSeededBotMirror(t, e)
				resolver := &botShedResolver{Resolver: &stubResolver{ptr: map[string][]string{"198.51.100.42": {"crawl.googlebot.com."}}, fwd: map[string][]string{"crawl.googlebot.com": {"198.51.100.42"}}}}
				e.bots.SetResolver(resolver)
				r := sourceRequest("bot", "items")
				r.Host = host
				r.Cookie = "guardian_token=" + mintTestToken(t, e.pow, r.Host, r.RemoteAddr, r.UserAgent, 4)
				// Warm through the ordinary pipeline, then compare the security verdict.
				if d := e.Evaluate(t.Context(), r); d.PoWExemption != "verified_bot:googlebot" {
					t.Fatalf("warm: %+v", d)
				}
				cookie := r.Cookie
				r = sourceRequest("bot", tc.suffix)
				r.Host = host
				r.Cookie = cookie
				full := e.Evaluate(t.Context(), r)
				if tc.want == ShedDeny && full.Action != ActionDeny {
					t.Fatalf("normal did not deny: %+v", full)
				}
				raw.fail = true
				before, dns := ops.calls.Load(), resolver.calls.Load()
				if got := e.ShedDecision(r); got != tc.want {
					t.Fatalf("normal=%+v shed=%v want=%v", full, got, tc.want)
				}
				if ops.calls.Load() != before || resolver.calls.Load() != dns {
					t.Fatal("overload accessed store or DNS")
				}
				r = sourceRequest("bot", "items")
				r.Host = host
				if got := e.ShedDecision(r); got != ShedReject {
					t.Fatal("crawler exemption admitted without token")
				}
				if ops.calls.Load() != before || resolver.calls.Load() != dns {
					t.Fatal("tokenless overload accessed store or DNS")
				}
			})
		}
	}
}
func TestCrawlerShedUnknownAndSpoofPolicies(t *testing.T) {
	for _, host := range []string{"site.test", "lenient.test"} {
		for _, identity := range []string{"cold", "negative", "wrong-domain", "error"} {
			t.Run(host+"/"+identity, func(t *testing.T) {
				ops := &botShedOps{}
				e := allowlistExemptionEngineWithStore(t, true, false, store.Instrument(store.NewMemory(), ops))
				attachSeededBotMirror(t, e)
				stub := &stubResolver{}
				switch identity {
				case "wrong-domain":
					stub.ptr = map[string][]string{"198.51.100.42": {"crawler.example.org."}}
					stub.fwd = map[string][]string{"crawler.example.org": {"198.51.100.42"}}
				case "error":
					stub.err = map[string]error{"198.51.100.42": &net.DNSError{Err: "timeout", IsTimeout: true}}
				}
				resolver := &botShedResolver{Resolver: stub}
				e.bots.SetResolver(resolver)
				r := sourceRequest("bot", "items")
				r.Host = host
				r.Cookie = "guardian_token=" + mintTestToken(t, e.pow, r.Host, r.RemoteAddr, r.UserAgent, 4)
				if identity != "cold" {
					e.Evaluate(t.Context(), r)
				}
				want := ShedReject
				if identity == "negative" || identity == "wrong-domain" {
					want = ShedDeny
					if host == "lenient.test" {
						want = ShedPass
					}
				}
				before, dns := ops.calls.Load(), resolver.calls.Load()
				if got := e.ShedDecision(r); got != want {
					t.Fatalf("got %v want %v", got, want)
				}
				if ops.calls.Load() != before || resolver.calls.Load() != dns {
					t.Fatal("unknown/spoof lookup accessed store or DNS")
				}
			})
		}
	}
}
func TestCachedCrawlerReloadAndBan(t *testing.T) {
	e := allowlistExemptionEngine(t, true, false)
	attachSeededBotMirror(t, e)
	r := sourceRequest("bot", "items")
	r.Cookie = "guardian_token=" + mintTestToken(t, e.pow, r.Host, r.RemoteAddr, r.UserAgent, 4)
	e.Evaluate(t.Context(), r)
	if err := e.BlockIP(t.Context(), r.RemoteAddr, "admin", time.Minute); err != nil {
		t.Fatal(err)
	}
	if got := e.ShedDecision(r); got != ShedDeny {
		t.Fatal("identity bypassed admin ban")
	}
	if _, err := e.UnblockIP(t.Context(), r.RemoteAddr, false); err != nil {
		t.Fatal(err)
	}
	// A cached googlebot hostname must not carry yesterday's allowed-domain verdict.
	cfg := loadTestConfig(t, `store: {backend: memory}
signing_key_file: test.key
defaults:
 verified_bots:
  bots: [{name: googlebot, domains: [example.org]}]
 pow: {enabled: true, base_difficulty: 1, max_difficulty: 6}
`)
	if err := e.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	if got := e.ShedDecision(r); got != ShedDeny {
		t.Fatal("reload reused stale crawler exemption")
	}
	if d := e.Evaluate(t.Context(), r); d.Reason != "bot_spoof:googlebot" {
		t.Fatalf("normal reload: %+v", d)
	}
}
