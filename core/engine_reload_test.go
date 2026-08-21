// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/intel/inteltest"
	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/core/store"
)

func TestEngineReloadSwapsHeaderExemptionsAtomically(t *testing.T) {
	base := `
store: { backend: memory }
signing_key_file: test-signing.key
defaults:
  pow: { enabled: true, base_difficulty: 1, max_difficulty: 2 }
`
	enabled := `
store: { backend: memory }
signing_key_file: test-signing.key
defaults:
  pow:
    enabled: true
    base_difficulty: 1
    max_difficulty: 2
    header_exemptions: [ { header: X-Machine-Key, require_value: true } ]
`
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	key, err := pow.LoadOrCreateKey(filepath.Join(t.TempDir(), "pow.key"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(loadTestConfig(t, base), st, pow.NewManager(key, st), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	r := req("x.test", "198.51.100.80", "/", "curl")
	r.Header = func(name string) []string {
		if name == "X-Machine-Key" {
			return []string{"opaque"}
		}
		return nil
	}
	if d := e.Evaluate(t.Context(), r); d.Action != ActionChallenge {
		t.Fatalf("before reload = %s/%s, want challenge", d.Action, d.Reason)
	}
	if err := e.Reload(loadTestConfig(t, enabled)); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(t.Context(), r); d.Action != ActionAllow || d.Reason != "default" {
		t.Fatalf("after reload = %s/%s, want allow/default", d.Action, d.Reason)
	}

	// A reload whose optional verifier key is private material fails before the
	// snapshot swap, and the last good shape-only policy remains active.
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	privateFile := filepath.Join(t.TempDir(), "application-private.pem")
	if err := os.WriteFile(privateFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	invalid := fmt.Sprintf(`
store: { backend: memory }
signing_key_file: test-signing.key
defaults:
  pow:
    enabled: true
    header_exemptions:
      - header: X-Machine-Key
        require_value: true
        verifier: { type: jwt_eddsa, public_keys: [ %q ], issuer: issuer, audience: api, max_lifetime: 15m }
`, privateFile)
	if err := e.Reload(loadTestConfig(t, invalid)); err == nil {
		t.Fatal("reload accepted application private key")
	}
	if d := e.Evaluate(t.Context(), r); d.Action != ActionAllow || d.Reason != "default" {
		t.Fatalf("failed reload replaced active policy: %s/%s", d.Action, d.Reason)
	}
}

// reloadedYAML flips the pipelineYAML policy: the old denylist is gone and
// 198.51.100.0/24 (allowed before) is now denied.
const reloadedYAML = `
store: { backend: memory }
defaults:
  waf:
    ip_behaviour: { enabled: true, block_ttl: 15m }
  denylist:
    ips: [ "198.51.100.0/24" ]
`

// TestEngineReload: Reload atomically swaps the active config, so the same
// request flips decisions, while behavioural state in the store survives.
func TestEngineReload(t *testing.T) {
	ctx := context.Background()
	cfg := loadTestConfig(t, pipelineYAML)
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	e, err := NewEngine(cfg, st, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)

	newlyDenied := req("x.test", "198.51.100.7", "/page", "Mozilla")
	oldDenied := req("x.test", "203.0.113.9", "/page", "Mozilla")
	if d := e.Evaluate(ctx, newlyDenied); d.Action != ActionAllow {
		t.Fatalf("before reload: got %s (%s), want allow", d.Action, d.Reason)
	}
	if d := e.Evaluate(ctx, oldDenied); d.Action != ActionDeny {
		t.Fatalf("before reload: got %s (%s), want deny", d.Action, d.Reason)
	}

	// A behavioural block placed before the reload must survive it: that
	// state lives in the store, not in the config snapshot.
	if err := e.BlockIP(ctx, "192.0.2.55", "test", time.Minute); err != nil {
		t.Fatal(err)
	}

	next := loadTestConfig(t, reloadedYAML)
	if err := e.Reload(next); err != nil {
		t.Fatal(err)
	}

	if got := e.Config(); got != next {
		t.Errorf("Config() = %p, want the reloaded config %p", got, next)
	}
	if d := e.Evaluate(ctx, newlyDenied); d.Action != ActionDeny {
		t.Errorf("after reload: got %s (%s), want deny (new denylist)", d.Action, d.Reason)
	}
	if d := e.Evaluate(ctx, oldDenied); d.Action != ActionAllow {
		t.Errorf("after reload: got %s (%s), want allow (old denylist dropped)", d.Action, d.Reason)
	}
	if _, blocked, err := e.BlockStatus(ctx, "192.0.2.55"); err != nil || !blocked {
		t.Errorf("block did not survive reload: blocked=%v err=%v", blocked, err)
	}
}

func TestEngineReloadPreservesLoadedURLReputationFeed(t *testing.T) {
	var available atomic.Bool
	available.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !available.Load() {
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("203.0.113.0/24\n"))
	}))
	defer srv.Close()

	cfg := loadTestConfig(t, fmt.Sprintf(`
store: { backend: memory }
reputation:
  feeds:
    - { name: remote-deny, url: %q, refresh: 1m, action: deny }
defaults:
  reputation: { enabled: true }
`, srv.URL))
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	e, err := NewEngine(cfg, st, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)

	r := req("x.test", "203.0.113.7", "/", "Mozilla")
	deadline := time.Now().Add(5 * time.Second)
	for {
		if d := e.Evaluate(t.Context(), r); d.Action == ActionDeny && d.Reason == "reputation:remote-deny" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("initial URL reputation feed never loaded")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// A reload must not replace the loaded deny set with an empty provider just
	// because URL refresh is asynchronous and the source is currently down.
	available.Store(false)
	if err := e.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(t.Context(), r); d.Action != ActionDeny || d.Reason != "reputation:remote-deny" {
		t.Fatalf("reload dropped last good URL feed: got %s/%s", d.Action, d.Reason)
	}
}

type reloadBlockingResolver struct {
	started chan struct{}
	release chan struct{}
}

func (r *reloadBlockingResolver) LookupAddr(context.Context, string) ([]string, error) {
	close(r.started)
	<-r.release
	return nil, &net.DNSError{Err: "temporary failure", IsTemporary: true}
}

func (*reloadBlockingResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return nil, &net.DNSError{Err: "temporary failure", IsTemporary: true}
}

func TestReloadKeepsInflightSnapshotResourcesAlive(t *testing.T) {
	db := inteltest.WriteCountryDB(t, t.TempDir(), map[string]string{"198.51.100.0/24": "NL"})
	cfg := loadTestConfig(t, fmt.Sprintf(`
store: { backend: memory }
geoip: { location_db: %s }
defaults:
  verified_bots:
    dns_timeout: 1m
    bots: [ { name: googlebot } ]
  geo:
    enabled: true
    deny: { countries: [ NL ] }
`, db))
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	e, err := NewEngine(cfg, st, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)

	resolver := &reloadBlockingResolver{started: make(chan struct{}), release: make(chan struct{})}
	e.BotVerifier().SetResolver(resolver)
	oldSnapshot := e.snap.Load()
	decisions := make(chan Decision, 1)
	go func() {
		decisions <- e.Evaluate(context.Background(), req("x.test", "198.51.100.7", "/", googlebotUA))
	}()

	select {
	case <-resolver.started:
	case <-time.After(5 * time.Second):
		t.Fatal("request never entered bot DNS verification")
	}
	if err := e.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	if got := oldSnapshot.refs.Load(); got != 1 {
		t.Fatalf("retired snapshot refs = %d, want one in-flight owner", got)
	}
	if got := oldSnapshot.intel.Lookup(netip.MustParseAddr("198.51.100.7")).Country; got != "NL" {
		t.Fatalf("retired snapshot resources closed before evaluator released: country=%q", got)
	}
	close(resolver.release)

	select {
	case d := <-decisions:
		if d.Action != ActionDeny || d.Reason != "geo:country:NL" {
			t.Fatalf("in-flight request lost its old snapshot resources: got %s/%s", d.Action, d.Reason)
		}
		if got := oldSnapshot.refs.Load(); got != 0 {
			t.Fatalf("retired snapshot refs after request = %d, want zero", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request did not complete")
	}
}
