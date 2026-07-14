// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/intel/inteltest"
	"github.com/melroy89/angie-guardian/core/store"
)

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
geoip: { country_db: %s }
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
