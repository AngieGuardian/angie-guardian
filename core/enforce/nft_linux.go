// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package enforce

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// Kernel object names inside the operator-configurable table. The sets are
// referenced from documentation and (in sets_only mode) from operator rules,
// so they are fixed, not configurable.
const (
	nftSet4Name  = "guardian_block4"
	nftSet6Name  = "guardian_block6"
	nftChainName = "guardian_drop"
)

// nftSink programs blocked IPs into kernel nftables sets over netlink
// (pure Go, no nft binary). Elements carry per-element timeouts equal to the
// block's remaining TTL, so a crashed daemon's blocks expire kernel-side. In
// managed mode the sink also owns a base chain whose single drop rule per
// family matches only the configured TCP ports: SSH and the admin listener
// are out of its reach by construction.
type nftSink struct {
	cfg NFTConfig
	log *slog.Logger

	// newConn is the connection factory; tests swap it for WithTestDial.
	newConn func() (*nftables.Conn, error)

	mu       sync.Mutex
	conn     *nftables.Conn
	netns    *os.File // held open for the sink's lifetime
	ready    bool     // table/sets/chain exist
	lastErr  string
	elements int
}

func newNFTSink(cfg NFTConfig, log *slog.Logger) (Sink, error) {
	s := &nftSink{cfg: cfg, log: log}
	if cfg.NetNS != "" {
		f, err := os.Open(cfg.NetNS)
		if err != nil {
			// A bad netns path never self-heals; refuse the sink outright so
			// the operator sees one clear error instead of a retry loop.
			return nil, fmt.Errorf("open netns %s: %w", cfg.NetNS, err)
		}
		s.netns = f
	}
	s.newConn = func() (*nftables.Conn, error) {
		if s.netns != nil {
			return nftables.New(nftables.WithNetNSFd(int(s.netns.Fd())))
		}
		return nftables.New()
	}
	// First setup attempt is best-effort: a permission error here is reported
	// unhealthy and retried on every reconcile tick.
	s.mu.Lock()
	if err := s.ensure(); err != nil {
		s.setErr(err)
		log.Warn("nftables setup failed, will retry on reconcile", "err", err)
	}
	s.mu.Unlock()
	return s, nil
}

func (s *nftSink) Name() string { return "nftables" }

func (s *nftSink) table() *nftables.Table {
	return &nftables.Table{Family: nftables.TableFamilyINet, Name: s.cfg.Table}
}

func (s *nftSink) setDef(name string) *nftables.Set {
	keyType := nftables.TypeIPAddr
	if name == nftSet6Name {
		keyType = nftables.TypeIP6Addr
	}
	return &nftables.Set{
		Table:      s.table(),
		Name:       name,
		KeyType:    keyType,
		HasTimeout: true,
		Size:       uint32(s.cfg.MaxEntries),
	}
}

// ensure idempotently creates the table, sets and (in managed mode) the drop
// chain. Callers hold s.mu. The chain is flushed and rebuilt because the sink
// owns it; that keeps repeated setup from duplicating rules.
func (s *nftSink) ensure() error {
	if s.ready {
		return nil
	}
	conn, err := s.newConn()
	if err != nil {
		return fmt.Errorf("netlink: %w", err)
	}
	table := s.table()
	conn.AddTable(table)
	set4, set6 := s.setDef(nftSet4Name), s.setDef(nftSet6Name)
	if err := conn.AddSet(set4, nil); err != nil {
		return fmt.Errorf("add set %s: %w", nftSet4Name, err)
	}
	if err := conn.AddSet(set6, nil); err != nil {
		return fmt.Errorf("add set %s: %w", nftSet6Name, err)
	}
	if s.cfg.Mode == "managed" {
		hook := nftables.ChainHookInput
		if s.cfg.Hook == "prerouting" {
			hook = nftables.ChainHookPrerouting
		}
		policy := nftables.ChainPolicyAccept
		chain := &nftables.Chain{
			Name: nftChainName, Table: table,
			Hooknum: hook, Priority: nftables.ChainPriorityFilter,
			Type: nftables.ChainTypeFilter, Policy: &policy,
		}
		conn.AddChain(chain)
		conn.FlushChain(chain)
		for _, fam := range []struct {
			nfproto      byte
			offset, size uint32
			set          *nftables.Set
		}{
			{unix.NFPROTO_IPV4, 12, 4, set4},
			{unix.NFPROTO_IPV6, 8, 16, set6},
		} {
			// Each rule gets its own anonymous constant port set (anonymous
			// sets are only valid within the batch that defines them).
			ports := &nftables.Set{Table: table, Anonymous: true, Constant: true, KeyType: nftables.TypeInetService}
			els := make([]nftables.SetElement, 0, len(s.cfg.Ports))
			for _, p := range s.cfg.Ports {
				els = append(els, nftables.SetElement{Key: binaryutil.BigEndian.PutUint16(p)})
			}
			if err := conn.AddSet(ports, els); err != nil {
				return fmt.Errorf("add port set: %w", err)
			}
			conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: []expr.Any{
				// <fam> saddr @guardian_blockN tcp dport { ports } drop
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{fam.nfproto}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: fam.offset, Len: fam.size},
				&expr.Lookup{SourceRegister: 1, SetName: fam.set.Name, SetID: fam.set.ID},
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Lookup{SourceRegister: 1, SetName: ports.Name, SetID: ports.ID},
				&expr.Verdict{Kind: expr.VerdictDrop},
			}})
		}
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nftables setup: %w", err)
	}
	s.conn = conn
	s.ready = true
	return nil
}

// skip filters what must never reach the kernel: loopback and link-local
// unconditionally, private / special-purpose ranges unless allow_private is
// set, the operator's never_block union (LB/CDN ranges plus every configured
// allowlist prefix), and blocks shorter than min_ttl.
func (s *nftSink) skip(a netip.Addr, ttl time.Duration) bool {
	if !a.IsValid() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() {
		return true
	}
	if !s.cfg.AllowPrivate && isPrivateOrSpecial(a) {
		return true
	}
	if ttl > 0 && ttl < s.cfg.MinTTL {
		return true
	}
	for _, p := range s.cfg.NeverBlock {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// isPrivateOrSpecial reports addresses that are almost never a real remote
// client and are dangerous to kernel-drop: RFC1918 / ULA private space
// (IsPrivate), plus unspecified, multicast, and the IPv4 CGNAT range
// 100.64.0.0/10 that netip does not classify as private. A block programmed for
// one of these usually means a trusted-proxy misconfiguration leaked an
// internal hop as the client IP, and dropping it blackholes real infrastructure.
func isPrivateOrSpecial(a netip.Addr) bool {
	if a.IsPrivate() || a.IsUnspecified() || a.IsMulticast() {
		return true
	}
	return cgnat4.Contains(a)
}

// cgnat4 is the IPv4 carrier-grade NAT shared address space (RFC 6598).
var cgnat4 = netip.MustParsePrefix("100.64.0.0/10")

// elementFor maps an address to its set name and raw key bytes.
func elementFor(a netip.Addr) (setName string, key []byte) {
	if a.Is4() {
		k := a.As4()
		return nftSet4Name, k[:]
	}
	k := a.As16()
	return nftSet6Name, k[:]
}

func (s *nftSink) Apply(ev BlockEvent) error {
	if !ev.Remove && s.skip(ev.IP, ev.TTL) {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensure(); err != nil {
		s.setErr(err)
		return err
	}
	setName, key := elementFor(ev.IP)
	set := s.setDef(setName)
	el := nftables.SetElement{Key: key, Timeout: max(ev.TTL, 0)}
	if ev.Remove {
		if err := s.conn.SetDeleteElements(set, []nftables.SetElement{{Key: key}}); err != nil {
			s.setErr(err)
			return err
		}
		if err := s.conn.Flush(); err != nil && !errors.Is(err, unix.ENOENT) {
			s.setErr(err)
			return err
		}
		return nil
	}
	if err := s.conn.SetAddElements(set, []nftables.SetElement{el}); err != nil {
		s.setErr(err)
		return err
	}
	err := s.conn.Flush()
	if errors.Is(err, unix.EEXIST) {
		// Re-block of a live element (backoff raised the TTL): replace it so
		// the new timeout takes effect.
		s.conn.SetDeleteElements(set, []nftables.SetElement{{Key: key}})
		s.conn.SetAddElements(set, []nftables.SetElement{el})
		err = s.conn.Flush()
	}
	if err != nil {
		s.setErr(err)
		return err
	}
	return nil
}

// Reconcile converges the kernel sets on the authoritative block list: adds
// what is missing, deletes what no longer exists, and repairs a previously
// failed setup (this is the retry path for missing capabilities). Existing
// elements keep their kernel timeout; only membership is corrected.
func (s *nftSink) Reconcile(active []ActiveBlock) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensure(); err != nil {
		s.setErr(err)
		return err
	}
	now := time.Now()
	desired := map[string]map[string]time.Duration{nftSet4Name: {}, nftSet6Name: {}}
	for _, b := range active {
		var ttl time.Duration // 0 = no kernel timeout (block without expiry)
		if !b.ExpiresAt.IsZero() {
			if ttl = b.ExpiresAt.Sub(now); ttl <= 0 {
				continue
			}
		}
		if s.skip(b.Addr, ttl) {
			continue
		}
		setName, key := elementFor(b.Addr)
		desired[setName][string(key)] = ttl
	}
	total := 0
	for _, setName := range []string{nftSet4Name, nftSet6Name} {
		set := s.setDef(setName)
		current, err := s.conn.GetSetElements(set)
		if err != nil {
			s.setErr(err)
			return fmt.Errorf("list %s: %w", setName, err)
		}
		want := desired[setName]
		var adds, dels []nftables.SetElement
		have := make(map[string]bool, len(current))
		for _, el := range current {
			k := string(el.Key)
			if _, ok := want[k]; ok {
				have[k] = true
			} else {
				dels = append(dels, nftables.SetElement{Key: el.Key})
			}
		}
		for k, ttl := range want {
			if !have[k] {
				adds = append(adds, nftables.SetElement{Key: []byte(k), Timeout: ttl})
			}
		}
		// Deletes and adds flush separately: an element can expire by its kernel
		// timeout between the read above and the delete flush, and the resulting
		// ENOENT would abort a combined batch, discarding the adds and (via
		// setErr) forcing a full re-setup on the next tick over a benign race.
		if len(dels) > 0 {
			if err := s.conn.SetDeleteElements(set, dels); err != nil {
				s.setErr(err)
				return err
			}
			if err := s.conn.Flush(); err != nil && !errors.Is(err, unix.ENOENT) {
				s.setErr(err)
				return fmt.Errorf("converge %s: %w", setName, err)
			}
		}
		if len(adds) > 0 {
			if err := s.conn.SetAddElements(set, adds); err != nil {
				s.setErr(err)
				return err
			}
			if err := s.conn.Flush(); err != nil {
				s.setErr(err)
				return fmt.Errorf("converge %s: %w", setName, err)
			}
		}
		total += len(want)
	}
	s.elements = total
	s.lastErr = ""
	return nil
}

func (s *nftSink) Status() SinkStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return SinkStatus{
		Name:      "nftables",
		Mode:      s.cfg.Mode,
		Healthy:   s.ready && s.lastErr == "",
		Elements:  s.elements,
		LastError: s.lastErr,
	}
}

// Close releases the netns handle. Kernel state is left in place on purpose:
// elements expire by their own timeouts, and tearing down the table on a
// restart would drop every active block for the daemon's downtime.
func (s *nftSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.netns != nil {
		return s.netns.Close()
	}
	return nil
}

// setErr records the last failure and drops readiness on connection-level
// errors so the next reconcile re-runs setup. Callers hold s.mu.
func (s *nftSink) setErr(err error) {
	s.lastErr = err.Error()
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.ECONNREFUSED) || errors.Is(err, unix.ENOENT) {
		s.ready = false
	}
}
