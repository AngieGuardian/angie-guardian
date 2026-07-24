// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package enforce

import (
	"bytes"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
)

// dialCapture builds a sink whose netlink traffic is captured instead of
// sent to the kernel (nftables.WithTestDial), so message-level behavior is
// testable without privileges.
func dialCapture(t *testing.T, cfg NFTConfig) (*nftSink, *[][]byte) {
	t.Helper()
	var captured [][]byte
	s := &nftSink{cfg: cfg, log: slog.New(slog.DiscardHandler)}
	s.newConn = func() (*nftables.Conn, error) {
		return nftables.New(nftables.WithTestDial(
			func(req []netlink.Message) ([]netlink.Message, error) {
				for _, msg := range req {
					b, err := msg.MarshalBinary()
					if err != nil {
						t.Fatal(err)
					}
					captured = append(captured, b)
				}
				return req, nil
			}))
	}
	return s, &captured
}

func anyContains(msgs [][]byte, needle []byte) bool {
	for _, m := range msgs {
		if bytes.Contains(m, needle) {
			return true
		}
	}
	return false
}

func nftTestConfig() NFTConfig {
	return NFTConfig{
		Enabled: true, Mode: "managed", Table: "guardian", Hook: "input",
		Ports: []uint16{80, 443}, MaxEntries: 1024,
	}
}

func TestNFTSkipPrivateAndSpecialRanges(t *testing.T) {
	addr := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	// Default (allow_private off): private, CGNAT, ULA, unspecified, multicast,
	// loopback and link-local are all withheld from the kernel; real routable
	// clients are offloaded.
	def := &nftSink{cfg: nftTestConfig(), log: slog.New(slog.DiscardHandler)}
	for _, ip := range []string{
		"10.1.2.3", "192.168.0.9", "172.16.5.5", "100.100.0.1", // RFC1918 + CGNAT
		"fd00::1", "::", "224.0.0.1", "127.0.0.1", "169.254.1.1", // ULA, unspecified, multicast, loopback, link-local
	} {
		if !def.skip(addr(ip), time.Hour) {
			t.Errorf("skip(%s) = false, want true (must not kernel-drop internal/special space)", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "2606:4700::1111"} {
		if def.skip(addr(ip), time.Hour) {
			t.Errorf("skip(%s) = true, want false (a routable client must be offloaded)", ip)
		}
	}

	// allow_private opt-in: private space reaches the kernel, but loopback and
	// link-local remain unconditionally excluded.
	cfg := nftTestConfig()
	cfg.AllowPrivate = true
	priv := &nftSink{cfg: cfg, log: slog.New(slog.DiscardHandler)}
	if priv.skip(addr("10.1.2.3"), time.Hour) {
		t.Error("allow_private: RFC1918 address must be offloaded")
	}
	if !priv.skip(addr("127.0.0.1"), time.Hour) {
		t.Error("allow_private must not override the unconditional loopback exclusion")
	}
}

func TestNFTEnsureManagedCreatesTableSetsChain(t *testing.T) {
	s, captured := dialCapture(t, nftTestConfig())
	s.mu.Lock()
	err := s.ensure()
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"guardian", nftSet4Name, nftSet6Name, nftChainName} {
		if !anyContains(*captured, []byte(name)) {
			t.Errorf("setup batch never mentions %q", name)
		}
	}
	// The port set elements ride in big-endian inet_service encoding.
	if !anyContains(*captured, []byte{0x01, 0xbb}) { // 443
		t.Error("setup batch does not carry port 443")
	}
}

func TestNFTEnsureSetsOnlySkipsChain(t *testing.T) {
	cfg := nftTestConfig()
	cfg.Mode = "sets_only"
	s, captured := dialCapture(t, cfg)
	s.mu.Lock()
	err := s.ensure()
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if anyContains(*captured, []byte(nftChainName)) {
		t.Error("sets_only mode must not create the managed chain")
	}
	if !anyContains(*captured, []byte(nftSet4Name)) || !anyContains(*captured, []byte(nftSet6Name)) {
		t.Error("sets_only mode must still create both sets")
	}
}

func TestNFTApplyAddsElementWithKey(t *testing.T) {
	s, captured := dialCapture(t, nftTestConfig())
	if err := s.Apply(BlockEvent{IP: netip.MustParseAddr("203.0.113.9"), Reason: "x", TTL: time.Minute}); err != nil {
		t.Fatal(err)
	}
	if !anyContains(*captured, []byte{203, 0, 113, 9}) {
		t.Error("add batch does not carry the element key bytes")
	}
	// An IPv6 block lands in the v6 set.
	*captured = nil
	v6 := netip.MustParseAddr("2001:db8::7")
	if err := s.Apply(BlockEvent{IP: v6, Reason: "x", TTL: time.Minute}); err != nil {
		t.Fatal(err)
	}
	k := v6.As16()
	if !anyContains(*captured, k[:]) {
		t.Error("v6 add batch does not carry the 16-byte key")
	}
}

func TestNFTApplySkipsProtectedAddresses(t *testing.T) {
	cfg := nftTestConfig()
	cfg.NeverBlock = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	cfg.MinTTL = 30 * time.Second
	s, captured := dialCapture(t, cfg)
	s.mu.Lock()
	if err := s.ensure(); err != nil {
		t.Fatal(err)
	}
	s.mu.Unlock()
	*captured = nil

	cases := []struct {
		name string
		ev   BlockEvent
	}{
		{"loopback", BlockEvent{IP: netip.MustParseAddr("127.0.0.1"), TTL: time.Minute}},
		{"v6 loopback", BlockEvent{IP: netip.MustParseAddr("::1"), TTL: time.Minute}},
		{"link-local", BlockEvent{IP: netip.MustParseAddr("169.254.1.1"), TTL: time.Minute}},
		{"never_block", BlockEvent{IP: netip.MustParseAddr("192.0.2.55"), TTL: time.Minute}},
		{"below min_ttl", BlockEvent{IP: netip.MustParseAddr("203.0.113.9"), TTL: time.Second}},
	}
	for _, tc := range cases {
		if err := s.Apply(tc.ev); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(*captured) != 0 {
			t.Fatalf("%s: protected address reached the kernel batch", tc.name)
		}
	}
	// A block without expiry (TTL 0) must NOT be dropped by the min_ttl
	// filter: it is the longest-lived block there is.
	if err := s.Apply(BlockEvent{IP: netip.MustParseAddr("203.0.113.10"), TTL: 0}); err != nil {
		t.Fatal(err)
	}
	if len(*captured) == 0 {
		t.Fatal("no-expiry block was skipped")
	}
}

func TestNFTStatusUnhealthyOnFailure(t *testing.T) {
	s, _ := dialCapture(t, nftTestConfig())
	st := s.Status()
	if st.Name != "nftables" || st.Mode != "managed" {
		t.Fatalf("status = %+v", st)
	}
	s.mu.Lock()
	s.setErr(errTest)
	s.mu.Unlock()
	if s.Status().Healthy {
		t.Fatal("sink with a recorded error reports healthy")
	}
}

var errTest = errorString("boom")

type errorString string

func (e errorString) Error() string { return string(e) }
