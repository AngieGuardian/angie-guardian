// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package pow

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"
)

// Per-host-and-IP difficulty escalation for clients that keep requesting challenges
// without ever solving them. The issuance rate limit caps how fast an IP can
// farm challenges and pow_fail scoring punishes wrong solutions, but a client
// that fetches interstitials and simply discards them stays at base
// difficulty forever. This counter closes that gap: every issuance counts
// against the host+IP pair, a successful redemption clears that pair, and
// past a small allowance each further unsolved issuance raises the demanded
// work.
//
// Escalation is only the first half of the farming defence. Raising the work
// has a ceiling (the domain max_difficulty), and a client happy to keep
// fetching and discarding will sit at that ceiling indefinitely. Once the
// escalation alone pins it there, the caller reports a challenge_farm
// scoreboard event and the waf.ip_behaviour threshold blocks outright; see
// the BumpEscalation call site in transport/http/server.go.
const (
	// escalationFreeIssues is how many unsolved challenges a client may
	// accumulate before escalation starts. Covers honest bursts: several
	// tabs opened at once, reloads of the interstitial, a laptop lid closed
	// mid-solve.
	escalationFreeIssues = 4

	// escalationStep is how many unsolved issuances past the allowance buy
	// one extra leading-zero bit, i.e. every escalationStep abandoned
	// challenges double the work of the next one.
	escalationStep = 2
)

// The two counter prefixes. They are separate key spaces, not a shared one
// with a marker inside, so no hostname can ever be mistaken for the marker.
const (
	escalationPrefix      = "chesc:"
	frameEscalationPrefix = "chfesc:"
)

func escalationKey(prefix, host, ip string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	// SplitHostPort allocates an *AddrError for input without a port, and a
	// Host header carrying no port is the overwhelmingly common case; a port
	// separator always contains a colon, so guard the call (same reasoning as
	// stateless.NormalizeHost).
	if strings.IndexByte(host, ':') >= 0 {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	// Unmap an IPv4-mapped IPv6 address ("::ffff:1.2.3.4" -> "1.2.3.4"), which
	// is what a dual-stack listener hands the transport for an IPv4 client.
	// Without it these counters key the same client differently from the block
	// key and the behaviour counters, which both canonicalize (core.canonIP),
	// and an admin reset reconstructing the key would miss. Only the mapped
	// form is rewritten: every other address already arrives in the same
	// textual form netip would print, so the common path pays a parse and no
	// allocation. This runs once per challenge issuance.
	if addr, err := netip.ParseAddr(ip); err == nil && addr.Is4In6() {
		ip = addr.Unmap().String()
	}
	return prefix + host + ":" + ip
}

// ForgetEscalation clears both escalation counters for one host+IP pair. A
// solve proves the client is not discarding interstitials, whichever context it
// arrived in, so redemption resets both.
//
// This is the redemption path, so the shared copies are deleted in the
// background like any other counter flush. An operator reset that has to report
// what it achieved wants ResetEscalation.
//
// Nil-safe: PoW may not be configured at all.
func (m *Manager) ForgetEscalation(host, ip string) {
	if m == nil {
		return
	}
	m.counters.Forget(escalationKey(escalationPrefix, host, ip))
	m.counters.Forget(escalationKey(frameEscalationPrefix, host, ip))
}

// ResetEscalation is ForgetEscalation for an operator lifting a block: same two
// counters, but the shared copies are deleted synchronously and the outcome is
// reported, so an unblock cannot claim an escalation was cleared when the
// delete failed, never enqueued under flush-queue saturation, or landed on a
// key the counter cache had shed into its overload sketch. In all three the
// local count resets while the shared one survives for the next flush to merge
// back over the reset, and the operator would have been told otherwise.
//
// Returns how many of the two counters were actually cleared. Nil-safe.
func (m *Manager) ResetEscalation(ctx context.Context, host, ip string) (keys int, err error) {
	if m == nil {
		return 0, nil
	}
	for _, prefix := range [...]string{escalationPrefix, frameEscalationPrefix} {
		if e := m.counters.ForgetSync(ctx, escalationKey(prefix, host, ip)); e != nil {
			err = errors.Join(err, e)
			continue
		}
		keys++
	}
	return keys, err
}

// BumpEscalation counts one challenge issuance against host+ip and returns
// the extra leading-zero bits the challenge being issued should carry. The
// counter lives for window (the challenge TTL: the span in which the earlier
// challenges could still have been solved) from the first unsolved issuance,
// and a successful redemption clears only that host+IP pair (see Redeem).
// The result is unbounded; the caller clamps the final difficulty to the
// domain ceiling.
//
// The count goes through the CounterCache, so issuance never blocks on a
// store write for it: the local count answers, the shared store counter is
// flushed in the background, and a store failure degrades to per-instance
// escalation rather than taking the challenge path down.
func (m *Manager) BumpEscalation(_ context.Context, host, ip string, window time.Duration) int {
	return m.bump(escalationPrefix, host, ip, window)
}

// BumpFrameEscalation is BumpEscalation for issuances whose failure to be
// solved carries no information about the client: a framed navigation whose
// Fetch metadata cannot establish that the interstitial's frame-ancestors
// policy will let it render (see transport/http/fetchdest.go). It raises
// difficulty exactly as BumpEscalation does, on a SEPARATE counter that the
// caller never turns into a challenge_farm event.
//
// The split is what lets both halves hold at once. Nobody is ever blocked for
// abandoning a challenge they may never have been shown, so a third party
// cannot escalate an arbitrary visitor into a block by framing a protected URL
// in a loop. And the exemption is not a cheap-challenge loophole either: a
// client that claims a framed destination to dodge scoring still pays
// progressively more work per issuance, so farming through this path costs the
// same as farming through the ordinary one. Only the block is withheld, which
// is the part that cannot be aimed safely.
//
// Escalation here is capped by the caller at the domain ceiling like any other,
// and a solve clears it (ForgetEscalation), so a visitor who really is framing
// their own site's page pays nothing beyond the free allowance.
func (m *Manager) BumpFrameEscalation(_ context.Context, host, ip string, window time.Duration) int {
	return m.bump(frameEscalationPrefix, host, ip, window)
}

func (m *Manager) bump(prefix, host, ip string, window time.Duration) int {
	n := m.counters.Incr(escalationKey(prefix, host, ip), window)
	if n <= escalationFreeIssues {
		return 0
	}
	return int(n-escalationFreeIssues) / escalationStep
}
