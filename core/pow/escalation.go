// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package pow

import (
	"context"
	"net"
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
	return prefix + host + ":" + ip
}

// ForgetEscalation clears both escalation counters for one host+IP pair. A
// solve proves the client is not discarding interstitials, whichever context it
// arrived in, so redemption resets both.
func (m *Manager) ForgetEscalation(host, ip string) {
	m.counters.Forget(escalationKey(escalationPrefix, host, ip))
	m.counters.Forget(escalationKey(frameEscalationPrefix, host, ip))
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
