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

func escalationKey(host, ip string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	return "chesc:" + host + ":" + ip
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
	n := m.counters.Incr(escalationKey(host, ip), window)
	if n <= escalationFreeIssues {
		return 0
	}
	return int(n-escalationFreeIssues) / escalationStep
}
