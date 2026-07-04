// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package pow

import (
	"sync"
	"time"
)

// tokenCache remembers recently verified tokens so the hot path (stage 3 on
// every vouched request) skips the ~50-100µs Ed25519 signature verification.
// Keyed by a hash of token+binding, so a cache hit implies the exact same
// token, client and host already verified.
type tokenCache struct {
	mu sync.RWMutex
	m  map[[32]byte]int64 // key → cache-entry expiry, unix nanoseconds
}

// maxCacheEntries bounds memory (~5 MB at the cap). When full, the cache is
// wholesale-reset: entries repopulate on the next verify, which is cheap.
const maxCacheEntries = 1 << 17

// cacheMaxValidity caps how long a verification result is trusted without
// re-checking, independent of token expiry. Keeps the door open for a token
// denylist (P4) with bounded lag.
const cacheMaxValidity = 15 * time.Minute

func newTokenCache() *tokenCache {
	return &tokenCache{m: make(map[[32]byte]int64)}
}

func (c *tokenCache) get(key [32]byte, now time.Time) bool {
	c.mu.RLock()
	exp, ok := c.m[key]
	c.mu.RUnlock()
	return ok && now.UnixNano() < exp
}

// reset drops all cached verifications, forcing the next request per token
// through a full signature check. Called after a key rotation.
func (c *tokenCache) reset() {
	c.mu.Lock()
	clear(c.m)
	c.mu.Unlock()
}

func (c *tokenCache) put(key [32]byte, tokenExpiry, now time.Time) {
	exp := now.Add(cacheMaxValidity)
	if tokenExpiry.Before(exp) {
		exp = tokenExpiry
	}
	c.mu.Lock()
	if len(c.m) >= maxCacheEntries {
		clear(c.m)
	}
	c.m[key] = exp.UnixNano()
	c.mu.Unlock()
}
