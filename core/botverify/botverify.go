// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package botverify confirms that a client claiming to be a well-known
// crawler really is one. A User-Agent string is free to forge, so a UA
// allowlist entry like "Googlebot" would let any scraper skip the WAF; the
// search engines therefore document reverse-DNS verification instead:
//
//  1. PTR lookup on the client IP (e.g. 66.249.66.1 ->
//     crawl-66-249-66-1.googlebot.com)
//  2. check the returned hostname is under one of the bot's published
//     domains (googlebot.com for Googlebot proper; other Google crawler
//     categories use different domains and are modelled as separate bots)
//  3. forward-confirm: resolve that hostname and require the original IP
//     to be among its addresses, so an attacker who controls the PTR of
//     their own IP space cannot just point it at googlebot.com.
//
// Verification results are cached in the shared store: an IP's confirmed
// rDNS identity is a property of the IP, not of any one vhost's config, so
// one cache entry serves every domain and survives restarts (bbolt/redis).
// DNS work is deduplicated per IP and capped globally so a flood of spoofed
// UAs from many IPs degrades to "unverified" instead of a lookup storm.
package botverify

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/melroy89/angie-guardian/core/store"
)

// Resolver is the subset of *net.Resolver used, extracted for tests.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Status is the outcome of verifying one IP's rDNS identity.
type Status int

const (
	// StatusError: DNS was unavailable, over budget or shed by the
	// concurrency cap. The identity is unknown; callers must treat the
	// client as unverified but NOT as a proven impostor.
	StatusError Status = iota
	// StatusConfirmed: at least one PTR hostname forward-confirmed back to
	// the IP. Result.Hostnames holds the confirmed names.
	StatusConfirmed
	// StatusNone: definitive absence — the IP has no PTR record, or none of
	// its PTR hostnames resolve back to it. A client claiming a crawler UA
	// from such an IP is an impostor.
	StatusNone
)

// Result is one IP's verified rDNS identity.
type Result struct {
	Status Status
	// Hostnames are the forward-confirmed PTR hostnames, lowercased and
	// without the trailing dot. Non-empty iff Status == StatusConfirmed.
	Hostnames []string
}

// MatchesDomains reports whether any confirmed hostname is the given domain
// or a subdomain of it. Domains must be lowercase without a trailing dot.
func (r Result) MatchesDomains(domains []string) bool {
	for _, h := range r.Hostnames {
		for _, d := range domains {
			if h == d || strings.HasSuffix(h, "."+d) {
				return true
			}
		}
	}
	return false
}

// Options carries the per-call knobs (they live in the per-domain config).
type Options struct {
	Timeout     time.Duration // total DNS budget for one verification
	CacheTTL    time.Duration // TTL for confirmed identities
	NegativeTTL time.Duration // TTL for definitive "no identity" results
}

const (
	keyPrefix = "botdns:"
	// maxPTRs bounds how many PTR records get forward-confirmed, so a
	// hostile PTR set can't multiply lookups. Real crawlers return one.
	maxPTRs = 5
	// maxConcurrent caps in-flight verifications process-wide. When the cap
	// is hit, new IPs are reported StatusError (unverified) rather than
	// queued: the auth hot path must shed DNS load, never buffer it.
	maxConcurrent = 64
	// errTTL briefly caches transient DNS failures so a broken resolver
	// doesn't cost a lookup per request, while recovering quickly.
	errTTL = 30 * time.Second

	cacheOK   = "ok:" // + comma-joined confirmed hostnames
	cacheNone = "none"
	cacheErr  = "err"
)

// Verifier performs and caches rDNS + forward-confirm verification.
type Verifier struct {
	store    store.Store
	resolver Resolver
	log      *slog.Logger

	sem chan struct{}

	mu       sync.Mutex
	inflight map[string]*call
}

type call struct {
	done chan struct{}
	res  Result
}

func New(st store.Store, log *slog.Logger) *Verifier {
	return &Verifier{
		store:    st,
		resolver: net.DefaultResolver,
		log:      log,
		sem:      make(chan struct{}, maxConcurrent),
		inflight: make(map[string]*call),
	}
}

// SetResolver replaces the DNS resolver (tests, or a custom net.Resolver).
func (v *Verifier) SetResolver(r Resolver) { v.resolver = r }

// Verify returns the rDNS identity of ip, from cache when possible. It never
// returns an error: every failure mode collapses to StatusError, which
// callers treat as "unverified" (the request continues down the pipeline).
func (v *Verifier) Verify(ctx context.Context, ip string, opts Options) Result {
	// A cold recursive PTR resolution through a forwarding resolver can
	// take over a second, so the default budget is a generous 1s: it is
	// paid once per IP per CacheTTL, never on the hot path.
	if opts.Timeout <= 0 {
		opts.Timeout = time.Second
	}
	if opts.CacheTTL <= 0 {
		opts.CacheTTL = 12 * time.Hour
	}
	if opts.NegativeTTL <= 0 {
		opts.NegativeTTL = time.Hour
	}

	if raw, ok, err := v.store.Get(ctx, keyPrefix+ip); err == nil && ok {
		return decodeCache(string(raw))
	}

	// Deduplicate concurrent lookups for the same IP: one leader resolves,
	// followers wait for its result (or give up with their own context).
	v.mu.Lock()
	if c, ok := v.inflight[ip]; ok {
		v.mu.Unlock()
		select {
		case <-c.done:
			return c.res
		case <-ctx.Done():
			return Result{Status: StatusError}
		}
	}
	c := &call{done: make(chan struct{})}
	v.inflight[ip] = c
	v.mu.Unlock()

	c.res = v.resolveAndCache(ctx, ip, opts)

	v.mu.Lock()
	delete(v.inflight, ip)
	v.mu.Unlock()
	close(c.done)
	return c.res
}

func (v *Verifier) resolveAndCache(ctx context.Context, ip string, opts Options) Result {
	select {
	case v.sem <- struct{}{}:
		defer func() { <-v.sem }()
	default:
		// Cap reached: shed. Not cached, so verification is retried once
		// load allows — a spoof flood can't poison real crawler IPs.
		v.log.Debug("bot verification shed: concurrency cap reached", "ip", ip)
		return Result{Status: StatusError}
	}

	dnsCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	res := v.resolve(dnsCtx, ip)

	var value string
	ttl := opts.CacheTTL
	switch res.Status {
	case StatusConfirmed:
		value = cacheOK + strings.Join(res.Hostnames, ",")
	case StatusNone:
		value, ttl = cacheNone, opts.NegativeTTL
	default:
		value, ttl = cacheErr, errTTL
	}
	// Cache writes use the request context's values but must not be skipped
	// just because the DNS budget ran out, hence a fresh short deadline.
	putCtx, putCancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer putCancel()
	if err := v.store.Set(putCtx, keyPrefix+ip, []byte(value), ttl); err != nil {
		v.log.Warn("bot verification cache write failed", "ip", ip, "err", err)
	}
	return res
}

// resolve does the actual PTR + forward-confirm dance, uncached.
func (v *Verifier) resolve(ctx context.Context, ip string) Result {
	target, err := netip.ParseAddr(ip)
	if err != nil {
		// Not an IP at all. Under the trusted-proxy contract this is a
		// transport misconfiguration, not a client we can judge, so the
		// identity is unknown rather than a proven impostor: the same
		// fail-open stance the denylist stage takes on a garbage IP.
		return Result{Status: StatusError}
	}
	target = target.Unmap()

	ptrs, err := v.resolver.LookupAddr(ctx, ip)
	if err != nil {
		if isNotFound(err) {
			return Result{Status: StatusNone} // no PTR record at all
		}
		v.log.Debug("bot verification PTR lookup failed", "ip", ip, "err", err)
		return Result{Status: StatusError}
	}

	if len(ptrs) > maxPTRs {
		ptrs = ptrs[:maxPTRs]
	}
	var confirmed []string
	transient := false
	for _, ptr := range ptrs {
		host := strings.ToLower(strings.TrimSuffix(ptr, "."))
		if host == "" {
			continue
		}
		addrs, err := v.resolver.LookupIPAddr(ctx, host)
		if err != nil {
			if !isNotFound(err) {
				transient = true
			}
			continue
		}
		for _, a := range addrs {
			if got, ok := netip.AddrFromSlice(a.IP); ok && got.Unmap() == target {
				confirmed = append(confirmed, host)
				break
			}
		}
	}
	switch {
	case len(confirmed) > 0:
		return Result{Status: StatusConfirmed, Hostnames: confirmed}
	case transient:
		// Some forward lookup failed non-definitively: don't brand the IP
		// an impostor on flaky DNS.
		return Result{Status: StatusError}
	default:
		return Result{Status: StatusNone}
	}
}

func decodeCache(raw string) Result {
	switch {
	case strings.HasPrefix(raw, cacheOK):
		hosts := strings.Split(raw[len(cacheOK):], ",")
		return Result{Status: StatusConfirmed, Hostnames: hosts}
	case raw == cacheNone:
		return Result{Status: StatusNone}
	default:
		return Result{Status: StatusError}
	}
}

// isNotFound reports a definitive NXDOMAIN/no-record answer, as opposed to a
// timeout or server failure.
func isNotFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}
