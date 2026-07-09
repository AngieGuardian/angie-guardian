// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package stateless holds the store-free, I/O-free subset of Guardian's
// decision logic: the request/decision value types and the WAF checks that
// need no shared store, PoW manager or anomaly model (static allowlist,
// static denylist, honeypot trap paths, keyword/regex signatures).
//
// It is a leaf package depending only on core/waf and the standard library,
// so it can be compiled to WebAssembly (the http-wasm guest imports it) as
// well as reused by the sidecar. The main core package type-aliases the value
// types defined here, so both paths share exactly one implementation.
package stateless

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/melroy89/angie-guardian/core/waf"
)

// RequestContext carries only primitives (plus one transport-supplied getter)
// so it can be populated from an HTTP request (sidecar), a WASM host call, or
// a future cgo struct.
type RequestContext struct {
	Host       string
	Method     string
	URI        string // path with query string, as received
	RemoteAddr string // client IP, no port
	UserAgent  string
	Cookie     string // raw Cookie header

	// Header returns one request header by (case-insensitive) name, or ""
	// when absent. Transports set it so header-targeting WAF rules fetch only
	// the headers they actually name; nil means headers are unavailable and
	// header targets simply never match. Read it via HeaderValue.
	Header func(name string) string
}

// HeaderValue returns a request header via the transport's getter, or "" when
// none was provided.
func (r *RequestContext) HeaderValue(name string) string {
	if r.Header == nil {
		return ""
	}
	return r.Header(name)
}

// Action is the outcome kind of a decision.
type Action string

const (
	ActionAllow     Action = "allow"
	ActionChallenge Action = "challenge"
	ActionDeny      Action = "deny"
)

// Event is a behaviour observation emitted alongside a decision.
type Event struct {
	Type   string
	Detail string
}

// Event type constants shared with the sidecar's scoreboard.
const (
	EventSignature    = "signature"
	EventPoWFail      = "pow_fail"
	EventTamper       = "tamper"
	EventAnomaly      = "anomaly"
	EventInstantBlock = "instant_block"
)

// Decision is the outcome of evaluating one request.
type Decision struct {
	Action     Action
	Difficulty int // PoW difficulty in leading-zero bits when Action == ActionChallenge
	Reason     string
	Events     []Event
}

// --- shared config value types (stateless subset) --------------------------

// ListConfig is a static allow- or denylist. Matching rules:
//   - IPs: CIDRs or bare IPv4/IPv6 addresses
//   - UAs: case-insensitive substring match on User-Agent
//   - Paths: exact match, or prefix match when the entry ends with "/"
type ListConfig struct {
	IPs   []string `yaml:"ips" json:"ips"`
	UAs   []string `yaml:"uas" json:"uas"`
	Paths []string `yaml:"paths" json:"paths"`

	prefixes []netip.Prefix
	uasLower []string
}

// Compile precomputes the CIDR prefixes and lowered UAs. Must be called once
// after loading before Match* is used.
func (l *ListConfig) Compile() error {
	l.prefixes = l.prefixes[:0]
	for _, s := range l.IPs {
		if strings.Contains(s, "/") {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return fmt.Errorf("invalid CIDR %q: %w", s, err)
			}
			l.prefixes = append(l.prefixes, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return fmt.Errorf("invalid IP %q: %w", s, err)
		}
		l.prefixes = append(l.prefixes, netip.PrefixFrom(a, a.BitLen()))
	}
	l.uasLower = l.uasLower[:0]
	for _, ua := range l.UAs {
		l.uasLower = append(l.uasLower, strings.ToLower(ua))
	}
	return nil
}

func (l *ListConfig) MatchIP(addr netip.Addr) bool {
	for _, p := range l.prefixes {
		if p.Contains(addr.Unmap()) {
			return true
		}
	}
	return false
}

func (l *ListConfig) MatchUA(ua string) bool {
	if ua == "" {
		return false
	}
	lower := strings.ToLower(ua)
	for _, needle := range l.uasLower {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func (l *ListConfig) MatchPath(path string) bool { return MatchPathList(l.Paths, path) }

// MatchPathList: exact match, or prefix match when the entry ends with "/".
func MatchPathList(entries []string, path string) bool {
	for _, entry := range entries {
		if strings.HasSuffix(entry, "/") {
			if strings.HasPrefix(path, entry) || path == strings.TrimSuffix(entry, "/") {
				return true
			}
		} else if path == entry {
			return true
		}
	}
	return false
}

// HoneypotConfig configures trap paths that no legitimate client requests.
type HoneypotConfig struct {
	Enabled bool     `yaml:"enabled" json:"enabled"`
	Paths   []string `yaml:"paths" json:"paths"`
}

// DomainRules bundles the stateless per-domain config plus the compiled
// signature rule set. The sidecar builds this from its full DomainConfig; the
// guest builds it from GuestConfig.
type DomainRules struct {
	Allowlist       ListConfig
	Denylist        ListConfig
	Honeypot        HoneypotConfig
	KeywordsEnabled bool
	Rules           *waf.RuleSet // nil disables signature matching
}

// --- the evaluator ---------------------------------------------------------

// Evaluate runs the stateless pipeline (allowlist -> denylist -> honeypot ->
// signatures, first terminal wins). The result is terminal for this subset:
// ActionAllow (reason "default" if nothing matched) or ActionDeny. Because
// there is no PoW here, a signature rule whose action is "challenge" degrades
// to a deny.
func Evaluate(req *RequestContext, dr *DomainRules) Decision {
	if d, ok := evalAllowlist(req, dr); ok {
		return d
	}
	if d, ok := evalDenylist(req, dr); ok {
		return d
	}
	if d, ok := evalHoneypot(req, dr); ok {
		return d
	}
	if d, ok := evalSignatures(req, dr); ok {
		return d
	}
	return Decision{Action: ActionAllow, Reason: "default"}
}

func evalAllowlist(req *RequestContext, dr *DomainRules) (Decision, bool) {
	return CheckAllowlist(req, &dr.Allowlist)
}

// CheckAllowlist runs the static allowlist (path, IP, UA). It returns a
// terminal allow Decision and true on a match, or (zero, false) otherwise.
// Exported so the sidecar's allowlist stage shares this exact logic with the
// WASM guest and the two can never drift.
func CheckAllowlist(req *RequestContext, l *ListConfig) (Decision, bool) {
	if l.MatchPath(RequestPath(req.URI)) {
		return Decision{Action: ActionAllow, Reason: "allowlist:path"}, true
	}
	if addr, err := netip.ParseAddr(req.RemoteAddr); err == nil && l.MatchIP(addr) {
		return Decision{Action: ActionAllow, Reason: "allowlist:ip"}, true
	}
	if l.MatchUA(req.UserAgent) {
		return Decision{Action: ActionAllow, Reason: "allowlist:ua"}, true
	}
	return Decision{}, false
}

func evalDenylist(req *RequestContext, dr *DomainRules) (Decision, bool) {
	addr, err := netip.ParseAddr(req.RemoteAddr)
	if err != nil {
		return Decision{}, false
	}
	if dr.Denylist.MatchIP(addr) {
		return Decision{
			Action: ActionDeny,
			Reason: "denylist:ip",
			Events: []Event{{Type: "deny", Detail: "static denylist hit"}},
		}, true
	}
	return Decision{}, false
}

func evalHoneypot(req *RequestContext, dr *DomainRules) (Decision, bool) {
	return CheckHoneypot(req, &dr.Honeypot)
}

// CheckHoneypot runs the honeypot trap-path check. It returns a terminal deny
// Decision (with an instant-block event) and true on a hit. Exported so the
// sidecar's honeypot stage shares this exact logic with the WASM guest.
func CheckHoneypot(req *RequestContext, hp *HoneypotConfig) (Decision, bool) {
	if !hp.Enabled || len(hp.Paths) == 0 {
		return Decision{}, false
	}
	if MatchPathList(hp.Paths, RequestPath(req.URI)) {
		return Decision{
			Action: ActionDeny,
			Reason: "honeypot:path",
			Events: []Event{{Type: EventInstantBlock, Detail: "honeypot:path"}},
		}, true
	}
	return Decision{}, false
}

// BuildMatchInput assembles the normalized signature-matcher input for a rule
// set, fetching method and headers only when some rule targets them. Header
// values get the same best-effort percent-decoding as the path, so encoded
// payloads in URL-shaped headers (Referer and friends) can't slip past
// literal keywords. Shared by the sidecar's WAF stage and the WASM guest so
// their matching semantics cannot drift.
func BuildMatchInput(req *RequestContext, rs *waf.RuleSet) waf.MatchInput {
	in := waf.MatchInput{
		Path:  strings.ToLower(DecodePath(RequestPath(req.URI))),
		Query: strings.ToLower(DecodeQuery(RequestQuery(req.URI))),
		UA:    strings.ToLower(req.UserAgent),
	}
	if rs.NeedsMethod() {
		in.Method = strings.ToUpper(req.Method)
	}
	if names := rs.HeaderTargets(); len(names) > 0 && req.Header != nil {
		in.Headers = make(map[string]string, len(names))
		for _, name := range names {
			if v := req.HeaderValue(name); v != "" {
				in.Headers[name] = strings.ToLower(DecodePath(v))
			}
		}
	}
	return in
}

func evalSignatures(req *RequestContext, dr *DomainRules) (Decision, bool) {
	if !dr.KeywordsEnabled || dr.Rules == nil {
		return Decision{}, false
	}
	in := BuildMatchInput(req, dr.Rules)
	rule := dr.Rules.Match(&in)
	if rule == nil {
		return Decision{}, false
	}
	event := EventSignature
	if rule.Action == waf.ActionBlock {
		event = EventInstantBlock
	}
	return Decision{
		Action: ActionDeny,
		Reason: "waf:" + rule.ID,
		Events: []Event{{Type: event, Detail: rule.ID}},
	}, true
}

// --- pure URI/host helpers (shared by sidecar and guest) -------------------

// RequestPath returns the path portion of a URI (before "?").
func RequestPath(uri string) string {
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		return uri[:i]
	}
	return uri
}

// RequestQuery returns the query portion of a URI (after "?"), or "".
func RequestQuery(uri string) string {
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		return uri[i+1:]
	}
	return ""
}

// DecodePath best-effort URL-decodes a path for signature matching, so
// percent-encoding can't slip past literal keywords. On malformed escapes the
// raw string is returned.
func DecodePath(p string) string {
	if !strings.ContainsRune(p, '%') {
		return p
	}
	if d, err := url.PathUnescape(p); err == nil {
		return d
	}
	return p
}

// DecodeQuery best-effort URL-decodes a query string.
func DecodeQuery(q string) string {
	if !strings.ContainsAny(q, "%+") {
		return q
	}
	if d, err := url.QueryUnescape(q); err == nil {
		return d
	}
	return q
}

// NormalizeHost lowercases a host, strips any port and IPv6 brackets, and
// drops a trailing dot, so config lookups are case- and port-insensitive.
func NormalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	return strings.TrimSuffix(host, ".")
}

// NormalizeHostKey returns the normalized map key for a domain entry and
// records it in seen (normalized -> raw key). Two entries that collapse to the
// same normalized host ("A.test:443" vs "a.test") are a load error naming both
// raw keys: silently keeping one would let map order pick a random winner.
// Shared by the sidecar and guest config loaders so their policy cannot drift.
func NormalizeHostKey(seen map[string]string, host string) (string, error) {
	key := NormalizeHost(host)
	if prev, dup := seen[key]; dup {
		return "", fmt.Errorf("domains: %q and %q both normalize to %q", host, prev, key)
	}
	seen[key] = host
	return key, nil
}

// ClientIP extracts the bare client IP from a source address that may carry a
// port and/or IPv6 brackets ("1.2.3.4:80", "[2001:db8::1]:443", "2001:db8::1").
// It must not corrupt a bare IPv6 literal, so it never hand-splits on the last
// colon: it tries net.SplitHostPort first, then falls back to the string as-is
// (bracket-trimmed) when there is no port. The result is validated as an IP;
// anything that doesn't parse is returned unchanged for the caller to reject.
func ClientIP(addr string) string {
	if addr == "" {
		return ""
	}
	// host:port or [ipv6]:port
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	// No port. Trim brackets from a bare "[ipv6]" form.
	trimmed := strings.Trim(addr, "[]")
	if _, err := netip.ParseAddr(trimmed); err == nil {
		return trimmed
	}
	// Not a bare IP either (e.g. still bracketed with junk); return as-is.
	return addr
}
