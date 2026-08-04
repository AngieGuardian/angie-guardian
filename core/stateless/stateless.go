// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package stateless holds the store-free, I/O-free subset of Guardian's
// decision logic: the request/decision value types and the WAF checks that
// need no shared store, PoW manager or anomaly model (static allowlist,
// static denylist, honeypot trap paths, WAF rules with literal/regex matchers).
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
	"path"
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

	// Header returns every value of one request header by (case-insensitive)
	// name. Transports set it so header-targeting WAF rules fetch only the
	// headers they actually name; nil means headers are unavailable and header
	// targets simply never match. Read it via HeaderValues.
	Header func(name string) []string

	// Unchallengeable reports that this request is classified as unable to
	// complete a PoW challenge, so issuing one would only be recorded as an
	// abandoned challenge. Strength varies by cause: a declared subresource
	// provably cannot run the interstitial, while a request judged by its Accept
	// header is a behavioural heuristic. The transport sets it, because this is
	// protocol knowledge (Fetch metadata and Accept semantics for HTTP) that
	// the core deliberately does not carry; false means "not known to be",
	// which is the safe default every other transport gets for free.
	//
	// It exists because the alternative is worse than a flag. The browser's
	// favicon service fetches an icon on an anonymous channel: no cookie
	// whatever the token's SameSite policy, no Sec-Fetch-* even over HTTPS, and
	// Accept: */*. It therefore cannot present a token and cannot run the
	// interstitial, so a challenge decision for it is a decision that can never
	// be satisfied. Recording it as a challenge made an unsatisfiable refusal
	// read as a challenge storm in /admin/decisions, which is a diagnosis
	// problem, not a cosmetic one. See ActionRefuse.
	Unchallengeable bool

	// Memoized derivations of the fields above, filled on first use by
	// NormalizedPath and LowerUA. A full evaluation asks several independent
	// checks the same two questions — "what path does policy match against?" and
	// "what does the User-Agent look like lowercased?" — and both answers cost an
	// allocation to produce. Computing them per check made the URI and the UA the
	// two largest allocation sources on the auth hot path.
	//
	// A RequestContext belongs to one request on one goroutine, so no
	// synchronization is needed. Callers must not mutate URI or UserAgent after
	// reading a derivation; nothing does, and transports build the value once.
	normPath string
	lowerUA  string
}

// NormalizedPath returns the request path in the form every path-scoped policy
// matches against: percent-decoded and dot-segment-normalized (see
// NormalizePath). Computed once per request.
func (r *RequestContext) NormalizedPath() string {
	// NormalizePath never returns "", so the zero value is an unambiguous
	// "not computed yet".
	if r.normPath == "" {
		r.normPath = NormalizePath(RequestPath(r.URI))
	}
	return r.normPath
}

// LowerUA returns the lowercased User-Agent used by every substring match
// (allowlist, denylist, verified-bot needles, WAF ua targets). Computed once
// per request.
func (r *RequestContext) LowerUA() string {
	if r.lowerUA == "" && r.UserAgent != "" {
		r.lowerUA = strings.ToLower(r.UserAgent)
	}
	return r.lowerUA
}

// HeaderValues returns every value of a request header via the transport's
// getter, or nil when none was provided.
func (r *RequestContext) HeaderValues(name string) []string {
	if r.Header == nil {
		return nil
	}
	return r.Header(name)
}

// Action is the outcome kind of a decision.
type Action string

const (
	ActionAllow     Action = "allow"
	ActionChallenge Action = "challenge"
	ActionDeny      Action = "deny"
	// ActionRefuse is a challenge withheld from a request classified as unable
	// to complete it (RequestContext.Unchallengeable). It is deliberately not
	// ActionDeny: the refusal is not itself a block, it scores nothing of its own,
	// and the transport answers exactly as it would have for ActionChallenge,
	// so the wire behaviour and the Angie routing are unchanged. Only the
	// recorded outcome differs, which is the entire point.
	//
	// "The refusal itself" is the whole of the claim, and the distinction is
	// worth stating because the obvious reading is wrong. No challenge is
	// issued, so nothing bumps the unsolved-issuance escalation and no
	// challenge_farm event can follow it. What a stage already emitted still
	// stands: a request refused the challenge a WAF rule or the anomaly
	// scorer asked for is still scored for that WAF rule or that score,
	// because it really did trip one, and being unable to solve a puzzle is no
	// evidence otherwise. The favicon case this exists for reaches the refusal
	// carrying no events at all, which is why it scores nothing end to end.
	ActionRefuse Action = "refuse"
)

// Event is a behaviour observation emitted alongside a decision.
type Event struct {
	Type   string
	Detail string
}

// Event type constants shared with the sidecar's scoreboard.
const (
	EventRuleMatch    = "rule_match"
	EventPoWFail      = "pow_fail"
	EventTamper       = "tamper"
	EventAnomaly      = "anomaly"
	EventInstantBlock = "instant_block"
	EventBotSpoof     = "bot_spoof"
	// EventChallengeFarm marks a challenge issued to a client whose unsolved-
	// challenge escalation alone is pinned at the domain difficulty ceiling:
	// it keeps fetching interstitials and discarding them. Reported by the
	// challenge handler; scored via the waf.ip_behaviour.thresholds
	// challenge_farm key (generous 80/h default, "off" disables).
	EventChallengeFarm = "challenge_farm"
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

// Compile precomputes the CIDR prefixes and lowered UAs, and rejects entries
// that could never mean what they say. Must be called once after loading
// before Match* is used.
//
// Validating here rather than in each loader's own checks is the point of this
// package: the sidecar and the WASM guest both arrive through this function
// (core.DomainConfig.validate and GuestDomain.resolve), so a rule added here
// cannot silently fail to apply on one side. The path rules below were added
// to the sidecar's own validate() first and did exactly that, leaving a guest
// config free to carry the entry that switches the guest off entirely.
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
		ua = strings.TrimSpace(ua)
		if ua == "" {
			return fmt.Errorf("empty user-agent entry")
		}
		l.uasLower = append(l.uasLower, strings.ToLower(ua))
	}
	// Paths are compared against a normalized request path, so an entry that is
	// not itself normalized, or that is empty, relative or a bare "/", either
	// never matches or matches everything. See ValidateMatchPath.
	for _, p := range l.Paths {
		if err := ValidateMatchPath("paths", p, rootHarmList); err != nil {
			return err
		}
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

// Prefixes exposes the compiled IP prefixes (after Compile). The enforcement
// layer unions them across all scopes into its kernel-sink safety filter;
// callers must not mutate the returned slice.
func (l *ListConfig) Prefixes() []netip.Prefix { return l.prefixes }

func (l *ListConfig) MatchUA(ua string) bool { return l.MatchUALower(strings.ToLower(ua)) }

// MatchUALower is MatchUA for a User-Agent the caller has already lowercased
// (RequestContext.LowerUA), so a request that consults several lists pays the
// lowercasing once rather than once per list.
func (l *ListConfig) MatchUALower(lower string) bool {
	if lower == "" {
		return false
	}
	for _, needle := range l.uasLower {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func (l *ListConfig) MatchPath(path string) bool { return MatchPathList(l.Paths, path) }

// ValidateMatchPath checks one configured entry that will be compared against a
// request path by MatchPathList. field names the setting for the error message,
// and rootHarm says what a bare "/" would do there, which differs by list.
//
// Every caller matches against RequestContext.NormalizedPath, i.e. percent
// decoded with dot segments and duplicate slashes resolved, so an entry that is
// not itself in that form can never equal it and can never be a prefix of it.
// "/a/../admin" and "/%61dmin" are simply dead rules, and "/admin//" is worse
// than dead: TrimSuffix strips one slash, so it still matches the bare
// "/admin/" while silently failing to cover the subtree the trailing slash was
// asking for. All of them read as policy and enforce nothing, which is the
// failure this whole family of checks exists to prevent. The paths: overlay
// keys have carried the same fixed-point rule since they were added.
func ValidateMatchPath(field, entry, rootHarm string) error {
	switch {
	case strings.TrimSpace(entry) == "":
		return fmt.Errorf("%s: empty or whitespace-only entry; every entry must be an absolute path like /health", field)
	case !strings.HasPrefix(entry, "/"):
		return fmt.Errorf("%s entry %q is not absolute: request paths always start with /, so it could never match", field, entry)
	case entry == "/":
		return fmt.Errorf("%s entry \"/\" %s", field, rootHarm)
	}
	// Only the path is ever matched. RequestPath cuts the URI at the first "?"
	// before normalization, so a query in an entry cannot match the request it
	// was plainly written for, and a fragment never reaches the server at all.
	//
	// Neither is literally unmatchable, which is why this is its own rule rather
	// than a corollary of the fixed-point check below: both survive
	// NormalizePath untouched, and a request spelled /admin%3Fdebug=1 or
	// /admin%23x decodes to exactly them. That is the only thing such an entry
	// can match, nobody targets it deliberately, and an operator who wrote
	// /admin?debug=1 meant the query. Refuse the ambiguity, as the paths:
	// overlay keys already do (validatePathKey).
	if strings.ContainsAny(entry, "?#") {
		return fmt.Errorf("%s entry %q must not contain ? or #: only the path is matched, since the query is cut before matching and a fragment never reaches the server", field, entry)
	}
	if norm := NormalizePath(entry); norm != entry {
		return fmt.Errorf("%s entry %q is not in normalized form, so it could never match; write %q", field, entry, norm)
	}
	return nil
}

// ValidateHoneypotPaths checks every trap path. Shared by the sidecar and the
// guest: the guest carries a honeypot too and validated none of it.
func (hp *HoneypotConfig) Validate() error {
	for _, p := range hp.Paths {
		if err := ValidateMatchPath("waf.honeypot.paths", p, rootHarmHoneypot); err != nil {
			return err
		}
	}
	return nil
}

// The "/" harm differs by list, so each names its own.
const (
	rootHarmList     = `prefix-matches every URL, so this list would match every request; name the specific paths instead`
	rootHarmHoneypot = `would match every request: the first visitor would be denied (and blocked when ip_behaviour is on); use a specific trap path`
)

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
// WAF rule set. The sidecar builds this from its full DomainConfig; the
// guest builds it from GuestConfig.
type DomainRules struct {
	Allowlist    ListConfig
	Denylist     ListConfig
	Honeypot     HoneypotConfig
	RulesEnabled bool
	Rules        *waf.RuleSet // nil disables rule matching
}

// --- the evaluator ---------------------------------------------------------

// Evaluate runs the stateless pipeline (allowlist -> denylist -> honeypot ->
// WAF rules, first terminal wins). The result is terminal for this subset:
// ActionAllow (reason "default" if nothing matched) or ActionDeny. Because
// there is no PoW here, a WAF rule whose action is "challenge" degrades
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
	if d, ok := evalRules(req, dr); ok {
		return d
	}
	return Decision{Action: ActionAllow, Reason: "default"}
}

// The static-list verdicts carry nothing per-request, so they are immutable
// package values returned by pointer. That is not micro-optimization for its
// own sake: the allowlist and denylist run on every single request, and a
// function returning a Decision whose address the caller takes makes Go
// heap-allocate that Decision on EVERY call, match or not. Callers must treat
// these as read-only.
var (
	allowlistPath = &Decision{Action: ActionAllow, Reason: "allowlist:path"}
	allowlistIP   = &Decision{Action: ActionAllow, Reason: "allowlist:ip"}
	allowlistUA   = &Decision{Action: ActionAllow, Reason: "allowlist:ua"}

	staticDenyEvents = []Event{{Type: "deny", Detail: "static denylist hit"}}
	denylistIP       = &Decision{Action: ActionDeny, Reason: "denylist:ip", Events: staticDenyEvents}
	denylistUA       = &Decision{Action: ActionDeny, Reason: "denylist:ua", Events: staticDenyEvents}
	denylistPath     = &Decision{Action: ActionDeny, Reason: "denylist:path", Events: staticDenyEvents}

	honeypotHit = &Decision{
		Action: ActionDeny,
		Reason: "honeypot:path",
		Events: []Event{{Type: EventInstantBlock, Detail: "honeypot:path"}},
	}
)

func evalAllowlist(req *RequestContext, dr *DomainRules) (Decision, bool) {
	d := CheckAllowlist(req, &dr.Allowlist)
	if d == nil {
		return Decision{}, false
	}
	return *d, true
}

// CheckAllowlist runs the static allowlist (path, IP, UA). It returns a
// terminal allow Decision on a match, or nil otherwise. Exported so the
// sidecar's allowlist stage shares this exact logic with the WASM guest and the
// two can never drift. The returned Decision is shared and must not be mutated.
func CheckAllowlist(req *RequestContext, l *ListConfig) *Decision {
	if l.MatchPath(req.NormalizedPath()) {
		return allowlistPath
	}
	if addr, err := netip.ParseAddr(req.RemoteAddr); err == nil && l.MatchIP(addr) {
		return allowlistIP
	}
	if l.MatchUALower(req.LowerUA()) {
		return allowlistUA
	}
	return nil
}

func evalDenylist(req *RequestContext, dr *DomainRules) (Decision, bool) {
	d := CheckDenylist(req, &dr.Denylist)
	if d == nil {
		return Decision{}, false
	}
	return *d, true
}

// CheckDenylist runs the static denylist (IP, UA, path), the mirror image of
// CheckAllowlist: every list dimension an operator can configure is enforced,
// not just IPs. Exported so the sidecar's denylist stage shares this exact
// logic with the WASM guest and the two can never drift. The returned Decision
// is shared and must not be mutated.
func CheckDenylist(req *RequestContext, l *ListConfig) *Decision {
	if addr, err := netip.ParseAddr(req.RemoteAddr); err == nil && l.MatchIP(addr) {
		return denylistIP
	}
	if l.MatchUALower(req.LowerUA()) {
		return denylistUA
	}
	if l.MatchPath(req.NormalizedPath()) {
		return denylistPath
	}
	return nil
}

func evalHoneypot(req *RequestContext, dr *DomainRules) (Decision, bool) {
	d := CheckHoneypot(req, &dr.Honeypot)
	if d == nil {
		return Decision{}, false
	}
	return *d, true
}

// CheckHoneypot runs the honeypot trap-path check. It returns a terminal deny
// Decision (with an instant-block event) on a hit, or nil otherwise. Exported
// so the sidecar's honeypot stage shares this exact logic with the WASM guest.
// The returned Decision is shared and must not be mutated.
func CheckHoneypot(req *RequestContext, hp *HoneypotConfig) *Decision {
	if !hp.Enabled || len(hp.Paths) == 0 {
		return nil
	}
	if MatchPathList(hp.Paths, req.NormalizedPath()) {
		return honeypotHit
	}
	return nil
}

// BuildMatchInput assembles the normalized matcher input for a WAF rule
// set, fetching method and headers only when some rule targets them. Header
// values get the same best-effort percent-decoding as the path, so encoded
// payloads in URL-shaped headers (Referer and friends) can't slip past
// literal keywords. Shared by the sidecar's WAF stage and the WASM guest so
// their matching semantics cannot drift.
func BuildMatchInput(req *RequestContext, rs *waf.RuleSet) waf.MatchInput {
	in := waf.MatchInput{
		Path:  strings.ToLower(DecodePath(RequestPath(req.URI))),
		Query: strings.ToLower(DecodeQuery(RequestQuery(req.URI))),
		UA:    req.LowerUA(),
	}
	if rs.NeedsMethod() {
		in.Method = strings.ToUpper(req.Method)
	}
	if names := rs.HeaderTargets(); len(names) > 0 && req.Header != nil {
		// Built lazily: one rule anywhere in the file targeting a header makes
		// every request take this branch, and most requests carry none of the
		// targeted headers. Allocating the map up front spent an allocation per
		// request to hold nothing.
		for _, name := range names {
			for _, v := range req.HeaderValues(name) {
				if v == "" {
					continue
				}
				if in.Headers == nil {
					in.Headers = make(map[string][]string, len(names))
				}
				in.Headers[name] = append(in.Headers[name], strings.ToLower(DecodePath(v)))
			}
		}
	}
	return in
}

func evalRules(req *RequestContext, dr *DomainRules) (Decision, bool) {
	if !dr.RulesEnabled || dr.Rules == nil {
		return Decision{}, false
	}
	in := BuildMatchInput(req, dr.Rules)
	rule := dr.Rules.Match(&in)
	if rule == nil {
		return Decision{}, false
	}
	event := EventRuleMatch
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

// DecodePath best-effort URL-decodes a path for WAF rule matching, so
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

// NormalizePath percent-decodes a request path and resolves dot segments and
// duplicate slashes the way the web server does before serving ("/a/../b" ->
// "/b", "//x" -> "/x"), preserving a trailing slash. Every path-scoped policy
// match (allowlist, honeypot, per-path overlays) must use this form: matching
// the raw URI instead would let "/static/../admin" adopt or escape a policy
// for a path Angie never serves. WAF rule matching deliberately keeps the
// un-cleaned decoded path so traversal rules still see "../" attempts.
func NormalizePath(p string) string {
	p = DecodePath(p)
	if p == "" {
		return "/"
	}
	trailingSlash := strings.HasSuffix(p, "/")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = path.Clean(p)
	if trailingSlash && p != "/" {
		p += "/"
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
	// net.SplitHostPort allocates an *AddrError for every input without a port,
	// and a Host header carrying no port is the overwhelmingly common case, so
	// it was the single largest allocation source on the auth hot path. A port
	// separator (and an IPv6 literal) always contains a colon; nothing else
	// SplitHostPort would strip does.
	if strings.IndexByte(host, ':') >= 0 {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
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
