// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import "net/http"

// Response security headers set by guardiand itself.
//
// The Angie glue (deploy/angie-guardian.conf) already adds a page-fitted CSP to
// @guardian_challenge and @guardian_denied, but that is the deployment's copy of
// the policy: it does not apply when Guardian is reached any other way (a direct
// probe, a dev setup, an operator-written vhost that forgot the add_header, or
// the admin listener, which Angie never fronts at all). Emitting the same policy
// from the daemon makes every page self-protecting regardless of the glue.
//
// Emitting it in BOTH places is safe by design: a browser enforces every CSP it
// receives, so two headers mean the intersection of the two policies. The
// constants below are kept identical to the glue's, plus directives the pages
// never exercise, so the intersection is exactly this policy.
const (
	// cspChallenge fits the interstitial exactly: one inline script, one inline
	// style, a blob: Web Worker for the solver, and a same-origin fetch to post
	// the solution. Keep in sync with deploy/angie-guardian.conf.
	//
	// frame-ancestors is 'self', not 'none': a protected page may legitimately
	// be embedded by the same site, and the interstitial has to be solvable
	// wherever the page it guards renders. Cross-origin framing is refused,
	// which is the clickjacking case that matters and is already broken anyway
	// (the token cookie is SameSite=Lax, so it would never come back).
	cspChallenge = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; " +
		"worker-src blob:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'"

	// cspStatic fits an inline-styled static page with no script and no
	// subresources (the denied page). Keep in sync with the glue.
	cspStatic = "default-src 'none'; style-src 'unsafe-inline'; " +
		"base-uri 'none'; form-action 'none'; frame-ancestors 'self'"

	// cspDashboard fits the admin reporting page: its own inline script and
	// style, the same-origin vendored chart libraries, the data: SVG favicon,
	// and same-origin fetches to the token-guarded /admin endpoints and the
	// world atlas. No CDN, no eval, no workers. Framing is refused outright: a
	// management console has no reason to be embedded anywhere.
	cspDashboard = "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; " +
		"img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)

// frameOptions mirrors a policy's frame-ancestors for browsers predating it.
// Empty means the response is not a document, so neither header applies.
const (
	frameSameOrigin = "SAMEORIGIN"
	frameDeny       = "DENY"
)

// Shared single-value header slices, assigned into response header maps
// directly. Header.Set allocates a fresh []string per call, on headers whose
// values come from a tiny fixed set and are stamped onto every response the
// daemon serves; assigning a shared slice costs nothing per response. Safe
// because nothing mutates a response header's value slice after assignment:
// net/http only reads them when writing the response, and no handler here
// appends to one. The variables are effectively constants — never modify them.
var (
	hdrValNosniff    = []string{"nosniff"}
	hdrValNoReferrer = []string{"no-referrer"}
	hdrValCSP        = map[string][]string{
		cspChallenge: {cspChallenge},
		cspStatic:    {cspStatic},
		cspDashboard: {cspDashboard},
	}
	hdrValFrame = map[string][]string{
		frameSameOrigin: {frameSameOrigin},
		frameDeny:       {frameDeny},
	}
	hdrValHTML    = []string{"text/html; charset=utf-8"}
	hdrValNoStore = []string{"no-store"}
)

// securityHeaders applies the headers every Guardian-served response carries.
// nosniff matters even for JSON: without it a browser may content-sniff an
// admin response body into HTML. Referrer-Policy keeps the challenged URL
// (which can carry query parameters) out of any off-origin request the page
// makes. Pass csp == "" for non-document responses (JSON, metrics, assets):
// they get nosniff and Referrer-Policy but no page policy.
//
// The map keys are written in canonical MIME form, which is what makes direct
// assignment equivalent to Header.Set minus its per-call allocation.
func securityHeaders(w http.ResponseWriter, csp, frameOpts string) {
	h := w.Header()
	h["X-Content-Type-Options"] = hdrValNosniff
	h["Referrer-Policy"] = hdrValNoReferrer
	if csp != "" {
		if v, ok := hdrValCSP[csp]; ok {
			h["Content-Security-Policy"] = v
		} else {
			h.Set("Content-Security-Policy", csp)
		}
	}
	if frameOpts != "" {
		if v, ok := hdrValFrame[frameOpts]; ok {
			h["X-Frame-Options"] = v
		} else {
			h.Set("X-Frame-Options", frameOpts)
		}
	}
}
