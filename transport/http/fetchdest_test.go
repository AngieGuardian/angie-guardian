// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import "testing"

// TestIsSubresourceDest pins both halves of the classification: the
// destinations that provably cannot run the interstitial, and everything that
// must keep the ordinary challenge path because refusing it would either break
// a solvable client or hand a farmer a bypass.
func TestIsSubresourceDest(t *testing.T) {
	cases := []struct {
		dest string
		want bool
		why  string
	}{
		// Cannot parse or execute an HTML document.
		{"image", true, "the /favicon.ico case that started this"},
		{"style", true, "CSS parser"},
		{"script", true, "JS parser"},
		{"font", true, "font decoder"},
		{"empty", true, "fetch()/XHR"},
		{"audio", true, "media decoder"},
		{"video", true, "media decoder"},
		{"track", true, "WebVTT parser"},
		{"manifest", true, "JSON parser"},
		{"json", true, "JSON module, parsed as data"},
		{"text", true, "text module, parsed as data"},
		{"webidentity", true, "FedCM, consumed by the credential API"},
		{"worker", true, "no DOM, and the page needs one"},
		{"sharedworker", true, "no DOM"},
		{"serviceworker", true, "no DOM"},
		{"audioworklet", true, "no DOM"},
		{"paintworklet", true, "no DOM"},
		{"report", true, "reporting endpoint, response discarded"},
		{"xslt", true, "XSLT parser"},

		// Document-like: these render markup and run script. The framed four
		// are gated on origin instead, by challengeRefusal below.
		{"document", false, "an ordinary navigation"},
		{"iframe", false, "nested navigation, renders same-origin"},
		{"frame", false, "legacy nested navigation"},
		{"embed", false, "can render HTML with script"},
		{"object", false, "can render HTML with script"},
		{"fencedframe", false, "a navigation, not a subresource: unscorableFrame handles it"},

		// Unknown must keep today's behaviour, or the farming defence has a
		// one-header bypass and a future destination silently breaks.
		{"", false, "absent: old clients, non-browsers, a header-stripping proxy"},
		{"Image", false, "non-conforming casing is not a conforming destination"},
		{" image", false, "not a token the standard emits"},
		{"future-dest", false, "added to the Fetch standard after this list"},
	}

	for _, c := range cases {
		if got := isSubresourceDest(c.dest); got != c.want {
			t.Errorf("isSubresourceDest(%q) = %v, want %v (%s)", c.dest, got, c.want, c.why)
		}
	}
}

// TestIsDocumentDest pins the exemption the Accept heuristic yields to. The
// direction that matters is the opposite of isSubresourceDest's: here a false
// negative is the dangerous one, because a destination wrongly reported as
// non-document lets a weaker signal (Accept) decide a request that a stronger,
// unforgeable one had already answered.
//
// Absent and unrecognized are deliberately false. That is not an oversight to
// be "fixed" later: the browser's favicon service sends no Fetch metadata at
// all, even over HTTPS, and it is exactly the request this whole path exists
// for.
func TestIsDocumentDest(t *testing.T) {
	cases := []struct {
		dest string
		want bool
		why  string
	}{
		{"document", true, "a top-level navigation, whatever it says it accepts"},
		{"iframe", true, "nested navigation; unscorableFrame decides the scoring, not this"},
		{"frame", true, "legacy nested navigation"},
		{"embed", true, "renders HTML with script"},
		{"object", true, "renders HTML with script"},
		{"fencedframe", true, "a navigation, and unconditionally unscored elsewhere"},

		{"", false, "absent: the favicon service sends none of these, even over HTTPS"},
		{"image", false, "already refused by isSubresourceDest before this is consulted"},
		{"empty", false, "fetch()/XHR"},
		{"Document", false, "non-conforming casing is not a conforming destination"},
		{"future-dest", false, "unknown stays unknown; the Accept heuristic may then speak"},
	}

	for _, c := range cases {
		if got := isDocumentDest(c.dest); got != c.want {
			t.Errorf("isDocumentDest(%q) = %v, want %v (%s)", c.dest, got, c.want, c.why)
		}
	}
}

// TestUnscorableFrame covers the origin half, which controls scoring only and
// never whether a challenge is issued. The interstitial is served with
// frame-ancestors 'self' and X-Frame-Options: SAMEORIGIN, so a frame from
// another origin may be refused rendering by the browser and can then never
// solve it; the token cookie is SameSite=Lax, so even a visitor already holding
// one arrives on a cross-site frame load looking unvouched. Counting those
// issuances would let any page escalate an arbitrary visitor's IP into a
// challenge_farm block by framing a protected URL in a loop.
func TestUnscorableFrame(t *testing.T) {
	cases := []struct {
		dest, site string
		want       bool
		why        string
	}{
		// Framed and apparently foreign: issued, but not scored.
		{"iframe", "cross-site", true, "the drive-by escalation attack"},
		{"frame", "cross-site", true, "legacy frameset, same problem"},
		{"embed", "cross-site", true, ""},
		{"object", "cross-site", true, ""},
		{"iframe", "same-site", true, "frame-ancestors 'self' is an origin check, so a sibling subdomain cannot render it either"},

		// A same-origin frame renders and solves normally, so it must keep
		// being scored or the exemption is itself a way around escalation.
		{"iframe", "same-origin", false, "a site framing its own page"},
		{"embed", "same-origin", false, ""},
		{"iframe", "", false, "absent Sec-Fetch-Site keeps ordinary scoring"},
		{"iframe", "none", false, "user-initiated"},
		{"iframe", "not-a-real-site-value", false, "unknown keeps ordinary scoring"},

		// Top-level navigation is never framed. A cross-site one is an ordinary
		// inbound link from a search engine and is scored exactly as before.
		{"document", "cross-site", false, "an inbound link from another site"},
		{"document", "same-origin", false, ""},
		{"document", "none", false, "typed address or bookmark"},
		{"", "cross-site", false, "no destination at all keeps ordinary scoring"},

		// A fenced frame is unscorable whatever the site value: the loading
		// mode expects an opt-in response header Guardian does not send, so it
		// may never render at all.
		{"fencedframe", "cross-site", true, ""},
		{"fencedframe", "same-origin", true, "the opt-in is missing regardless of origin"},
		{"fencedframe", "", true, "and regardless of whether Sec-Fetch-Site arrives"},

		// Subresources are refused outright before scoring is ever reached, so
		// this predicate has nothing to say about them.
		{"image", "cross-site", false, "handled by isSubresourceDest"},
	}

	for _, c := range cases {
		if got := unscorableFrame(c.dest, c.site); got != c.want {
			t.Errorf("unscorableFrame(dest=%q, site=%q) = %v, want %v (%s)",
				c.dest, c.site, got, c.want, c.why)
		}
	}
}
