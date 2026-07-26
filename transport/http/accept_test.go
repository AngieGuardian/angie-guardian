// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import "testing"

// TestAcceptLooksNonNavigational pins a heuristic, so the table is weighted
// towards the cases where it must NOT fire. Refusing a challenge to something
// that could have solved it locks that client out of the site entirely, while
// failing to refuse one merely leaves today's behaviour in place, so every
// ambiguity resolves to false.
//
// The measured strings matter more than the invented ones: the Floorp 153 image
// value below is copied from a HAR of the real /favicon.ico load this work came
// from, and it ends */*;q=0.5 rather than the */*;q=0.8 an earlier draft assumed
// by analogy with Chrome.
func TestAcceptLooksNonNavigational(t *testing.T) {
	cases := []struct {
		values []string
		want   bool
		why    string
	}{
		// Nothing usable: unknown keeps the ordinary challenge path, the same
		// reasoning that makes an absent Sec-Fetch-Dest keep it.
		{nil, false, "absent: HTTP/1.0 clients, minimal tooling, a stripping proxy"},
		{[]string{""}, false, "present but empty says nothing"},
		{[]string{"   "}, false, "whitespace only says nothing"},
		{[]string{",,,"}, false, "only separators: legacy empty list elements, not a preference"},

		// Explicitly asks for HTML, so it may well be a navigation.
		{[]string{"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}, false,
			"the Fetch standard document value, sent by every mainstream browser"},
		{[]string{"text/html"}, false, "the plainest possible navigation"},
		{[]string{"text/html;charset=utf-8"}, false, "parameters are not part of the media range"},
		{[]string{"TEXT/HTML;q=0.9"}, false, "media types are case-insensitive"},
		{[]string{"  text/html  ,  application/json  "}, false, "surrounding whitespace is not significant"},
		{[]string{"text/*"}, false, "a text wildcard covers HTML; lean towards not refusing"},
		{[]string{"text/html;q=0"}, false,
			"formally rejects HTML, but q is not honoured: only a client being deliberately awkward sends this"},
		{[]string{"application/json", "text/html"}, false,
			"Accept may arrive as several field lines and text/html in any of them exempts the request"},

		// Asks for something a navigation would not, with no stronger signal
		// present. This is the population the refusal is for.
		{[]string{"*/*"}, true,
			"the favicon service, curl, and fetch() alike: formally accepts HTML, behaviourally never a navigation"},
		{[]string{"image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5"}, true,
			"measured from a Floorp 153 HAR of the real /favicon.ico load"},
		{[]string{"image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"}, true,
			"Chrome's image value"},
		{[]string{"application/json"}, true, "an API client or a stale SPA fetch()"},
		{[]string{"application/json", "image/png"}, true,
			"several field lines, none of them HTML"},
		{[]string{"text/plain"}, true, "text, but not a document a browser would render as one"},

		// Unparseable input condemns the whole header, not just the segment.
		// Deciding from noise is how a heuristic turns into a lockout, and
		// there is nothing to harden against: a farmer can send text/html and
		// be exempt whatever this does.
		{[]string{"garbage"}, false, "no type/subtype pair: unusable, so keep the ordinary path"},
		{[]string{"image/png, garbage"}, false, "one bad segment makes the whole header unusable"},
		{[]string{"/html"}, false, "empty type"},
		{[]string{"text/"}, false, "empty subtype"},
		{[]string{"image/png", "garbage"}, false, "unusable in any field line condemns all of them"},

		// Splitting on the first slash and requiring two non-empty halves
		// accepted all of these as confident non-navigation signals. RFC 9110
		// §12.5.1 says type and subtype are tokens and a wildcard type pairs
		// only with a wildcard subtype, so they are malformed and must keep the
		// ordinary path.
		{[]string{"text /html"}, false,
			"a stray space must not refuse a client that is plainly asking for HTML"},
		{[]string{"image/png/extra"}, false, "a second slash: '/' is not a token character"},
		{[]string{"image/p ng"}, false, "a space inside the subtype is not a token"},
		{[]string{"*/json"}, false, "a wildcard type pairs only with a wildcard subtype"},
		{[]string{"text/html extra"}, false, "trailing junk after a valid range is still malformed"},
		{[]string{"image/png;q=0.5, text /html"}, false,
			"one malformed segment condemns the header even when the others parse"},
		{[]string{"*/*"}, true, "the one wildcard-type range that is well formed"},

		// Round two: validating type and subtype but discarding everything
		// after the first semicolon is the same mistake in a different place.
		// A media range includes its parameters (RFC 9110 §5.6.6), and a q
		// parameter also has to satisfy the §12.4.2 weight grammar, which a
		// plain token check would not catch.
		{[]string{"application/json;garbage"}, false,
			"a bare token is not a parameter: parameter = name '=' value"},
		{[]string{"application/json;q=wat"}, false,
			"a token, but not a weight; checking token-ness alone lets this through"},
		{[]string{"application/json;q=1.5"}, false, "a weight outside 0..1"},
		{[]string{"application/json;q=0.1234"}, false, "more than three decimals"},
		{[]string{"application/json;q="}, false, "empty parameter value"},
		{[]string{"application/json;=0.5"}, false, "empty parameter name"},
		{[]string{"application/json;q = 0.5"}, false,
			"the grammar has no whitespace around '='; strictness here keeps the ordinary path"},
		{[]string{"application/json;charset=\"unterminated"}, false, "unterminated quoted string"},
		{[]string{";q=0.5"}, false, "parameters with no media range to attach to"},
		{[]string{"text/html;garbage"}, false,
			"malformed wins over the text/html exemption: the header is unusable either way"},

		{[]string{"application/json;q=0"}, true, "a weight of exactly 0 is well formed"},
		{[]string{"application/json;q=1"}, true, "and so is exactly 1"},
		{[]string{"application/json;q=1.000"}, true, "1 may be padded with zeroes"},
		{[]string{"application/json;charset=utf-8"}, true, "a token parameter value"},
		{[]string{"application/json;charset=\"utf-8\""}, true, "a quoted-string parameter value"},
		{[]string{"application/json;;q=0.5"}, true,
			"*( OWS ';' OWS [ parameter ] ) tolerates an empty element"},
		{[]string{"application/json ; q=0.5"}, true, "whitespace around a parameter is normal"},
	}

	for _, c := range cases {
		if got := acceptLooksNonNavigational(c.values); got != c.want {
			t.Errorf("acceptLooksNonNavigational(%q) = %v, want %v (%s)", c.values, got, c.want, c.why)
		}
	}
}
