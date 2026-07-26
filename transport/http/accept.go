// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import "strings"

// hdrAccept is the client's content-negotiation preference. Spelled in
// canonical MIME form, like the Sec-Fetch-* names in fetchdest.go, so
// Header.Get and Header.Values answer without rewriting the key.
//
// The Angie glue overrides only the X-Guardian-* set on the way to
// @guardian_challenge, so the client's own Accept arrives here intact. Which
// also means the documented off switch is `proxy_set_header Accept "";` in that
// location: withholding the header restores the pre-existing behaviour with no
// daemon config change, exactly as for Sec-Fetch-Dest.
const hdrAccept = "Accept"

// acceptLooksNonNavigational reports whether the client's Accept header is
// present, usable, and asks for something that a document navigation would not.
//
// Read the name literally: this is a behavioural judgement, not a semantic one,
// and the distinction is the whole reason the predicate exists in this shape.
// RFC 9110 §12.5.1 defines Accept as content-negotiation preference metadata,
// and "*/*" formally accepts every media type, HTML included, so a function
// called acceptExcludesHTML would be false on its face for the very request
// this was written for. What is true is narrower:
//
//	In mainstream browsers an ordinary document navigation normally includes an
//	explicit text/html media range. A present Accept without one is therefore a
//	strong non-navigation heuristic, not proof.
//
// It is only "normally" because the Fetch standard says browsers SHOULD send
// text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 for the
// document, frame and iframe destinations, not MUST, defaulting everything else
// to */*; Firefox implements that but lets the value be overridden through
// preferences; and fetch("/page"), curl, extensions and the browser's own
// internal services all send */* for URLs that return HTML.
//
// Because it is a heuristic it never decides alone. The caller consults it only
// after Sec-Fetch-Dest and Sec-Fetch-Mode have both come up empty, so a modern
// browser navigating over HTTPS is exempt on its destination whatever it asks
// for. Where Fetch metadata is unavailable (plain HTTP, older clients, a proxy
// that strips the headers) an unusual real navigation can still be refused;
// that is an accepted compatibility tradeoff, and the off switch above is how an
// operator hosting such clients opts out.
//
// Every remaining judgement call therefore leans towards NOT refusing:
//
//   - Absent, empty, or nothing but separators reads as unknown and returns
//     false, the same reasoning that makes an absent Sec-Fetch-Dest keep the
//     ordinary path (see isSubresourceDest).
//
//   - A segment that is not a well-formed media range makes the whole header
//     unusable, not merely that segment, and returns false. Refusing on
//     unparseable input would be deciding from noise, and this is a
//     false-positive reducer rather than a farming defence: a farmer can send
//     text/html and be exempt whatever this does, so there is nothing to
//     harden against here.
//
//     Well-formed means what RFC 9110 §12.5.1 says it means, checked rather
//     than assumed, and the media range includes its PARAMETERS. Type and
//     subtype must both be tokens, a wildcard type pairs only with a wildcard
//     subtype, each parameter must be name=value with a token name and a token
//     or quoted-string value, and a q parameter must match the §12.4.2 weight
//     grammar. Two rounds of review were needed to get this right, so the
//     failures are worth naming: splitting on the first slash and requiring two
//     non-empty halves accepted "text /html" (a lockout over a stray space, on
//     a client plainly asking for HTML), "image/png/extra" and "image/p ng";
//     then validating those two and discarding everything after the first
//     semicolon unexamined accepted "application/json;garbage" and
//     "application/json;q=wat". Both mistakes are the same shape, throwing
//     input away and calling the remainder parsed.
//
//     Parameter syntax is validated and parameter SEMANTICS are still ignored,
//     which is not a contradiction: q=0 is well formed, so it keeps the
//     ordinary path by the rule below rather than by being rejected here.
//
//     Splitting on "," and ";" ahead of quoted strings means a value legally
//     containing either separator is torn apart and read as malformed. That is
//     the safe direction (the request keeps the ordinary path) and nothing in
//     the wild sends one, so it is left as is rather than answered with a real
//     tokenizer.
//
//   - text/* counts as accepting HTML alongside text/html, for the same reason.
//
//   - q values are not honoured, so text/html;q=0 reads as accepting HTML even
//     though it formally rejects it. Nobody sends that except to be difficult,
//     and the lenient reading is the safe one.
//
// values is what Header.Values returns, not Header.Get: Accept may arrive as
// several field lines, and text/html appearing in any of them must exempt the
// request.
func acceptLooksNonNavigational(values []string) bool {
	usable := false
	for _, v := range values {
		for seg := range strings.SplitSeq(v, ",") {
			mediaRange, params, hasParams := strings.Cut(seg, ";")
			mediaRange = strings.TrimSpace(mediaRange)
			if mediaRange == "" {
				if hasParams {
					return false // parameters with nothing to attach to
				}
				continue // legacy empty list element; ignore, do not condemn
			}
			if hasParams && !validMediaParameters(params) {
				return false
			}
			mediaType, subtype, ok := strings.Cut(mediaRange, "/")
			if !ok || !isToken(mediaType) || !isToken(subtype) {
				return false
			}
			// media-range = "*/*" / (type "/" "*") / (type "/" subtype), so a
			// wildcard type with a concrete subtype ("*/json") is not one.
			if mediaType == "*" && subtype != "*" {
				return false
			}
			if strings.EqualFold(mediaType, "text") &&
				(subtype == "*" || strings.EqualFold(subtype, "html")) {
				return false
			}
			usable = true
		}
	}
	return usable
}

// validMediaParameters reports whether s, the part of a media range after its
// first semicolon, is a well-formed parameter list.
//
// RFC 9110 §5.6.6 gives parameters = *( OWS ";" OWS [ parameter ] ) with
// parameter = parameter-name "=" parameter-value, so an empty element is
// tolerated but a bare token is not a parameter: that is what rejects
// "application/json;garbage". A q parameter additionally has to satisfy the
// §12.4.2 weight grammar, which is what rejects "application/json;q=wat";
// checking only that the value is a token would let it through.
//
// Whitespace around each parameter is tolerated because real senders emit it.
// Whitespace around the "=" is not, since the grammar has none there and no
// sender produces it, and every strictness choice here fails towards keeping
// the ordinary challenge path.
func validMediaParameters(s string) bool {
	for p := range strings.SplitSeq(s, ";") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		name, value, ok := strings.Cut(p, "=")
		if !ok || !isToken(name) {
			return false
		}
		if !isToken(value) && !isQuotedString(value) {
			return false
		}
		if strings.EqualFold(name, "q") && !isWeight(value) {
			return false
		}
	}
	return true
}

// isWeight reports whether s matches the RFC 9110 §12.4.2 qvalue grammar:
// ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] ). Anything outside 0..1,
// or carrying more than three decimals, is malformed rather than merely
// unusual.
func isWeight(s string) bool {
	if s != "" && (s[0] == '0' || s[0] == '1') {
		if len(s) == 1 {
			return true
		}
		if s[1] != '.' || len(s) > 5 {
			return false
		}
		for i := 2; i < len(s); i++ {
			// A weight of 1 may only be padded with zeroes.
			if s[i] < '0' || s[i] > '9' || (s[0] == '1' && s[i] != '0') {
				return false
			}
		}
		return true
	}
	return false
}

// isQuotedString reports whether s is an RFC 9110 §5.6.4 quoted-string:
// DQUOTE *( qdtext / quoted-pair ) DQUOTE. Control characters are rejected, an
// unescaped inner quote ends the string early and so makes it malformed, and a
// trailing backslash leaves the string unterminated.
func isQuotedString(s string) bool {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return false
	}
	for i := 1; i < len(s)-1; i++ {
		switch c := s[i]; {
		case c == '\\':
			i++ // skip the escaped character
			if i >= len(s)-1 {
				return false
			}
		case c == '"':
			return false
		case c < 0x20 && c != '\t', c == 0x7f:
			return false
		}
	}
	return true
}

// tchar is the RFC 9110 §5.6.2 token character set, as a lookup table so the
// check costs no allocation on the challenge path.
var tchar = func() (t [256]bool) {
	for _, c := range "!#$%&'*+-.^_`|~" {
		t[c] = true
	}
	for c := '0'; c <= '9'; c++ {
		t[c] = true
	}
	for c := 'a'; c <= 'z'; c++ {
		t[c] = true
		t[c-32] = true // the upper-case half
	}
	return t
}()

// isToken reports whether s is a non-empty RFC 9110 token. Note that "/" is not
// a token character, so this is also what rejects a media range carrying a
// second slash; there is no separate check for that.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if !tchar[s[i]] {
			return false
		}
	}
	return true
}
