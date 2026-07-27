// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import "net/http"

// Metric outcome labels for the two ways a request can be refused a challenge.
// They double as refusalKind's return values so the label, the log line and the
// branch that produced them cannot disagree.
const (
	outcomeSubresourceRefused = "subresource_refused"
	outcomeAcceptRefused      = "accept_heuristic_refused"
)

// refusalNone is what the auth hop relays when it recorded a challenge, as
// distinct from relaying nothing at all. The difference matters: "nothing" means
// an Angie config that predates the relay, which has to keep working.
const refusalNone = "none"

// relayedRefusal reads the verdict the auth hop reached for this same client
// request, which Angie captures with auth_request_set and replays on the way
// into @guardian_challenge. It reports the refusal kind ("" when the auth hop
// recorded an ordinary challenge) and whether a verdict was relayed at all.
//
// The two hops are separate HTTP requests, so before this they each decided
// independently and could disagree in two ways, both of which put the decision
// log at odds with what the client was actually served:
//
//   - A config reload in the gap between them. The auth hop resolves
//     pow.refuse_unchallengeable from the snapshot live when it runs and the
//     challenge hop from the snapshot live when IT runs, so toggling the key
//     mid-flight makes one hop refuse while the other issues. Reproduced in
//     both directions; see TestRefusalVerdictSurvivesAReloadBetweenTheHops.
//   - Any difference in the headers reaching the two locations. Refusing is
//     decided from Sec-Fetch-* and Accept, and only the shipped config
//     guarantees both hops see the client's own values. Clearing or rewriting
//     one of them in a single location (an operator's own directive, a
//     third-party header module) silently drifts the hops apart.
//
// Relaying the verdict closes both, because the challenge hop stops deciding.
// Carrying the KIND rather than a bare "refused" flag is what closes the second
// one: the hop then needs no header of the client's to act, so it cannot be
// affected by a header it no longer reads.
//
// This follows what X-Guardian-Difficulty already does for the other half of
// the same decision (see handleChallenge), and inherits the same forgery
// question. With the shipped config the answer is that the client cannot reach
// it: proxy_set_header overwrites the header unconditionally, and an empty
// $guardian_refusal removes it. On a config too old to relay, a forged value is
// accepted, so weigh what it buys: "none" obtains an ordinary challenge, with
// ordinary escalation and difficulty, which the same client obtains anyway by
// sending Accept: text/html, since refusalKind is a statement about the request
// and not a farming defence. A forged kind refuses the forger. Neither is a
// gain, which is why the relay is trusted where the difficulty is clamped.
//
// An unrecognized value reads as "not relayed" so it fails to the local
// decision, never to a silent pass.
func relayedRefusal(h http.Header) (kind string, relayed bool) {
	switch v := h.Get(hdrRefusal); v {
	case refusalNone:
		return "", true
	case outcomeSubresourceRefused, outcomeAcceptRefused:
		return v, true
	}
	return "", false
}

// refusalKind reports why this request could never complete a PoW challenge,
// naming the cause, or "" if it might complete one.
//
// The auth path is the caller that matters: the decision it records should say
// "refused" rather than "challenge" for a request that was never going to solve
// anything (see core.RequestContext.Unchallengeable), and it relays the answer
// on to the hop that serves the refusal, which obeys it rather than asking
// again (see relayedRefusal). handleChallenge still asks directly when no
// verdict was relayed, which is an Angie config predating the relay.
//
// Note what is and is not config-dependent here, since it is what makes the
// relay small: this function reads headers only. Whether to act on it at all is
// pow.refuse_unchallengeable, and that gate is the only part a reload can move
// underneath a request already in flight.
//
// Cheap enough for the auth hot path by ordering: a document navigation is
// rejected by isDocumentDest and a subresource by isSubresourceDest, both plain
// switches over a short token, so only a request carrying no Fetch metadata at
// all ever reaches the Accept parse.
func refusalKind(h http.Header) string {
	dest := h.Get(hdrSecFetchDest)
	switch {
	case isSubresourceDest(dest):
		return outcomeSubresourceRefused
	case !isDocumentDest(dest) &&
		h.Get(hdrSecFetchMode) != modeNavigate &&
		acceptLooksNonNavigational(h.Values(hdrAccept)):
		return outcomeAcceptRefused
	}
	return ""
}

// hdrSecFetchDest is the Fetch Metadata request header naming what the client
// intends to do with the response: "document" for a navigation, "image" for an
// <img>, "empty" for fetch()/XHR, and so on. Browsers set it themselves on
// every request and page script cannot override it. The Angie glue replaces
// only the X-Guardian-* set on the way to @guardian_challenge, so the client's
// own value arrives at the challenge handler intact.
//
// Spelled in canonical MIME form, like the X-Guardian-* names above it, so
// Header.Get answers without rewriting the key.
// hdrSecFetchSite names the relationship between the initiator's origin and the
// requested one: "same-origin", "same-site", "cross-site", or "none" for a
// user-initiated load (typed address, bookmark). Set by the browser alongside
// Sec-Fetch-Dest and equally unforgeable from page script.
//
// hdrSecFetchMode names the request mode: "navigate" for a top-level or nested
// document load, "no-cors"/"cors" for subresources, "same-origin", "websocket".
// Only "navigate" is read here, as a second, independent way for a request to
// prove it is a navigation when its destination says nothing.
//
// All three headers are only sent to potentially-trustworthy URLs, i.e. HTTPS
// and localhost. A site served over plain HTTP receives none of them, which
// reads as unknown and keeps the ordinary path everywhere below: correct, but
// it means none of the false-positive protection in this file applies there.
// The Accept heuristic in accept.go is the one that does, precisely because it
// needs no Fetch metadata, and it consults the predicates here to decide when
// it must stay out of the way.
const (
	hdrSecFetchDest = "Sec-Fetch-Dest"
	hdrSecFetchSite = "Sec-Fetch-Site"
	hdrSecFetchMode = "Sec-Fetch-Mode"
)

// modeNavigate is the Sec-Fetch-Mode value of a document navigation.
const modeNavigate = "navigate"

// unscorableFrame reports whether a challenge request is a framed navigation
// that MAY be unable to render the interstitial, in which case the issuance is
// counted on the separate frame escalation counter (pow.BumpFrameEscalation),
// which raises difficulty but never reports a challenge_farm event.
//
// Note the asymmetry with isSubresourceDest, which is deliberate and is the
// whole design here. A subresource provably cannot run the page, so it is
// refused one outright. A frame only might not, so it is issued a challenge and
// merely never blocked for failing to solve it.
//
// "fencedframe" is unconditionally unscorable, whatever the site value. A
// fenced frame is a nested navigable, so the interstitial's frame-ancestors
// policy applies, and the loading mode additionally expects an opt-in response
// header that Guardian does not send. Whether that opt-in is strictly required
// is not something the incubating spec settles cleanly, which is exactly why
// this is the safe placement: issuing keeps it working if it can render, and
// never scoring keeps it harmless if it cannot.
//
// The reason an ordinary frame might not render: the interstitial is served with
// frame-ancestors 'self' and X-Frame-Options: SAMEORIGIN, so a browser refuses
// to render it in a foreign-origin frame, and the token cookie is SameSite=Lax,
// so a visitor who already holds a valid token does not even send it on a
// cross-site frame load and arrives looking unvouched. Counting those issuances
// makes the /favicon.ico bug remotely exploitable: any page can frame a
// protected URL in a loop and escalate an arbitrary visitor's IP (and behind a
// NAT everyone sharing that egress) into a challenge_farm block on a site the
// attacker does not control.
//
// The reason it is only "might": Sec-Fetch-Site is NOT an ancestor check.
// Fetch Metadata computes it over the request's whole URL list, comparing each
// hop against the INITIATOR's origin, and says nothing about the frame ancestor
// chain. So an A -> B -> A redirect (an SSO callback landing back in a
// same-origin iframe) arrives tagged cross-site even though the ancestor is
// still A, frame-ancestors 'self' permits it, and the page renders and solves
// perfectly well. A 403 there would break embedded login flows. Two different
// properties, and this header only approximates the one that matters, so it may
// deny the challenge nothing and must never deny the challenge itself.
//
// What this does NOT give up is progressive difficulty. These issuances are
// still escalated, on their own counter, so claiming a framed destination is
// not a route to unlimited cheap challenges. Only the block is withheld, that
// being the part which cannot be aimed safely when the signal is ambiguous.
func unscorableFrame(dest, site string) bool {
	return dest == "fencedframe" || (isFramedDest(dest) && isForeignSite(site))
}

// isFramedDest reports whether dest loads a document into a nested browsing
// context rather than the top level. These stay on the document side of
// isSubresourceDest because they really can render HTML and run script.
//
// "document" is deliberately absent: a top-level navigation is never framed, so
// a cross-site one is an ordinary inbound link from a search engine or another
// site and must be scored exactly as before.
func isFramedDest(dest string) bool {
	switch dest {
	case "frame", "iframe", "embed", "object":
		return true
	}
	return false
}

// isDocumentDest reports whether dest names a destination that renders a
// document, at the top level or nested. It is the exemption the Accept
// heuristic yields to: a request whose destination already tells us it is a
// navigation must keep the existing destination-driven path whatever it asks
// for, since the destination is the stronger signal and, unlike Accept, is set
// by the browser and unforgeable from page script.
//
// "Existing destination-driven path" is three paths, not one: a subresource is
// refused outright by isSubresourceDest, a foreign frame or a fencedframe is
// issued a challenge and left unscored by unscorableFrame, and anything else
// document-like gets the ordinary challenge with ordinary farm scoring. This
// predicate only keeps the Accept heuristic out of all three.
//
// Absent and unrecognized are deliberately NOT document-like here, which is
// what lets the heuristic act on the request this was written for: the browser's
// favicon service sends no Fetch metadata at all, even over HTTPS.
func isDocumentDest(dest string) bool {
	return dest == "document" || dest == "fencedframe" || isFramedDest(dest)
}

// isForeignSite reports whether site explicitly says something other than the
// target's own origin was involved in the request. "same-site" counts, because
// frame-ancestors 'self' and X-Frame-Options: SAMEORIGIN are origin checks, so
// a sibling subdomain cannot render the page either.
//
// "same-origin", "none", absent and unrecognized all fall through to ordinary
// scoring, so a site framing its own pages is escalated exactly as before and
// withholding the header is not a way around escalation.
func isForeignSite(site string) bool {
	switch site {
	case "cross-site", "same-site":
		return true
	}
	return false
}

// isSubresourceDest reports whether dest is a Fetch destination that provably
// cannot render the interstitial. The challenge page is an HTML document that
// solves its challenge with inline script and a blob: Web Worker, so only a
// request whose response will be parsed as a document has any way to complete
// it. An <img>, a stylesheet or an XHR is handed markup it cannot parse, let
// alone execute.
//
// This is an allowlist of destinations known to be subresources, not a
// denylist of the document-like ones, and the direction is load-bearing:
//
//   - Absent (old clients, most non-browsers, an intermediate that strips the
//     header) reads as unknown and keeps the ordinary challenge path. Reading
//     absence as "not a navigation" would hand every challenge farmer a
//     one-header bypass.
//   - A destination added to the Fetch standard after this list was written
//     also reads as unknown, so a future document-like destination is never
//     silently refused a challenge it could have solved.
//
// The list is every destination the Fetch standard currently defines that is
// processed as data, script or media, which is all of them except "document",
// "frame", "iframe", "embed" and "object". The last four are handled by
// isFramedDest instead: they can render HTML, but only same-origin.
//
// Matching is exact rather than case-folded or trimmed. The header is a
// standard-defined token that browsers emit in exactly this form; anything
// else is a non-conforming client, which belongs in the unknown bucket that
// keeps today's behaviour.
func isSubresourceDest(dest string) bool {
	switch dest {
	case "audio", "audioworklet", "empty", "font", "image", "json", "manifest",
		"paintworklet", "report", "script", "serviceworker", "sharedworker",
		"style", "text", "track", "video", "webidentity", "worker", "xslt":
		return true
	}
	return false
}
