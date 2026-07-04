// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package web embeds the client-facing pages: the PoW challenge interstitial
// and the denied page. Everything is self-contained HTML (inline CSS + JS,
// solver workers via Blob URLs) so Guardian needs no asset routing.
package web

import "embed"

//go:embed challenge.html.tmpl denied.html
var FS embed.FS
