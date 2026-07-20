// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package web embeds the served pages: the PoW challenge interstitial, the
// denied page, and the admin reporting dashboard. The HTML is self-contained
// (inline CSS + JS, solver workers via Blob URLs). The dashboard's one library
// dependency, Chart.js, is vendored under vendor/ and embedded here too, served
// same-origin from the admin listener so Guardian needs no CDN and works
// air-gapped (see vendor/README.md).
package web

import "embed"

//go:embed challenge.html.tmpl denied.html dashboard.html vendor/chart.umd.min.js
var FS embed.FS
