// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package web embeds the served pages: the PoW challenge interstitial, the
// denied page, and the admin reporting dashboard. The HTML is self-contained
// (inline CSS + JS, with a Blob SHA-256 worker or content-addressed same-origin
// Argon2id worker/runtime/WASM). The dashboard's library
// dependencies (Chart.js, its geo/zoom modules, Hammer.js, and the TopoJSON
// world atlas the map draws) are vendored under vendor/ and embedded here too,
// served same-origin from the admin listener so Guardian needs no CDN and
// works air-gapped (see vendor/README.md).
package web

import "embed"

//go:embed challenge.html.tmpl denied.html dashboard.html
//go:embed vendor/chart.umd.min.js vendor/chart-geo.umd.min.js vendor/hammer.min.js vendor/chartjs-plugin-zoom.min.js vendor/countries-110m.json
//go:embed vendor/guardian-argon2/*
var FS embed.FS
