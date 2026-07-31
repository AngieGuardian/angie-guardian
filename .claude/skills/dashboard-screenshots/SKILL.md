---
name: dashboard-screenshots
description: Recapture the four docs dashboard screenshots (top of page, IP lookup, top offenders + world map, Angie server traffic) with a freshly seeded guardiand and the Chrome DevTools MCP. Use when dashboard sections change, docs screenshots look stale, or the user asks to update/redo the dashboard screenshots.
---

# Dashboard screenshots for the docs

Produces the four images embedded in `docs/guide/admin.md`, saved directly into
`docs/public/`. All four share one fixed rendering setup (see "Zoom and
resolution" below); only the viewport height and scroll anchor differ per shot:

| File | Content | Scroll anchor (top at y=8) | Viewport height (CSS px) |
|------|---------|---------------------------|--------------------------|
| `dashboard.png` | Top of page: tiles, system health, decisions charts, funnel, solve-time cards, per-domain traffic | y=0 (no scroll) | ~1990, so the shot ends exactly with the Activity section (measure the "Active blocks" h2 top and subtract a few px) |
| `dashboard-lookup.png` | IP lookup card for the star offender: blocked chip + Unblock, geo/ASN line, decision history table | `#lookup-h2` | ~800 (`#lookup-card` bottom minus `#lookup-h2` top) |
| `dashboard-map.png` | Top offenders: world map + IP/reason/path/country tables, domains table, IP intelligence | the "Top offenders" h2 | ~1500 (through the end of the IP intelligence table) |
| `dashboard-angie.png` | Server traffic (Angie API): tiles, request-rate chart, per-zone tables, upstreams | `#angie-h2` | ~1415 (`#angie-cache-h2` top minus `#angie-h2` top; the caches section is NOT included) |

The hero must include charts ("people love charts").

## Zoom and resolution (set in stone)

- Browser zoom stays at **100%**. Never use Chrome page zoom or OS scaling; the
  "zoomed out" look comes entirely from the narrow emulated viewport below.
- One `emulate` call fixes the rendering: `colorScheme: "dark"` and viewport
  string `1280x<H>x2` — **1280 CSS px wide** (the dashboard's grid packs cards
  side by side at this width, which is what makes the shots read as zoomed
  out), `<H>` from the table above, **deviceScaleFactor 2** so every PNG comes
  out 2560 px wide and stays crisp when the docs page scales it down.
- Each screenshot is exactly one viewport: set `<H>` for the shot, scroll the
  anchor to 8 px from the top, then `take_screenshot` with a `filePath`
  straight into `docs/public/` (plain viewport shot: no `fullPage`, no element
  `uid`).
- The heights above are the values actually shipped (July 31 2026) but seeded
  data shifts layout by a few px per run, so re-measure instead of trusting
  them blindly: `getBoundingClientRect().top + window.scrollY` on the anchor
  and on the element that must NOT be in frame, height = the difference. A shot
  must never cut a card mid-way; end it on a section boundary.
- Scroll with `window.scrollTo(0, anchorTop - 8)` inside `evaluate_script`.
  Expect PNGs of roughly 0.5-0.7 MB each; there is no PNG optimizer on this
  machine, that size is fine.

For the lookup shot, submit `203.0.113.66` (the staged star offender) in the
`#lookup-form` and wait for the card: it should read "blocked" with a
`waf:dotfile-probe`-style reason, the Moscow / Bulletproof Hosting Ltd geo line
and a deny table full of scanner user agents. Capture while the behavioural
block (30m TTL) is still active. The ring is count-bounded, so the decision
rows survive after the seeder stops as long as no new traffic overwrites them.

## 1. Fresh instance, always re-seed first

State is a memory store, so a restart gives clean counters. Kill stale daemons
first (`pkill -f guardian.seed.yaml`; note `pgrep -x guardiand` for binaries,
the seed one usually runs via `go run`).

Copy `test/seed/guardian.seed.yaml` to the scratchpad and add under `admin:`:

```yaml
  angie_api:
    url: https://server.melroy.org/status/
```

That is the live test Angie (real bchexplorer.cash traffic, approved for docs
use) and it lights up the Server traffic section. Keep `log_level: warn` unless
debugging. Then, from the repo root:

```
go run ./cmd/guardiand -config <scratchpad>/guardian.screenshot.yaml   # background
make seed                                                              # 2 minutes
```

Wait for the admin API (`curl -H "Authorization: Bearer seed-demo-token"
http://127.0.0.1:18072/admin/stats`) before seeding.

## 2. Capture procedure (Chrome DevTools MCP), per shot

1. `new_page` → `http://127.0.0.1:18072/admin/dashboard#token=seed-demo-token`
   (once; the `#token=` fragment logs in without touching the gate form).
2. Inject the scrollbar killer via `evaluate_script`, guarded by an element id
   so it can be re-run safely; the lookup form submit navigates to `?ip=`, and
   any navigation drops injected styles, so re-inject before every shot:
   ```js
   ::-webkit-scrollbar{display:none} html{scrollbar-width:none}
   ```
3. `emulate` with `colorScheme: "dark"` and viewport `1280x<H>x2` for this
   shot's `<H>` (see the table and "Zoom and resolution").
4. For the hero: confirm the page auto-refreshed after the seeder exited (wait
   ~5 s, one 5 s refresh tick) so the tiles show the final counts. For the
   lookup: submit the star offender and wait for the card. Others: no prep.
5. Clear Chart.js tooltips (section 4), scroll the anchor to `anchorTop - 8`,
   and `take_screenshot` with `filePath` directly to `docs/public/<name>.png`.
6. Read the PNG back and inspect before moving on (section 5 checklist).

## 3. Timing is everything

The decisions ring retains only ~4 minutes and charts are anchored to "now":

- Capture the hero within ~10 seconds of the seeder exiting or the charts get a
  dead right-edge tail (an 80s delay ruins the take).
- Best-looking hero: after the first 2m seed, run `make seed SEEDTIME=100s`
  again and capture right at its end. The gap draws two attack waves and the
  right edge is full.
- The Store health row flips to a false red "degraded" a few minutes after
  traffic stops (ScanActiveBlocks capability probe counted as an op error,
  `core/store/instrumented.go` — see issue tracker). Another reason to shoot
  immediately; every health row must be green in the hero.

The map and Angie shots are not timing-sensitive.

## 4. Chart.js sticky-tooltip gotcha

A frozen hover tooltip can ride on any canvas chart and survives synthetic
mouseout/mouseleave AND the MCP hover tool. Before every shot that includes a
chart, clear it:

```js
for (const cv of document.querySelectorAll('canvas')) {
  const ch = Chart.getChart(cv);
  if (ch) { ch.setActiveElements([]); ch.tooltip?.setActiveElements([], {x:0,y:0}); ch.update('none'); }
}
```

## 5. Verify and ship

Read each PNG back and check: no tooltip, no scrollbar, green health rows, full
charts, section not cut mid-card. Then commit the images (plus any
`docs/guide/admin.md` caption changes), run `make docs-dev` and hand the user
`http://localhost:5173/guide/admin` to verify BEFORE pushing to main.
