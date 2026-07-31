---
name: dashboard-screenshots
description: Recapture the four docs dashboard screenshots (top of page, IP lookup, top offenders + world map, Angie server traffic) with a freshly seeded guardiand and the Chrome DevTools MCP. Use when dashboard sections change, docs screenshots look stale, or the user asks to update/redo the dashboard screenshots.
---

# Dashboard screenshots for the docs

Produces the four images embedded in `docs/guide/admin.md`, saved directly into
`docs/public/`:

| File | Content | Framing |
|------|---------|---------|
| `dashboard.png` | Top of page: tiles, system health, decisions charts, funnel, solve-time cards, per-domain traffic | from y=0 through the end of the Activity section |
| `dashboard-lookup.png` | IP lookup card for the star offender: blocked chip + Unblock, geo/ASN line, decision history table | from `#lookup-h2` to the bottom of `#lookup-card` (~800px) |
| `dashboard-map.png` | Top offenders: world map + IP/reason/path/country tables, domains table, IP intelligence | from the "Top offenders" h2 to the end of IP intelligence |
| `dashboard-angie.png` | Server traffic (Angie API): tiles, request-rate chart, per-zone tables, upstreams | from `#angie-h2` up to (not including) `#angie-cache-h2` |

The hero must include charts ("people love charts").

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

## 2. Browser setup (Chrome DevTools MCP)

- `new_page` → `http://127.0.0.1:18072/admin/dashboard#token=seed-demo-token`
- `emulate` with `colorScheme: dark` and viewport `1280x<H>x2` (DPR 2 gives crisp
  2560px-wide PNGs). Set `<H>` per shot to the measured section height so each
  screenshot is exactly one viewport, then scroll the section top to y=8.
- Inject `::-webkit-scrollbar{display:none} html{scrollbar-width:none}` via
  `evaluate_script` (re-inject after any reload).
- Measure section offsets with `getBoundingClientRect().top + scrollY` on the
  h2 / `#angie-h2` elements; do not hardcode pixel offsets.

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
