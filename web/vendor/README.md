# Vendored third-party assets

These files are committed into the repository and embedded into the `guardiand`
binary (`web/web.go`'s `//go:embed`) for direct/dev deployments. Release archives
also ship the Argon2id files separately so Angie can serve them directly from
`/usr/share/guardian/assets` without proxying public asset traffic through the
daemon. They remain same-origin and have no runtime dependency on a CDN.

## chart.umd.min.js

- **Library:** Chart.js
- **Version:** 4.5.1
- **Build:** UMD, minified (`dist/chart.umd.min.js`). The full UMD build
  auto-registers all controllers, scales, and elements, so the dashboard uses the
  global `window.Chart` directly with no `Chart.register(...)` calls.
- **License:** MIT (c) Chart.js Contributors
- **Upstream:** https://www.chartjs.org — source of the exact file is the npm
  registry tarball `https://registry.npmjs.org/chart.js/-/chart.js-4.5.1.tgz`,
  path `package/dist/chart.umd.min.js`.
- **Local edit:** the trailing `//# sourceMappingURL=chart.umd.min.js.map` comment
  was removed so the browser never requests a `.map` we do not serve. No other
  change.
- **SHA-256 (of the committed file, post-edit):**
  `84d0e233daba702b8f77d669d8c137cad36d441a10f200b6f2d3ab553bdfcf6b`

Verify the committed blob at any time with:

```sh
sha256sum web/vendor/chart.umd.min.js
```

This recorded hash is our integrity anchor (a same-origin embedded asset cannot use
Subresource Integrity), letting a reviewer confirm the blob was not tampered.

## chart-geo.umd.min.js

- **Library:** chartjs-chart-geo (Chart.js module for charting maps)
- **Version:** 4.3.6
- **Build:** UMD, minified (`build/index.umd.min.js`), renamed for clarity. The
  bundle is self-contained: d3-geo, d3-array, d3-color, d3-interpolate,
  d3-scale-chromatic and topojson-client are all rolled in, and it re-exports
  topojson as `ChartGeo.topojson`, so no second library is needed to turn the
  atlas below into GeoJSON features.
- **License:** MIT (c) Samuel Gratzl
- **Upstream:** https://www.sgratzl.com/chartjs-chart-geo/ — source of the exact
  file is the npm registry tarball
  `https://registry.npmjs.org/chartjs-chart-geo/-/chartjs-chart-geo-4.3.6.tgz`,
  path `package/build/index.umd.min.js`.
- **Local edit:** the trailing `//# sourceMappingURL=index.umd.min.js.map`
  comment was removed so the browser never requests a `.map` we do not serve.
  No other change.
- **SHA-256 (of the committed file, post-edit):**
  `b97d16a78122c6851e488d1e680479bfa4472b0f3beec21a992df09d97d3080e`

It declares a peer dependency on `chart.js ^4.1.0` (satisfied by the 4.5.1
above) and reads the `Chart` global at load time, so its `<script>` tag **must**
come after `chart.umd.min.js`. Like the full Chart.js UMD build, it
self-registers its controllers, scales and elements, so the dashboard needs no
`Chart.register(...)` call.

## hammer.min.js

- **Library:** Hammer.js (touch gesture recognition used by chartjs-plugin-zoom)
- **Version:** 2.0.8
- **Build:** Minified UMD (`hammer.min.js`).
- **License:** MIT (c) 2011-2014 Jorik Tangelder / Eight Media
- **Upstream:** https://hammerjs.github.io — source of the exact file is the npm
  registry tarball `https://registry.npmjs.org/hammerjs/-/hammerjs-2.0.8.tgz`,
  path `package/hammer.min.js`.
- **Local edit:** the trailing `sourceMappingURL` comment was removed so the
  browser never requests a map we do not serve. No other change.
- **SHA-256 (of the committed file, post-edit):**
  `48a49126467354ca90ce115e82149652c0ad5289f8d8651ce200d693dd78943c`

## chartjs-plugin-zoom.min.js

- **Library:** chartjs-plugin-zoom (wheel/pinch zoom and pointer pan for Chart.js)
- **Version:** 2.2.0
- **Build:** Minified UMD (`dist/chartjs-plugin-zoom.min.js`).
- **License:** MIT (c) 2013-2021 chartjs-plugin-zoom contributors
- **Upstream:** https://www.chartjs.org/chartjs-plugin-zoom/ — source of the
  exact file is the npm registry tarball
  `https://registry.npmjs.org/chartjs-plugin-zoom/-/chartjs-plugin-zoom-2.2.0.tgz`,
  path `package/dist/chartjs-plugin-zoom.min.js`.
- **Local edit:** no change (the published minified file has no source-map
  reference).
- **SHA-256 (of the committed file):**
  `e4a088e5bab93be6ee47c939eeb9ebaa80e0b39156d4bdfd1af9c844be81b6c4`

The UMD bundle reads both `Chart` and `Hammer` globals, so it must load after
Chart.js and Hammer.js. Its standard pan/zoom handlers expect Cartesian
min/max scales; the dashboard supplies projection-specific handlers for the
chartjs-chart-geo map.

## countries-110m.json

- **Data:** world-atlas — TopoJSON world map, 1:110m resolution
  (`countries` + `land` objects, 177 country geometries).
- **Version:** 2.0.2
- **License:** ISC (c) Michael Bostock. Derived from
  [Natural Earth](https://www.naturalearthdata.com), which is public domain.
- **Upstream:** npm registry tarball
  `https://registry.npmjs.org/world-atlas/-/world-atlas-2.0.2.tgz`, path
  `package/countries-110m.json`.
- **Local edit:** none.
- **SHA-256 (of the committed file):**
  `2516c915867c7baf18ddec727aec46c315541a07cfb3d79a6559b05d5e94eee8`

chartjs-chart-geo ships no map data, so the geometry has to come from
somewhere; this is that somewhere. The 110m resolution is deliberate: the 50m
and 10m variants are 739 KB and 3.5 MB for detail a dashboard-sized choropleth
cannot show. Country geometries are keyed by **ISO 3166-1 numeric** id, which
is why the dashboard carries an alpha-2 → numeric table (GeoIP returns
alpha-2). Note the atlas has fewer countries than GeoIP can report; the
dashboard lists the remainder beside the map rather than dropping them.

## Updating

1. Download the desired version's tarball from the npm registry
   (e.g. `https://registry.npmjs.org/chart.js/-/chart.js-<version>.tgz`).
2. Extract the vendored path to `web/vendor/`:
   - chart.js: `package/dist/chart.umd.min.js` → `chart.umd.min.js`
   - chartjs-chart-geo: `package/build/index.umd.min.js` → `chart-geo.umd.min.js`
   - Hammer.js: `package/hammer.min.js` → `hammer.min.js`
   - chartjs-plugin-zoom: `package/dist/chartjs-plugin-zoom.min.js` →
     `chartjs-plugin-zoom.min.js`
   - world-atlas: `package/countries-110m.json` → `countries-110m.json`
3. Remove the trailing `sourceMappingURL` comment from the JavaScript files.
4. Update the version and SHA-256 above.
5. Rebuild and run the dashboard; confirm charts and the map render and the
   browser makes no external request (see the dashboard-charts test notes / e2e).
