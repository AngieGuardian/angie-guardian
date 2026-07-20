# Vendored third-party assets

These files are committed into the repository and embedded into the `guardiand`
binary (`web/web.go`'s `//go:embed`). They are served **same-origin** from the
admin listener so the dashboard has **no runtime dependency on any CDN** and works
in air-gapped / restricted environments. Nothing here is fetched from the network
at build or run time.

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

## Updating

1. Download the desired version's tarball from the npm registry
   (`https://registry.npmjs.org/chart.js/-/chart.js-<version>.tgz`).
2. Extract `package/dist/chart.umd.min.js` to `web/vendor/chart.umd.min.js`.
3. Remove the trailing `sourceMappingURL` comment.
4. Update the version and SHA-256 above.
5. Rebuild and run the dashboard; confirm charts render and the browser makes no
   external request (see the dashboard-charts test notes / e2e).
