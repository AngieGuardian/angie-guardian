import { defineConfig } from 'vitepress'

// The production site is served from the domain root (angieguardian.org), so
// base defaults to '/'. DOCS_BASE can still override it for a subpath deploy.
const base = process.env.DOCS_BASE || '/'

export default defineConfig({
  lang: 'en-US',
  title: 'Angie Guardian',
  description:
    'A Web Application Firewall and proof-of-work bot firewall for Angie, written in Go.',
  base,
  cleanUrls: true,
  lastUpdated: true,

  head: [['link', { rel: 'icon', type: 'image/svg+xml', href: `${base}logo_small.svg` }]],

  themeConfig: {
    logo: '/logo_small.svg',

    nav: [
      { text: 'Home', link: '/' },
      { text: 'Guide', link: '/guide/what-is-guardian', activeMatch: '/guide/' },
      { text: 'Reference', link: '/reference/configuration', activeMatch: '/reference/' },
      { text: 'Examples', link: '/examples', activeMatch: '/examples' },
    ],

    sidebar: {
      '/guide/': [
        {
          text: 'Introduction',
          items: [
            { text: 'What is Angie Guardian?', link: '/guide/what-is-guardian' },
            { text: 'Getting Started', link: '/guide/getting-started' },
            { text: 'Verify a Release', link: '/guide/release-verification' },
          ],
        },
        {
          text: 'Setup',
          items: [
            { text: 'Configuration', link: '/guide/configuration' },
            { text: 'Bots, GeoIP & Reputation', link: '/guide/bots-ip-intel' },
            { text: 'Wire it into Angie', link: '/guide/angie' },
            { text: 'Run it in Production', link: '/guide/production' },
            { text: 'Security Model & Limitations', link: '/guide/threat-model' },
          ],
        },
        {
          text: 'Operations',
          items: [
            { text: 'Admin API & Dashboard', link: '/guide/admin' },
            { text: 'Block Enforcement Offload', link: '/guide/block-offload' },
            { text: 'Attack Mode', link: '/guide/attack-mode' },
            { text: 'Train the Anomaly Model', link: '/guide/anomaly' },
            { text: 'Load Testing', link: '/guide/load-testing' },
            { text: 'Troubleshooting', link: '/guide/troubleshooting' },
          ],
        },
        {
          text: 'Advanced',
          items: [{ text: 'WASM Module', link: '/guide/wasm' }],
        },
        {
          text: 'Contributing',
          items: [{ text: 'Development', link: '/guide/development' }],
        },
      ],
      '/reference/': [
        {
          text: 'Reference',
          items: [
            { text: 'Configuration Options', link: '/reference/configuration' },
            { text: 'Admin API', link: '/reference/admin-api' },
            { text: 'Store Keys', link: '/reference/store-keys' },
            { text: 'Metrics', link: '/reference/metrics' },
            { text: 'CLI Tools', link: '/reference/cli' },
            { text: 'Compatibility & Versioning', link: '/reference/compatibility' },
          ],
        },
      ],
    },

    socialLinks: [
      { icon: 'gitlab', link: 'https://gitlab.melroy.org/melroy/angie-guardian' },
      { icon: 'github', link: 'https://github.com/AngieGuardian/angie-guardian' },
      { icon: 'telegram', link: 'https://t.me/angieguardian' },
      { icon: 'matrix', link: 'https://matrix.to/#/#angieguardian:melroy.org' },
    ],

    editLink: {
      pattern:
        'https://gitlab.melroy.org/melroy/angie-guardian/-/edit/main/docs/:path',
      text: 'Edit this page on GitLab',
    },

    search: { provider: 'local' },

    outline: { level: [2, 3] },

    footer: {
      message: 'Released under the AGPL-3.0 license.',
      copyright: 'Copyright © Melroy van den Berg',
    },
  },
})
