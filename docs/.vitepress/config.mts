import { defineConfig } from 'vitepress'

// The site is served from / locally and from the Pages subpath in CI
// (the pages job derives DOCS_BASE from $CI_PAGES_URL).
const base = process.env.DOCS_BASE || '/'

export default defineConfig({
  lang: 'en-US',
  title: 'Angie Guardian',
  description:
    'A Web Application Firewall and proof-of-work bot firewall for Angie, written in Go.',
  base,
  cleanUrls: true,
  lastUpdated: true,

  head: [['link', { rel: 'icon', type: 'image/svg+xml', href: `${base}logo.svg` }]],

  themeConfig: {
    logo: '/logo.svg',

    nav: [
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
          ],
        },
        {
          text: 'Setup',
          items: [
            { text: 'Configuration', link: '/guide/configuration' },
            { text: 'Bots, GeoIP & Reputation', link: '/guide/bots-ip-intel' },
            { text: 'Wire it into Angie', link: '/guide/angie' },
            { text: 'Run it in Production', link: '/guide/production' },
          ],
        },
        {
          text: 'Operations',
          items: [
            { text: 'Admin API & Dashboard', link: '/guide/admin' },
            { text: 'Train the Anomaly Model', link: '/guide/anomaly' },
            { text: 'Load Testing', link: '/guide/load-testing' },
          ],
        },
        {
          text: 'Advanced',
          items: [{ text: 'WASM Module', link: '/guide/wasm' }],
        },
      ],
      '/reference/': [
        {
          text: 'Reference',
          items: [
            { text: 'Configuration Options', link: '/reference/configuration' },
            { text: 'Admin API', link: '/reference/admin-api' },
            { text: 'Metrics', link: '/reference/metrics' },
            { text: 'CLI Tools', link: '/reference/cli' },
          ],
        },
      ],
    },

    socialLinks: [
      { icon: 'gitlab', link: 'https://gitlab.melroy.org/melroy/angie-guardian' },
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
