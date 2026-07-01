// @ts-check
const { themes: prismThemes } = require('prism-react-renderer');
const fs = require('fs');
const path = require('path');

const SITE_URL = 'https://lj-expand.github.io';
const BASE_URL = '/lje-ffi/';

// The API pages render from static JSON (static/api/*.json) via a React
// component, so their MDX source carries no prose for docusaurus-plugin-llms to
// pick up. Expose the raw JSON as static assets and link them from the LLM
// files so machine consumers can fetch the structured docs directly.
const apiJsonDir = path.join(__dirname, 'static', 'api');
const apiJsonLinks = fs
  .readdirSync(apiJsonDir)
  .filter((f) => f.endsWith('.json'))
  .sort()
  .map((f) => {
    const name = f.replace(/\.json$/, '');
    return `- [ffi.${name}](${SITE_URL}${BASE_URL}api/${f}): machine-readable JSON reference for the \`ffi.${name}\` namespace`;
  })
  .join('\n');
const apiJsonSection = `## API reference (JSON)\n\nStructured JSON describing each \`ffi.*\` namespace — functions, parameters, returns, and errors. Fetch these for the full, machine-readable API surface (the HTML API pages are rendered from these files).\n\n${apiJsonLinks}`;

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'lje-ffi',
  tagline: 'Documentation for lje-ffi',
  url: SITE_URL,
  baseUrl: BASE_URL,
  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',
  onBrokenAnchors: 'ignore',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  plugins: [
    [
      require.resolve('@easyops-cn/docusaurus-search-local'),
      {
        docsRouteBasePath: '/',
        hashed: true,
      },
    ],
    [
      'docusaurus-plugin-llms',
      {
        logLevel: 'quiet',
        generateLLMsTxt: true,
        generateLLMsFullTxt: true,
        docsDir: 'content',
        title: 'lje-ffi',
        description: 'Extensive FFI binary module for LJE ranging from calling foreign functions, detouring them, and more.',
        excludeImports: true,
        removeDuplicateHeadings: true,
        generateMarkdownFiles: true,

        rootContent: apiJsonSection,
        fullRootContent: apiJsonSection,

        includeOrder: [
          'intro.mdx',
          'installation.md',
          'guides/*',
          'api/*',
        ],
      },
    ]
  ],

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          path: 'content',
          routeBasePath: '/',
          sidebarPath: require.resolve('./sidebars.js'),
        },
        blog: false,
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      navbar: {
        title: 'lje-ffi',
        items: [
          {
            type: 'docSidebar',
            sidebarId: 'apiSidebar',
            position: 'left',
            label: 'API Reference',
          },
          {
            href: 'https://github.com/lj-expand/lje-ffi',
            position: 'right',
            className: 'header-github-link',
            'aria-label': 'GitHub repository',
          },
        ],
      },
      footer: {
        style: 'dark',
        copyright: `lje-ffi documentation`,
      },
      prism: {
        theme: prismThemes.vsLight,
        darkTheme: prismThemes.vsDark,
        additionalLanguages: ['lua', 'toml'],
      },
    }),
};

module.exports = config;
