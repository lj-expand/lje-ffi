/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  apiSidebar: [
    { type: 'doc', id: 'intro', label: 'Introduction' },
    { type: 'doc', id: 'installation', label: 'Installation' },
    {
      type: 'category',
      label: 'Guides',
      collapsed: false,
      items: [
        'guides/quickstart'
      ]
    },
    {
      type: 'category',
      label: 'API Reference',
      collapsed: false,
      items: [
        'api/module',
        'api/mem',
        'api/call',
        'api/callback',
        'api/struct',
        'api/disasm',
        'api/vtable',
        'api/hook',
        'api/detour',
        'api/tcc',
      ],
    },
  ],
};

module.exports = sidebars;
