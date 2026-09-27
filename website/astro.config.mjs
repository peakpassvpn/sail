import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import mermaid from 'astro-mermaid';

export default defineConfig({
  site: 'https://peakpassvpn.github.io',
  base: '/sail',
  integrations: [
    mermaid({
      autoTheme: true,
      enableLog: false,
      mermaidConfig: {
        fontFamily: 'Inter, ui-sans-serif, system-ui, sans-serif',
        flowchart: { curve: 'basis', htmlLabels: true },
      },
    }),
    starlight({
      title: 'Sail',
      description: 'A unified Rust proxy platform for Clash, sing-box and Surge configuration ecosystems.',
      favicon: '/favicon.svg',
      defaultLocale: 'root',
      locales: {
        root: { label: 'English', lang: 'en' },
        zh: { label: '简体中文', lang: 'zh-CN' },
      },
      head: [
        { tag: 'meta', attrs: { name: 'robots', content: 'index, follow, max-image-preview:large' } },
        { tag: 'meta', attrs: { name: 'keywords', content: 'Rust proxy platform, Clash, sing-box, Surge, unified proxy core, VPN core' } },
        { tag: 'meta', attrs: { name: 'twitter:card', content: 'summary_large_image' } },
        { tag: 'meta', attrs: { property: 'og:image', content: 'https://peakpassvpn.github.io/sail/hero-network.png' } },
        { tag: 'meta', attrs: { name: 'twitter:image', content: 'https://peakpassvpn.github.io/sail/hero-network.png' } },
      ],
      logo: {
        src: './src/assets/sail-mark.svg',
        replacesTitle: false,
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/peakpassvpn/sail',
        },
      ],
      customCss: ['./src/styles/docs.css'],
      components: {
        ThemeSelect: './src/components/ThemeSwitch.astro',
        LanguageSelect: './src/components/LanguageSwitch.astro',
      },
      sidebar: [
        {
          label: 'Start here',
          translations: { 'zh-CN': '快速开始' },
          items: [
            { label: 'Getting started', translations: { 'zh-CN': '入门指南' }, slug: 'getting-started' },
            { label: 'Installation', translations: { 'zh-CN': '安装' }, slug: 'installation' },
            { label: 'CLI reference', translations: { 'zh-CN': 'CLI 参考' }, slug: 'cli' },
          ],
        },
        {
          label: 'Core guides',
          translations: { 'zh-CN': '核心指南' },
          items: [
            { label: 'Configuration', translations: { 'zh-CN': '配置模型' }, slug: 'configuration' },
            { label: 'Routing', translations: { 'zh-CN': '路由规则' }, slug: 'routing' },
            { label: 'TLS and fingerprints', translations: { 'zh-CN': 'TLS 与指纹' }, slug: 'tls-fingerprints' },
            { label: 'MPTP', slug: 'mptp' },
          ],
        },
        {
          label: 'Build and integrate',
          translations: { 'zh-CN': '构建与集成' },
          items: [
            { label: 'Protocols', translations: { 'zh-CN': '协议与兼容性' }, slug: 'protocols' },
            { label: 'Platform integration', translations: { 'zh-CN': '平台集成' }, slug: 'platform-integration' },
            { label: 'Architecture', translations: { 'zh-CN': '架构' }, slug: 'architecture' },
          ],
        },
        {
          label: 'Configuration reference',
          translations: { 'zh-CN': '配置参考' },
          items: [
            { slug: 'reference/common' },
            { slug: 'reference/inbounds' },
            { slug: 'reference/outbounds' },
            { slug: 'reference/transport' },
          ],
        },
        {
          label: 'Help',
          translations: { 'zh-CN': '帮助' },
          items: [
            { label: 'Troubleshooting', translations: { 'zh-CN': '故障排查' }, slug: 'troubleshooting' },
          ],
        },
      ],
    }),
  ],
});
