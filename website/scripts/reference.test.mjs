// Tests of the reference generator, rule by rule, on a small configuration
// model written here. Run with `npm run test:config`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  applyCase, collapse, compatibilityPage, labelValue, lackingTypes, literalOf, parentOf, parseType,
  brokenLinks, render, simplifyGates, slug, splitPath, stale, variantOf,
} from './reference.mjs';
import { buildModel, rustDefault, rustJson, WORDS } from './reference.mjs';
import { buildSchema, kindSchema, validate } from './schema.mjs';

// ------------------------------------------------------------ fixture

const MODEL = 'sail/src/config/model.rs';
const LAYERS = 'sail/src/transport/layers.rs';
const DIAL = 'sail/src/net/dial/fields.rs';
const DNS = 'sail/src/app/dns/client/server.rs';

const field = (name, type, serde = '', docs = '', gates = []) => ({
  name, type, gates, attributes: { docs, metadata: serde ? [`serde (${serde})`] : [] },
});
const struct = (name, source, fields, { serde = '', docs = '', gates = [], derive = 'Deserialize' } = {}) => ({
  name, source, gates,
  attributes: { docs, metadata: [`derive (${derive})`, ...(serde ? [`serde (${serde})`] : [])] },
  shape: { fields },
});
const variant = (name, fields = [], metadata = []) => ({ name, attributes: { docs: '', metadata }, payload: '', fields });
const enumOf = (name, source, variants, { serde = '', derive = 'Deserialize' } = {}) => ({
  name, source, gates: [],
  attributes: { docs: '', metadata: [`derive (${derive})`, ...(serde ? [`serde (${serde})`] : [])] },
  shape: { variants },
});

function fixture() {
  const fields = {
    sing_box: 'v9.9',
    fields: [
      { path: 'log', json: 'object' },
      { path: 'log.level', json: 'string', enum: ['a', 'b'] },
      { path: 'log.old', json: 'bool', deprecated: true },
      { path: 'dns', json: 'object' },
      { path: 'dns.servers', json: 'array' },
      { path: 'dns.servers[].type', json: 'string', enum: ['udp'] },
      { path: 'dns.servers[udp].server', json: 'string' },
      { path: 'inbounds', json: 'array' },
      { path: 'inbounds[].type', json: 'string', enum: ['tun'] },
      { path: 'inbounds[tun].tag', json: 'string' },
      { path: 'inbounds[tun].mtu', json: 'number' },
      { path: 'outbounds', json: 'array' },
      { path: 'outbounds[].type', json: 'string', enum: ['x', 'y', 'z'], required: true },
      { path: 'outbounds[x].tag', json: 'string' },
      { path: 'outbounds[x].server', json: 'string', required: true },
      { path: 'outbounds[x].tls', json: 'object' },
      { path: 'outbounds[x].tls.enabled', json: 'bool' },
      { path: 'outbounds[y].tag', json: 'string' },
      { path: 'outbounds[y].tls', json: 'object' },
      { path: 'outbounds[y].tls.enabled', json: 'bool' },
      { path: 'outbounds[z].tag', json: 'string' },
      { path: 'outbounds[z].secret', json: 'string' },
      { path: 'route', json: 'object' },
      { path: 'route.rules', json: 'array' },
      { path: 'route.rules[].domain', json: 'listable-string' },
      { path: 'route.rules[action=route].outbound', json: 'string' },
    ],
  };
  const tiers = {
    sing_box: 'v9.9',
    supported: fields.fields.map(f => f.path).filter(p => !['log.old', 'outbounds[z].tag', 'outbounds[z].secret', 'outbounds[y].tls.enabled'].includes(p)),
    ignored: { 'Dropped | it changes nothing': ['log.old'] },
    unsupported: { 'A protocol sail does not implement': ['outbounds[z].tag', 'outbounds[z].secret'], 'Not yet': ['outbounds[y].tls.enabled'] },
  };
  const definitions = [
    struct('Config', MODEL, [
      field('log', 'Log', 'default'),
      field('dns', 'Dns', 'default'),
      field('inbounds', 'Vec < Inbound >', 'default'),
      field('outbounds', 'Vec < Outbound >', 'default'),
      field('route', 'Route', 'default'),
      field('api', 'Option < Api >', 'default', 'The control API, here.'),
      field('warnings', 'Vec < String >', 'skip'),
    ], { serde: 'deny_unknown_fields' }),
    struct('Log', MODEL, [field('level', 'Level', 'default'), field('format', 'Format', 'default', 'How lines look.')], { derive: 'Deserialize , Default' }),
    enumOf('Level', MODEL, [variant('A'), variant('B', [], ['default'])], { serde: 'rename_all = "lowercase"', derive: 'Deserialize , Default' }),
    enumOf('Format', MODEL, [variant('Full', [], ['default']), variant('Compact')], { serde: 'rename_all = "lowercase"', derive: 'Deserialize , Default' }),
    struct('Dns', MODEL, [field('servers', 'Vec < DnsServer >', 'default')]),
    struct('DnsServer', MODEL, [field('kind', 'String', 'rename = "type"'), field('tag', 'String', 'default'), field('options', 'Options', 'flatten')]),
    struct('RemoteOptions', DNS, [field('server', 'Option < String >', 'default', 'The server.')]),
    struct('Inbound', MODEL, [field('protocol', 'String', 'rename = "type"'), field('tag', 'String', 'default', 'Defaults to the type.'), field('options', 'Options', 'flatten')]),
    struct('Inbound', 'sail/src/runtime/options.rs', [field('other', 'bool')]),
    struct('InboundBlocks', LAYERS, [field('tls', 'Option < InboundTls >', 'default')]),
    struct('InboundTls', LAYERS, [field('enabled', 'bool', 'default')]),
    struct('TunInboundOptions', 'sail/src/protocol/tun/inbound.rs', [field('mtu', 'u32', 'default = "default_mtu"', 'The MTU.')]),
    struct('Outbound', MODEL, [field('protocol', 'String', 'rename = "type"'), field('tag', 'String', 'default'), field('options', 'Options', 'flatten')]),
    struct('DialFields', DIAL, [field('detour', 'Option < String >', 'default', 'Through another.'), field('bind', 'Option < String >', 'default')]),
    struct('OutboundBlocks', LAYERS, [field('dial', 'DialFields', 'flatten'), field('tls', 'Option < OutboundTls >', 'default')]),
    struct('OutboundTls', LAYERS, [field('enabled', 'bool', 'default', 'Turns TLS on.')]),
    struct('XOptions', 'sail/src/protocol/x/mod.rs', [field('server', 'String', '', ''), field('port', 'u16', 'default = "default_port"')], { serde: 'deny_unknown_fields' }),
    struct('YOptions', 'sail/src/protocol/y/options.rs', []),
    struct('GOptions', 'sail/src/protocol/g/mod.rs', [
      field('members', 'Vec < String >', 'with = "listable"', 'Who is in it.'),
      field('interval', 'Option < std :: time :: Duration >', 'default , with = "duration"'),
      field('url', 'String', 'default = "default_url"', '', ['feature = "probe"']),
      field('headers', 'HashMap < String , String >', 'default'),
      field('extra', 'Option < serde_json :: Value >', 'default'),
      field('either', 'Option < Listable >', 'default'),
      field('secret', 'Option < Secret < String > >', 'default'),
      field('token', 'Secret < String >', 'default'),
      field('ratio', 'f64', 'default'),
      field('flag', 'bool', 'default'),
      field('count', 'usize', 'default'),
      field('r#loop', 'bool', 'default'),
      field('hidden', 'bool', 'skip_deserializing'),
      field('policy', 'Policy', 'default'),
      field('bytes', '[u8 ; 4]', 'default'),
      field('backups', 'Vec < Backup >', 'default'),
    ]),
    enumOf('Listable', LAYERS, [variant('One', [field('', 'String')]), variant('Many', [field('', 'Vec < String >')])], { serde: 'untagged' }),
    struct('Secret', LAYERS, [field('', 'T')], { serde: 'transparent' }),
    struct('Policy', 'sail/src/protocol/g/mod.rs', [field('level', 'u8')]),
    struct('Backup', 'sail/src/protocol/g/mod.rs', [field('weight', 'u8')]),
    struct('Route', MODEL, [field('rules', 'Vec < Rule >', 'default')]),
    struct('Rule', MODEL, [
      field('domain', 'Vec < String >', 'default , with = "listable"', 'Domains.'),
      field('geo', 'List < String >', 'default , alias = "geosite"', 'Categories.'),
      field('outbound', 'Option < String >', 'default', 'Where it goes.'),
    ]),
    struct('Api', MODEL, [
      field('depth', 'u8'),
      field('listen', 'Option < std :: net :: SocketAddr >', 'default', 'Where it listens.'),
      field('timeout', 'Option < Duration >', 'default , with = "crate::config::model::duration"'),
      field('mode', 'Option < Mode >', 'default'),
    ], { serde: 'default' }),
    enumOf('Mode', MODEL, [variant('Http', [field('port', 'u16', '', 'Its port.')], ['serde (rename = "web")']), variant('Off')], { serde: 'tag = "type" , rename_all = "lowercase"' }),
  ];
  const registrations = [
    { registry: 'outbound', name: 'x', options: ['XOptions'], source: 'sail/src/protocol/x/mod.rs', gates: ['any (feature = "outbound-x" , feature = "inbound-x")', 'feature = "outbound-x"'], blocks: { dial: true, detour: true, tls: true } },
    { registry: 'outbound', name: 'y', options: ['YOptions'], source: 'sail/src/protocol/y/mod.rs', gates: [], blocks: { tls: true } },
    { registry: 'outbound', name: 'g', options: ['GOptions', 'GOptions'], source: 'sail/src/protocol/g/mod.rs', gates: ['feature = "outbound-g"'], blocks: {} },
    { registry: null, name: null, options: ['TunInboundOptions'], source: 'sail/src/protocol/tun/inbound.rs', gates: ['feature = "inbound-tun"'] },
  ];
  const functions = [
    { name: 'default_port', source: 'sail/src/protocol/x/mod.rs', body: '8080' },
    { name: 'default_mtu', source: 'sail/src/protocol/tun/inbound.rs', body: '9000' },
    { name: 'default_url', source: 'sail/src/protocol/g/mod.rs', body: 'health :: URL . to_string ()' },
  ];
  const extensions = [
    { path: 'api', sample: '{}', what: 'The control API' },
    { path: 'log.format', sample: '"compact"', what: 'Compact lines' },
    { path: 'outbounds[g].members', sample: '[]', what: 'A group' },
    { path: 'route.rules[].geo', sample: '[]', what: 'Categories, the registry says' },
  ];
  const compat = {
    'sing-box.md': '# sing-box compatibility\n\nIntro.\n\n## Summary\n\n| Section | Fields |\n|---|--:|\n| `log` | 3 |\n\n## `outbounds`\n\n### Types sail does not implement\n\n| Type | Tier | Note | Fields |\n|---|---|---|--:|\n| `outbounds[z]` | Error | A protocol sail does not implement | 2 |\n',
    'zh/sing-box.md': '# sing-box 兼容性\n\n| 部分 | 字段数 |\n|---|--:|\n| `log` | 3 |\n',
    'clash.md': '# Clash / Mihomo compatibility\n\nEvery field.\n\n| Section | Fields |\n|---|--:|\n| `dns` | 33 |\n\nAfter.\n',
    'zh/clash.md': null,
    'surge.md': null,
    'zh/surge.md': null,
  };
  const pages = [
    { slug: 'common', roots: ['', 'log', 'api'] },
    { slug: 'dns', roots: ['dns'] },
    { slug: 'inbounds', roots: ['inbounds'] },
    { slug: 'outbounds', roots: ['outbounds'] },
    { slug: 'route', roots: ['route'] },
  ];
  return { fields, tiers, extract: { definitions, registrations, functions, extensions }, compat, pages };
}

const built = () => render(fixture());
const row = (text, key) => text.split('\n').find(l => l.startsWith(`| \`${key}\` |`));
const section = (text, heading) => {
  const start = text.indexOf(heading);
  assert.ok(start >= 0, `no ${heading}`);
  const next = text.indexOf('\n## ', start + heading.length);
  return text.slice(start, next < 0 ? undefined : next);
};

// ------------------------------------------------------------ paths

test('paths split outside brackets', () => {
  assert.deepEqual(splitPath(''), []);
  assert.deepEqual(splitPath('a.b[c.d].e'), ['a', 'b[c.d]', 'e']);
  assert.deepEqual(parentOf('outbounds[x].tls.enabled'), { section: 'outbounds[x].tls', key: 'enabled' });
  assert.deepEqual(parentOf('log'), { section: '', key: 'log' });
  assert.deepEqual(variantOf('route.rules[action=route]'), { base: 'route.rules', label: 'action=route' });
  assert.deepEqual(variantOf('dns.servers[]'), { base: 'dns.servers', label: '' });
  assert.equal(variantOf('outbounds[x].tls'), null);
  assert.equal(labelValue('action=route'), 'route');
  assert.equal(labelValue('ws'), 'ws');
  assert.equal(slug('inbounds[vless].users[]'), 'inbounds-vless-users');
  assert.equal(slug(''), 'top');
});

test('serde names follow rename_all', () => {
  assert.equal(applyCase('PreferIpv4', 'snake_case', true), 'prefer_ipv4');
  assert.equal(applyCase('HijackDns', 'kebab-case', true), 'hijack-dns');
  assert.equal(applyCase('HttpUpgrade', 'lowercase', true), 'httpupgrade');
  assert.equal(applyCase('max_streams', 'kebab-case'), 'max-streams');
  assert.equal(applyCase('max_streams', 'camelCase'), 'maxStreams');
  assert.equal(applyCase('Ws', 'UPPERCASE', true), 'WS');
  assert.equal(applyCase('max_streams', undefined), 'max_streams');
  assert.throws(() => applyCase('a', 'nonsense'), /Unknown rename_all/);
});

test('types parse with their arguments', () => {
  const t = parseType('Option < HashMap < String , Vec < crate :: a :: B > > >');
  assert.equal(t.name, 'Option');
  assert.equal(t.args[0].name, 'HashMap');
  assert.deepEqual(t.args[0].args[1].args[0].path, ['crate', 'a', 'B']);
  assert.equal(parseType('[u8 ; 4]').name, 'array');
  assert.equal(parseType('(u8 , u16)').name, 'tuple');
});

test('a default function shows its literal, or its name', () => {
  assert.equal(literalOf('true'), 'true');
  assert.equal(literalOf('4_096'), '4096');
  assert.equal(literalOf('0.2'), '0.2');
  assert.equal(literalOf('"tcp" . to_string ()'), '"tcp"');
  assert.equal(literalOf('"/" . into ()'), '"/"');
  assert.equal(literalOf('String :: from ("a b")'), '"a b"');
  assert.equal(literalOf('health :: URL . to_string ()'), null);
});

test('gates drop an outer any() of an inner feature', () => {
  assert.deepEqual(simplifyGates(['any (feature = "a" , feature = "b")', 'feature = "a"', 'feature = "a"']), ['feature = "a"']);
  assert.deepEqual(simplifyGates(['feature = "a"', 'windows']), ['feature = "a"', 'windows']);
});

test('paths that differ in one label collapse', () => {
  assert.deepEqual(collapse(['outbounds[a].tls', 'outbounds[b].tls', 'http_clients[].tls']), ['outbounds[a, b].tls', 'http_clients[].tls']);
  assert.deepEqual(collapse(['route.default_domain_resolver']), ['route.default_domain_resolver']);
});

test('the support table gives the types sail lacks', () => {
  const t = lackingTypes('### Types sail does not implement\n\n| Type | Tier | Note | Fields |\n|---|---|---|--:|\n| `a[b]` | Warned | x \\| y | 3 |\n\n### `a`\n\n| `a[c]` | Error | no | 1 |\n');
  assert.deepEqual([...t.keys()], ['a[b]']);
  assert.deepEqual(t.get('a[b]'), { tier: 'ignored', reason: 'x | y', count: 3 });
});

// ------------------------------------------------------------ pages

test('both languages get every page, the shared one and the landing page', () => {
  const { files } = built();
  const names = ['common', 'dns', 'inbounds', 'outbounds', 'route', 'shared', 'compatibility'];
  assert.deepEqual(Object.keys(files).sort(), [...names.map(n => `reference/${n}.md`), ...names.map(n => `zh/reference/${n}.md`)].sort());
  assert.match(files['reference/outbounds.md'], /^---\ntitle: "Outbounds and groups"\ndescription: "Field-by-field reference of sail's native format: sing-box v9\.9 JSON and sail's extensions\."\n---\n/);
  assert.match(files['zh/reference/outbounds.md'], /^---\ntitle: "出站与策略组"\n/);
  assert.match(files['reference/compatibility.md'], /^---\ntitle: "Compatibility"\ndescription: "How sail reads sing-box, Clash \/ Mihomo and Surge configurations: the support tables\."\n---\n/);
  assert.match(files['reference/dns.md'], /sing-box v9\.9/);
});

test('a status is the measured tier, with its reason, or an extension', () => {
  const { files } = built();
  const en = files['reference/common.md'];
  assert.match(row(en, 'level'), /\| Supported \|/);
  assert.match(row(en, 'old'), /\| Warned: Dropped \\\| it changes nothing \(deprecated in sing-box\) \|/);
  assert.match(row(en, 'format'), /\| sail extension \|/);
  const zh = files['zh/reference/common.md'];
  assert.match(row(zh, 'level'), /\| 支持 \|/);
  assert.match(row(zh, 'old'), /\| 警告：Dropped \\\| it changes nothing \(sing-box 已弃用\) \|/);
  assert.match(row(zh, 'format'), /\| sail 扩展 \|/);
  assert.match(row(files['reference/outbounds.md'].split('## `outbounds[x]`')[1], 'server'), /\| required \| Supported \|/);
  // The generic entry: sing-box's `type`, required.
  assert.match(row(section(files['reference/outbounds.md'], '## `outbounds[]`'), 'type'), /\| string, one of `x`, `y`, `z` \| required \| Supported \|/);
});

test('a type is sing-box\'s for its fields, and read from Rust for extensions', () => {
  const { files } = built();
  const en = files['reference/common.md'];
  assert.match(row(en, 'level'), /\| string, one of `a`, `b` \|/);
  assert.match(row(en, 'format'), /\| string, one of `full`, `compact` \|/);
  const api = section(en, '## `api`');
  assert.match(row(api, 'listen'), /\| string \| unset \|/);
  assert.match(row(api, 'timeout'), /\| duration \| unset \|/);
  const g = section(files['reference/outbounds.md'], '## `outbounds[g]`');
  assert.match(row(g, 'members'), /\| string or array of string \|/);
  assert.match(row(files['zh/reference/outbounds.md'].split('## `outbounds[g]`')[1], 'members'), /\| string 或 数组，元素为 string \|/);
});

test('Rust types read as JSON types', () => {
  const g = section(built().files['reference/outbounds.md'], '## `outbounds[g]`');
  assert.match(row(g, 'headers'), /\| object of string \| `\{\}` \|/);
  assert.match(row(g, 'extra'), /\| any JSON \| unset \|/);
  assert.match(row(g, 'either'), /\| string or array of string \| unset \|/);
  assert.match(row(g, 'secret'), /\| string \| unset \|/);
  assert.match(row(g, 'token'), /\| string \| `""` \|/);
  assert.match(row(g, 'ratio'), /\| number \| the type's default \|/);
  assert.match(row(g, 'flag'), /\| bool \| `false` \|/);
  assert.match(row(g, 'count'), /\| number \| `0` \|/);
  assert.match(row(g, 'loop'), /\| bool \| `false` \|/);
  assert.equal(row(g, 'hidden'), undefined);
  assert.match(row(g, 'policy'), /\| object → \[object\]\(#outbounds-g-policy\) \| the type's default \|/);
  assert.match(row(g, 'bytes'), /\| array \|/);
  assert.match(row(g, 'backups'), /\| array of object → \[\[\]\]\(#outbounds-g-backups\) \| `\[\]` \|/);
  assert.match(section(built().files['reference/outbounds.md'], '## `outbounds[g]`'), /### `outbounds\[g\]\.backups\[\]`\n\n[^\n]*\n\n[^\n]*\n[^\n]*\n\| `weight` \| number \| required \| sail extension \|/);
});

test('a shared object taken under two names is titled by both', () => {
  const f = fixture();
  f.extract.definitions.find(d => d.name === 'GOptions').shape.fields.find(x => x.name === 'backups').type = 'Option < Policy >';
  const shared = render(f).files['reference/shared.md'];
  assert.match(shared, /## `policy \/ backups`\n\nUsed at: `outbounds\[g\]\.policy`, `outbounds\[g\]\.backups`/);
});

test('a default comes from serde: a literal, a function, a variant, unset or required', () => {
  const { files } = built();
  const en = files['reference/common.md'];
  assert.match(row(en, 'level'), /\| `b` \|/);
  assert.match(row(en, 'log'), /\| each field's default \|/);
  assert.match(row(section(en, '## `api`'), 'listen'), /\| unset \|/);
  assert.match(row(section(en, '## `api`'), 'depth'), /\| the object's default \|/);
  assert.match(row(section(files['reference/inbounds.md'], '## `inbounds[tun]`'), 'mtu'), /\| `9000` \|/);
  assert.match(row(section(files['reference/inbounds.md'], '## `inbounds[tun]`'), 'tag'), /\| `""` \|/);
  const g = section(files['reference/outbounds.md'], '## `outbounds[g]`');
  assert.match(row(g, 'url'), /\| `default_url\(\)` \|/);
  assert.match(row(g, 'members'), /\| required \|/);
  // A field sail does not read has none.
  assert.match(row(section(files['reference/outbounds.md'], '## `outbounds[y]`'), 'tag'), /\| string \| `""` \|/);
});

test('descriptions are source comments, else the registry\'s note, with build gates', () => {
  const { files } = built();
  const en = files['reference/common.md'];
  assert.match(row(en, 'api'), /\| The control API, here\. \|$/);
  assert.match(row(section(en, '## `log`'), 'format'), /\| How lines look\. \|$/);
  assert.match(row(en, 'level'), /\| — \|$/);
  const g = section(files['reference/outbounds.md'], '## `outbounds[g]`');
  assert.match(row(g, 'url'), /Build: `feature = "probe"` \|$/);
  assert.match(row(section(files['zh/reference/outbounds.md'], '## `outbounds[g]`'), 'url'), /构建条件：`feature = "probe"` \|$/);
});

test('a registered type reads its options, its blocks and its base', () => {
  const { files, unlisted } = built();
  const x = section(files['reference/outbounds.md'], '## `outbounds[x]`');
  assert.match(x, /Rust: \[`XOptions`\]\(https:\/\/github\.com\/peakpassvpn\/sail\/blob\/dev\/sail\/src\/protocol\/x\/mod\.rs\) · Build: `feature = "outbound-x"`\n/);
  // Rust fields sing-box does not list are not claimed, only reported.
  assert.equal(row(x, 'port'), undefined);
  assert.ok(unlisted.includes('outbounds[x].port'));
  assert.ok(unlisted.includes('outbounds[x].detour'));
  // y takes no dial fields.
  assert.ok(!unlisted.includes('outbounds[y].detour'));
  assert.ok(!unlisted.some(p => p.endsWith('.type')));
  // A rule's struct holds every action's fields: not each shape's.
  assert.ok(!unlisted.includes('route.rules[].outbound'));
});

test('DNS servers and the TUN inbound read what sail matches them to', () => {
  const { files } = built();
  assert.match(row(section(files['reference/dns.md'], '## `dns.servers[udp]`'), 'server'), /\| The server\. \|$/);
  const tun = section(files['reference/inbounds.md'], '## `inbounds[tun]`');
  assert.match(tun, /Build: `feature = "inbound-tun"`/);
  assert.match(row(tun, 'mtu'), /The MTU\./);
  assert.match(row(tun, 'tag'), /Defaults to the type\./);
});

test('a type sail does not have is its own section, from Rust', () => {
  const { files } = built();
  const g = section(files['reference/outbounds.md'], '## `outbounds[g]`');
  assert.match(g, /\*\*sail extension\*\*/);
  assert.match(row(g, 'members'), /\| sail extension \| Who is in it\. \|$/);
  assert.match(row(g, 'interval'), /\| sail extension \|/);
  const api = section(files['reference/common.md'], '## `api`');
  assert.match(row(api, 'mode'), /\| object → \[object\]\(#api-mode\), \[\[web\]\]\(#api-mode-web\) \|/);
  // A root's fields with typed shapes are top sections, as dns.servers.
  assert.match(row(section(files['reference/common.md'], '## `api.mode[web]`'), 'port'), /\| number \| required \| sail extension \| Its port\. \|$/);
  assert.match(row(section(files['reference/common.md'], '## `api.mode`'), 'type'), /\| string, one of `web`, `off` \| required \|/);
});

test('an alias matches a field by its other name', () => {
  const { files } = built();
  assert.match(row(section(files['reference/route.md'], '## `route.rules[]`'), 'geo'), /Categories\./);
});

test('a type sail lacks is a line in a table, which links point to', () => {
  const { files } = built();
  const en = files['reference/outbounds.md'];
  assert.doesNotMatch(en, /## `outbounds\[z\]`/);
  assert.match(en, /<a id="outbounds-missing"><\/a>\n\n## Types sail does not implement: `outbounds`\n/);
  assert.match(en, /\| `outbounds\[z\]` \| Error: A protocol sail does not implement \| 2 \|/);
  assert.match(files['reference/common.md'], /\[\[z\]\]\(\/sail\/reference\/outbounds\/#outbounds-missing\)/);
  assert.match(files['zh/reference/outbounds.md'], /## sail 未实现的类型：`outbounds`/);
});

test('a type the support table says sail lacks, but sail registers, fails', () => {
  const f = fixture();
  f.extract.registrations.push({ registry: 'outbound', name: 'z', options: [], source: 'sail/src/protocol/z.rs', gates: [], blocks: {} });
  assert.throws(() => render(f), /The support table says sail lacks outbounds\[z\], which it reads/);
});

test('objects alike in several places are written once, on the shared page', () => {
  const { files } = built();
  const shared = files['reference/shared.md'];
  // x's and y's tls differ in a tier: each inline.
  assert.doesNotMatch(shared, /## `tls`/);
  assert.match(files['reference/outbounds.md'], /### `outbounds\[x\]\.tls`/);
  // Make them alike, and they move.
  const f = fixture();
  f.tiers.supported.push('outbounds[y].tls.enabled');
  f.tiers.unsupported['Not yet'] = [];
  const again = render(f).files;
  assert.match(again['reference/shared.md'], /<a id="tls"><\/a>\n\n## `tls`\n\nUsed at: `outbounds\[x, y\]\.tls`/);
  assert.match(again['reference/outbounds.md'], /\[object\]\(\/sail\/reference\/shared\/#tls\)/);
  assert.match(again['zh/reference/outbounds.md'], /\[对象\]\(\/sail\/zh\/reference\/shared\/#tls\)/);
  assert.doesNotMatch(again['reference/outbounds.md'], /### `outbounds\[x\]\.tls`/);
});

test('an object no page roots is written under the field that takes it', () => {
  const f = fixture();
  f.pages = f.pages.filter(p => p.slug !== 'route');
  assert.match(render(f).files['reference/common.md'], /### `route\.rules\[\]`/);
});

test('shared objects of one name are told apart by where they are', () => {
  const f = fixture();
  f.tiers.supported.push('outbounds[y].tls.enabled');
  f.tiers.unsupported['Not yet'] = [];
  for (const t of ['u', 'v']) {
    f.fields.fields.push({ path: `outbounds[${t}].tls`, json: 'object' }, { path: `outbounds[${t}].tls.enabled`, json: 'bool' });
    f.tiers.supported.push(`outbounds[${t}].tls`);
    f.extract.registrations.push({ registry: 'outbound', name: t, options: [], source: `sail/src/protocol/${t}.rs`, gates: [], blocks: { tls: true } });
  }
  f.tiers.ignored.Other = ['outbounds[u].tls.enabled', 'outbounds[v].tls.enabled'];
  f.fields.fields.push({ path: 'dns.servers[udp].tls', json: 'object' }, { path: 'dns.servers[udp].tls.enabled', json: 'bool' });
  f.fields.fields.push({ path: 'dns.servers[tcp].tls', json: 'object' }, { path: 'dns.servers[tcp].tls.enabled', json: 'bool' });
  f.tiers.supported.push('dns.servers[udp].tls', 'dns.servers[udp].tls.enabled', 'dns.servers[tcp].tls', 'dns.servers[tcp].tls.enabled');
  const shared = render(f).files['reference/shared.md'];
  const headings = shared.split('\n').filter(l => l.startsWith('## '));
  assert.deepEqual(headings, ['## `tls` — dns.servers', '## `tls` — outbounds', '## `tls` — outbounds (2)']);
  assert.match(shared, /<a id="tls-outbounds-2"><\/a>/);
  assert.match(shared, /Used at: `outbounds\[u, v\]\.tls`/);
});

test('two sections with one anchor fail the build', () => {
  const f = fixture();
  // `outbounds[x].tls.x` and `outbounds[x].tls[x]` both slug to outbounds-x-tls-x.
  f.fields.fields.push({ path: 'outbounds[x].tls.x', json: 'object' }, { path: 'outbounds[x].tls.x.a', json: 'bool' }, { path: 'outbounds[x].tls[x].b', json: 'bool' });
  f.tiers.supported.push('outbounds[x].tls.x', 'outbounds[x].tls.x.a', 'outbounds[x].tls[x].b');
  assert.throws(() => render(f), /Anchors given twice in reference\/outbounds\.md: outbounds-x-tls-x/);
});

test('every field lands on a page, or the build fails', () => {
  const f = fixture();
  f.pages = f.pages.filter(p => p.slug !== 'route').map(p => ({ ...p, roots: p.roots.filter(r => r !== '') }));
  assert.throws(() => render(f), /Fields on no page: .*route\.rules\[\]\.domain/);
});

test('the registries must agree', () => {
  const f = fixture();
  f.tiers.supported = f.tiers.supported.filter(p => p !== 'log.level');
  assert.throws(() => render(f), /No tier measured for log\.level/);
  const g = fixture();
  g.extract.extensions.push({ path: 'log.level', sample: '"a"', what: 'x' });
  assert.throws(() => render(g), /Extension is a sing-box field: log\.level/);
  const h = fixture();
  h.tiers.supported.push('log.nothing');
  assert.throws(() => render(h), /Tier for a field sing-box does not have: log\.nothing/);
});

test('an ambiguous type name fails', () => {
  const f = fixture();
  f.extract.definitions.push(struct('Rule', 'sail/src/other/a.rs', []), struct('Rule', 'sail/src/other/b.rs', []));
  f.extract.definitions = f.extract.definitions.filter(d => !(d.name === 'Rule' && d.source === MODEL));
  assert.throws(() => render(f), /Ambiguous type Rule/);
});

test('fields sail reads without a comment are listed', () => {
  const { undocumented } = built();
  assert.ok(undocumented.includes('XOptions.server (outbounds[x].server)'));
  assert.ok(!undocumented.some(u => u.startsWith('OutboundTls.enabled')));
});

test('every link into the reference has its anchor', () => {
  assert.deepEqual(brokenLinks(built().files), []);
  const f = fixture();
  f.tiers.supported.push('outbounds[y].tls.enabled');
  f.tiers.unsupported['Not yet'] = [];
  assert.deepEqual(brokenLinks(render(f).files), []);
  assert.deepEqual(brokenLinks({ 'reference/a.md': '[x](#nowhere) [y](/sail/reference/b/#here) [z](/sail/zh/reference/b/#here)', 'reference/b.md': '<a id="here"></a>' }), ['reference/a.md: #nowhere', 'reference/a.md: /sail/zh/reference/b/#here']);
});

// ------------------------------------------------------------ compat

test('the landing page takes each table\'s first table, and says which are absent', () => {
  const { compat } = fixture();
  const en = compatibilityPage('en', compat, 'v9.9');
  assert.match(en, /## sing-box\n\nFull table: \[docs\/compat\/sing-box\.md\]\(https:\/\/github\.com\/peakpassvpn\/sail\/blob\/dev\/docs\/compat\/sing-box\.md\) · Chinese: \[docs\/compat\/zh\/sing-box\.md\]/);
  assert.match(en, /### Summary\n\n\| Section \| Fields \|\n\|---\|--:\|\n\| `log` \| 3 \|\n\n/);
  assert.match(en, /## Clash \/ Mihomo\n\nFull table: [^\n]*clash\.md\)\n\n### Summary\n\n\| Section \| Fields \|\n\|---\|--:\|\n\| `dns` \| 33 \|\n\n## Surge/);
  assert.match(en, /## Surge\n\nAbsent in this revision\.\n/);
  const zh = compatibilityPage('zh', compat, 'v9.9');
  assert.match(zh, /\| 部分 \| 字段数 \|/);
  // No Chinese table: the English one.
  assert.match(zh, /## Clash \/ Mihomo\n\n完整表格：[^\n]*\n\n### 汇总\n\n\| Section \| Fields \|/);
  assert.match(zh, /## Surge\n\n本版本尚无。/);
});

test('stale pages are those that differ, are missing or are left over', () => {
  const disk = { 'reference/a.md': 'same', 'reference/b.md': 'old', 'reference/c.md': 'left' };
  const files = { 'reference/a.md': 'same', 'reference/b.md': 'new', 'reference/d.md': 'new' };
  assert.deepEqual(stale(files, n => disk[n] ?? null, () => Object.keys(disk)).sort(), ['reference/b.md', 'reference/c.md', 'reference/d.md']);
  assert.deepEqual(stale({ 'reference/a.md': 'same' }, n => disk[n] ?? null, () => ['reference/a.md']), []);
});

// ------------------------------------------------------------ schema

const schemaOf = () => buildSchema(buildModel(fixture()), { version: 'v9.9', id: 'https://example.com/schema.json', title: 't', description: 'd' });
const errorsOf = value => validate(schemaOf(), value);

test('the schema takes a configuration sail takes, and no field it does not list', () => {
  assert.deepEqual(errorsOf({ log: { level: 'a' }, outbounds: [{ type: 'x', tag: 'p', server: 's', tls: { enabled: true } }] }), []);
  assert.deepEqual(errorsOf({ log: { colour: true } }), ['log.colour: not a field here']);
  assert.deepEqual(errorsOf({ outbounds: [{ type: 'x', tag: 'p' }] }), ['outbounds[0]: server is required']);
  // sail's own enum is what it takes.
  assert.deepEqual(errorsOf({ log: { level: 'c' } }), ['log.level: "c" is none of a, b']);
});

test('a field sail refuses is not allowed, with why; one it warns of is deprecated', () => {
  const schema = schemaOf();
  const y = schema.$defs['outbounds[y]'].properties.tls.$ref;
  const tls = schema.$defs[decodeURIComponent(y.replace('#/$defs/', ''))];
  assert.deepEqual(tls.properties.enabled, { not: {}, description: 'sail refuses this field: Not yet' });
  assert.deepEqual(errorsOf({ outbounds: [{ type: 'y', tls: { enabled: true } }] }), ['outbounds[0].tls.enabled: sail refuses this field: Not yet']);
  const old = schema.properties.log;
  const log = schema.$defs[decodeURIComponent(old.$ref.replace('#/$defs/', ''))];
  assert.equal(log.properties.old.deprecated, true);
  assert.match(log.properties.old.description, /^sail ignores this field, with a warning: Dropped \| it changes nothing/);
});

test('entries are told apart by their type, and a type sail refuses is none of them', () => {
  const schema = schemaOf();
  assert.deepEqual(schema.properties.outbounds.items.properties.type.enum, ['g', 'x', 'y']);
  assert.deepEqual(errorsOf({ outbounds: [{ type: 'z', tag: 'p' }] }), ['outbounds[0].type: "z" is none of g, x, y']);
  // A field of another type is not one of this type's.
  assert.deepEqual(errorsOf({ outbounds: [{ type: 'y', server: 's' }] }), ['outbounds[0].server: not a field here']);
  assert.deepEqual(errorsOf({ outbounds: [{ tag: 'p' }] }), ['outbounds[0]: type is required']);
});

test('a rule takes its action\'s fields, and its conditions one value or a list', () => {
  assert.deepEqual(errorsOf({ route: { rules: [{ domain: 'a', action: 'route', outbound: 'x' }, { domain: ['a', 'b'] }] } }), []);
  assert.deepEqual(errorsOf({ route: { rules: [{ domain: 1 }] } }), ['route.rules[0].domain: number, not string']);
  // The model's `List` reads as a `Vec` read `with = "listable"` does.
  assert.deepEqual(errorsOf({ route: { rules: [{ geo: 'a' }, { geo: ['a', 'b'] }] } }), []);
  assert.deepEqual(errorsOf({ route: { rules: [{ geo: 1 }] } }), ['route.rules[0].geo: number, not string']);
});

test('a List is documented as a listable Vec is', () => {
  const model = buildModel(fixture());
  const vec = { type: 'Vec < String >', meta: 'default , with = "listable"', owner: { source: MODEL } };
  const list = { type: 'List < String >', meta: 'default', owner: { source: MODEL } };
  for (const w of [WORDS.en, WORDS.zh]) {
    assert.equal(rustJson(model, list.type, MODEL, list.meta, w), rustJson(model, vec.type, MODEL, vec.meta, w));
    assert.equal(rustDefault(model, list, w), rustDefault(model, vec, w));
  }
  assert.equal(rustDefault(model, list, WORDS.en), '`[]`');
});

test('a listable union takes one of its kinds or a list of them', () => {
  const s = { $defs: {}, ...kindSchema('listable-number|string') };
  for (const v of [1, 'a', [1, 'a']]) assert.deepEqual(validate(s, v), [], JSON.stringify(v));
  assert.equal(validate(s, true).length, 1);
  assert.deepEqual(kindSchema('number|duration'), { anyOf: [{ type: 'number' }, { type: 'string' }] });
});

test('a map of objects takes any key, each value such an object', () => {
  const f = fixture();
  f.extract.definitions.find(d => d.name === 'Config').shape.fields.push(field('limits', 'HashMap < String , Policy >', 'default'));
  f.extract.extensions.push({ path: 'limits', sample: '{}', what: 'Limits by name' });
  const schema = buildSchema(buildModel(f), { version: 'v9.9', id: 'x', title: 't', description: 'd' });
  assert.deepEqual(validate(schema, { limits: { alice: { level: 1 }, bob: {} } }), []);
  assert.deepEqual(validate(schema, { limits: { alice: { speed: 1 } } }), ['limits.alice.speed: not a field here']);
});
