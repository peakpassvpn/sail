// The configuration reference: sail's native format, sing-box's JSON and
// sail's extensions, object by object. Everything here is pure, so that the
// tests can feed it small inputs; build-config.mjs reads the real ones.
//
// Inputs:
// - `fields`: sing-box's field registry (sail/src/config/singbox/fields.json);
// - `tiers`: what the registry test measured sail does with each field
//   (fields.tiers.json);
// - `extract`: what website/tools/config-extract reads from sail's source:
//   the types serde reads, the protocols registered, default functions and
//   the registry test's list of extensions;
// - `compat`: the support tables in docs/compat, by file name, or null.

export const REPO = 'https://github.com/peakpassvpn/sail/blob/dev/';

// ---------------------------------------------------------------- paths

/** A registry path's segments: `a.b[c.d].e` is `a`, `b[c.d]`, `e`. */
export function splitPath(path) {
  if (path === '') return [];
  const out = [];
  let depth = 0;
  let cur = '';
  for (const ch of path) {
    if (ch === '[') depth++;
    if (ch === ']') depth--;
    if (ch === '.' && depth === 0) {
      out.push(cur);
      cur = '';
    } else cur += ch;
  }
  out.push(cur);
  return out;
}

/** The object a field is in, and its key there. */
export function parentOf(path) {
  const t = splitPath(path);
  return { section: t.slice(0, -1).join('.'), key: t[t.length - 1] };
}

/** `a.b[x]`: one shape of the field `a.b`, `x` (by type, or `action=`). */
export function variantOf(section) {
  const t = splitPath(section);
  if (!t.length) return null;
  const m = /^(.*)\[([^\]]*)\]$/.exec(t[t.length - 1]);
  if (!m) return null;
  return { base: [...t.slice(0, -1), m[1]].join('.'), label: m[2] };
}

/** The value a variant's label selects: `action=route` is `route`. */
export function labelValue(label) {
  return label.includes('=') ? label.slice(label.indexOf('=') + 1) : label;
}

export function slug(id) {
  return id.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'top';
}

// ---------------------------------------------------------------- serde

const compact = t => t.replace(/\s+/g, '');
export const serdeOf = attributes => attributes.metadata.filter(a => a.startsWith('serde')).join(' ');
const arg = (meta, name) => meta.match(new RegExp(`\\b${name}\\s*=\\s*"([^"]+)"`))?.[1];

/** A Rust name as serde's `rename_all` writes it. */
export function applyCase(name, rule, variant = false) {
  if (!rule) return name;
  const words = variant ? name.split(/(?=[A-Z])/).map(w => w.toLowerCase()) : name.split('_');
  switch (rule) {
    case 'lowercase': return variant ? name.toLowerCase() : name;
    case 'UPPERCASE': return name.toUpperCase();
    case 'snake_case': return words.join('_');
    case 'kebab-case': return words.join('-');
    case 'SCREAMING_SNAKE_CASE': return words.join('_').toUpperCase();
    case 'SCREAMING-KEBAB-CASE': return words.join('-').toUpperCase();
    case 'camelCase': return words.map((w, i) => (i ? w[0].toUpperCase() + w.slice(1) : w)).join('');
    case 'PascalCase': return words.map(w => w[0].toUpperCase() + w.slice(1)).join('');
    default: throw new Error(`Unknown rename_all rule: ${rule}`);
  }
}

/** Parses a Rust type into `{ name, path, args }`. */
export function parseType(text) {
  const s = compact(text);
  let i = 0;
  function one() {
    if (s[i] === '&') { i++; while (/[a-z']/.test(s[i]) && s.slice(i, i + 3) !== 'mut') i++; return one(); }
    if (s[i] === '(' || s[i] === '[') {
      const close = s[i] === '(' ? ')' : ']';
      i++;
      const args = [];
      while (s[i] !== close && i < s.length) { args.push(one()); if (s[i] === ',' || s[i] === ';') i++; while (/[0-9]/.test(s[i])) i++; }
      i++;
      return { name: close === ')' ? 'tuple' : 'array', path: [], args };
    }
    let path = '';
    while (i < s.length && /[A-Za-z0-9_:]/.test(s[i])) path += s[i++];
    const node = { path: path.split('::').filter(Boolean), args: [] };
    node.name = node.path[node.path.length - 1];
    if (s[i] === '<') {
      i++;
      while (s[i] !== '>' && i < s.length) {
        node.args.push(one());
        if (s[i] === ',') i++;
      }
      i++;
    }
    return node;
  }
  return one();
}

// ---------------------------------------------------------------- words

export const WORDS = {
  en: {
    field: 'Field', type: 'Type', default: 'Default', status: 'Status', doc: 'Description',
    supported: 'Supported', ignored: 'Warned', unsupported: 'Error', extension: 'sail extension',
    deprecated: 'deprecated in sing-box', build: 'Build', rust: 'Rust', and: ' and ',
    required: 'required', unset: 'unset', objectDefault: 'the object\'s default', typeDefault: 'the type\'s default',
    object: 'object', arrayOf: 'array of', objectOf: 'object of', or: ' or ', oneOf: 'one of', any: 'any JSON',
    seconds: 'duration, or a number of seconds', shapes: 'shapes',
    top: 'Top level', missing: 'Types sail does not implement', fieldsCount: 'Fields',
    usedAt: 'Used at', sharedIntro: 'Objects that several fields take with the same fields, types and tiers, written once. Each lists the fields it belongs to.',
    notIn: 'Absent in this revision.', table: 'Full table', summary: 'Summary', zhTable: 'Chinese', colon: ': ', fieldsDefault: 'each field\'s default',
  },
  zh: {
    field: '字段', type: '类型', default: '默认', status: '状态', doc: '说明',
    supported: '支持', ignored: '警告', unsupported: '报错', extension: 'sail 扩展',
    deprecated: 'sing-box 已弃用', build: '构建条件', rust: 'Rust 定义', and: ' 且 ',
    required: '必填', unset: '未设置', objectDefault: '所在对象的默认值', typeDefault: '类型的默认值',
    object: '对象', arrayOf: '数组，元素为', objectOf: '对象，值为', or: ' 或 ', oneOf: '取值', any: '任意 JSON',
    seconds: '时长，或秒数', shapes: '形态',
    top: '顶层', missing: 'sail 未实现的类型', fieldsCount: '字段数',
    usedAt: '所在位置', sharedIntro: '多处字段取用、字段、类型与分级均相同的对象，在此统一列出，并注明所在位置。',
    notIn: '本版本尚无。', table: '完整表格', summary: '汇总', zhTable: '中文版', colon: '：', fieldsDefault: '各字段取默认值',
  },
};

// ---------------------------------------------------------------- model

// DNS server types and the options each reads, as
// sail/src/app/dns/client/server.rs matches `type` to them.
export const DNS_SERVER_OPTIONS = {
  udp: 'RemoteOptions', tcp: 'RemoteOptions', tls: 'RemoteOptions', https: 'RemoteOptions',
  quic: 'RemoteOptions', h3: 'RemoteOptions', local: 'LocalOptions', mdns: 'MdnsOptions',
  hosts: 'HostsOptions', fakeip: 'FakeIpOptions', race: 'RaceOptions',
};
export const DNS_SERVER_SOURCE = 'sail/src/app/dns/client/server.rs';
// Inbounds the inbound manager builds itself, not through the registry.
export const UNREGISTERED_INBOUNDS = { tun: { options: 'TunInboundOptions', source: 'sail/src/protocol/tun/inbound.rs' } };
const MODEL = 'sail/src/config/model.rs';
const REGISTRIES = { inbounds: 'inbound', outbounds: 'outbound', endpoints: 'endpoint' };

/** Everything the pages are made of, before words. */
export function buildModel({ fields, tiers, extract, compat = {} }) {
  const lacking = lackingTypes(compat['sing-box.md'] || '');
  const info = new Map();
  for (const f of fields.fields) {
    info.set(f.path, { path: f.path, origin: 'sing-box', json: f.json, enum: f.enum, required: !!f.required, deprecated: !!f.deprecated });
  }
  for (const path of tiers.supported) tierOf(path).tier = 'supported';
  for (const [tier, groups] of [['ignored', tiers.ignored], ['unsupported', tiers.unsupported]]) {
    for (const [reason, paths] of Object.entries(groups)) {
      for (const path of paths) Object.assign(tierOf(path), { tier, reason });
    }
  }
  function tierOf(path) {
    const i = info.get(path);
    if (!i) throw new Error(`Tier for a field sing-box does not have: ${path}`);
    return i;
  }
  for (const f of info.values()) if (!f.tier) throw new Error(`No tier measured for ${f.path}`);
  for (const e of extract.extensions) {
    if (info.has(e.path)) throw new Error(`Extension is a sing-box field: ${e.path}`);
    info.set(e.path, { path: e.path, origin: 'extension', tier: 'supported', what: e.what });
  }

  // Sections: the objects fields are in.
  const sections = new Map();
  const section = id => {
    if (!sections.has(id)) sections.set(id, { id, rows: [], singbox: false });
    return sections.get(id);
  };
  section('');
  for (const f of info.values()) {
    const s = section(parentOf(f.path).section);
    s.rows.push(f.path);
    if (f.origin === 'sing-box') s.singbox = true;
  }

  const defs = extract.definitions;
  const byName = new Map();
  for (const d of defs) {
    if (!byName.has(d.name)) byName.set(d.name, []);
    byName.get(d.name).push(d);
  }
  /** The definition a type name means where `from` uses it. */
  function resolve(node, from) {
    const found = byName.get(node.name);
    if (!found) return null;
    if (found.length === 1) return found[0];
    const same = found.find(d => d.source === from);
    if (same) return same;
    const hinted = found.filter(d => node.path.slice(0, -1).some(seg => seg !== 'super' && seg !== 'crate' && d.source.includes(`/${seg}`)));
    if (hinted.length === 1) return hinted[0];
    const near = found.filter(d => d.source.split('/').slice(0, -1).join('/') === from.split('/').slice(0, -1).join('/'));
    if (near.length === 1) return near[0];
    throw new Error(`Ambiguous type ${node.name} in ${from}: ${found.map(d => d.source).join(', ')}`);
  }
  const find = (name, source) => {
    const d = (byName.get(name) || []).find(x => x.source === source);
    if (!d) throw new Error(`No definition ${name} in ${source}`);
    return d;
  };
  const isObject = d => d && ((d.shape.fields && d.shape.fields.some(f => f.name)) || (d.shape.variants && arg(serdeOf(d.attributes), 'tag')));

  /** The definitions a field's type names that are objects. */
  function refsOf(ty, from) {
    const out = [];
    const walk = node => {
      const d = node.name && resolve(node, from);
      if (isObject(d)) out.push(d);
      node.args.forEach(walk);
    };
    walk(parseType(ty));
    return out;
  }

  /** A struct's fields as serde reads them, flattened ones inlined. */
  function structFields(d) {
    const container = serdeOf(d.attributes);
    const rule = arg(container, 'rename_all');
    const out = [];
    for (const f of d.shape.fields || []) {
      if (!f.name) continue;
      const rustName = f.name.replace(/^r#/, '');
      const meta = serdeOf(f.attributes);
      if (/\bskip\b(?!_)/.test(meta) || /\bskip_deserializing\b/.test(meta)) continue;
      if (/\bflatten\b/.test(meta)) {
        for (const inner of refsOf(f.type, d.source)) out.push(...ownFields(inner));
        continue;
      }
      const name = arg(meta, 'rename') ?? applyCase(rustName, rule);
      const aliases = [...meta.matchAll(/\balias\s*=\s*"([^"]+)"/g)].map(m => m[1]);
      out.push({ name, aliases, type: f.type, meta, docs: f.attributes.docs, gates: f.gates || [], owner: d, containerDefault: /\bdefault\b/.test(container) });
    }
    return out;
  }

  /** An object's own fields: a struct's, or a tagged enum's tag. */
  function ownFields(d) {
    if (d.shape.fields) return structFields(d);
    const tag = arg(serdeOf(d.attributes), 'tag');
    if (!tag) return [];
    return [{ name: tag, aliases: [], type: '', tagOf: d, meta: '', docs: '', gates: [], owner: d, containerDefault: false }];
  }

  /** The fields of a tagged enum's variant, by its serde name. */
  function variantFields(d, value) {
    const rule = arg(serdeOf(d.attributes), 'rename_all');
    const v = d.shape.variants.find(v => (arg(serdeOf(v.attributes), 'rename') ?? applyCase(v.name, rule, true)) === value);
    if (!v) return null;
    return structFields({ ...d, attributes: { ...d.attributes, metadata: [] }, shape: { fields: v.fields } });
  }

  const registrations = extract.registrations.filter(r => r.registry);
  function registration(base, label) {
    const registry = REGISTRIES[base];
    if (!registry) return undefined;
    const r = registrations.find(r => r.registry === registry && r.name === label);
    if (r) return r;
    if (registry === 'inbound' && UNREGISTERED_INBOUNDS[label]) {
      const u = UNREGISTERED_INBOUNDS[label];
      const found = extract.registrations.find(r => r.source === u.source && r.options.includes(u.options));
      if (!found) throw new Error(`No ${u.options} read in ${u.source}`);
      return { registry, name: label, options: [u.options], source: u.source, gates: found.gates, blocks: {} };
    }
    return null;
  }

  /** What a registered type or a DNS server type reads: null for a type sail
   * does not have, undefined where types are not registered. */
  function override(base, label) {
    if (label === '') return undefined;
    if (base === 'dns.servers') {
      const options = DNS_SERVER_OPTIONS[label];
      if (!options) return null;
      return {
        fields: [...structFields(find('DnsServer', MODEL)), ...structFields(find(options, DNS_SERVER_SOURCE))],
        defs: [find(options, DNS_SERVER_SOURCE)],
        gates: find(options, DNS_SERVER_SOURCE).gates,
      };
    }
    const r = registration(base, label);
    if (r === undefined) return undefined;
    if (r === null) return null;
    const own = [...new Set(r.options)].map(name => {
      const d = resolve({ name, path: [name], args: [] }, r.source);
      if (!d) throw new Error(`No definition ${name} for ${r.source}`);
      return d;
    });
    const b = r.blocks || {};
    const fields = [];
    if (base === 'inbounds') {
      fields.push(...structFields(find('Inbound', MODEL)));
      const blocks = find('InboundBlocks', 'sail/src/transport/layers.rs');
      fields.push(...structFields(blocks).filter(f => b[f.name]));
    } else {
      fields.push(...structFields(find(base === 'outbounds' ? 'Outbound' : 'Endpoint', MODEL)));
      const dial = structFields(find('DialFields', 'sail/src/net/dial/fields.rs'));
      fields.push(...dial.filter(f => (f.name === 'detour' ? b.detour : b.dial)));
      if (base === 'outbounds') {
        const blocks = find('OutboundBlocks', 'sail/src/transport/layers.rs');
        fields.push(...(blocks.shape.fields || []).filter(f => b[f.name]).flatMap(f => structFields({ ...blocks, shape: { fields: [f] } })));
      }
    }
    for (const d of own) fields.push(...structFields(d));
    return { fields, defs: own, gates: r.gates, source: r.source };
  }

  const rustMemo = new Map();
  /** The Rust fields of a section, with the definitions they come from. */
  function rustSection(id) {
    if (rustMemo.has(id)) return rustMemo.get(id);
    let result = null;
    if (id === '') {
      const config = find('Config', MODEL);
      result = { fields: structFields(config), defs: [config], gates: config.gates };
    } else {
      const v = variantOf(id);
      if (v) {
        const o = override(v.base, v.label);
        if (o) result = o;
        else if (o === undefined) {
          const rf = rustField(v.base);
          if (rf) {
            const defs = refsOf(rf.type, rf.owner.source);
            const value = labelValue(v.label);
            const out = [];
            for (const d of defs) {
              if (d.shape.variants) {
                const vf = value ? variantFields(d, value) : null;
                if (vf) out.push(...vf);
              } else out.push(...structFields(d));
            }
            // A struct taken whole by each shape (a rule's conditions and
            // actions): its fields are not each shape's.
            if (defs.length) result = { fields: out, defs, gates: defs[0].gates, flat: defs.some(d => d.shape.fields) };
          }
        }
      } else {
        const rf = rustField(id);
        if (rf) {
          const defs = refsOf(rf.type, rf.owner.source);
          if (defs.length) result = { fields: defs.flatMap(ownFields), defs, gates: defs[0].gates };
        }
      }
    }
    rustMemo.set(id, result);
    return result;
  }
  function rustField(path) {
    const { section: s, key } = parentOf(path);
    const r = rustSection(s);
    return r?.fields.find(f => f.name === key || f.aliases.includes(key)) || null;
  }

  // Sections sing-box does not have: registered types, and objects in them.
  for (const [base, registry] of Object.entries(REGISTRIES)) {
    for (const r of registrations.filter(r => r.registry === registry)) section(`${base}[${r.name}]`);
  }

  /** The shapes of a field: its own object, then its variants. */
  function shapesOf(path) {
    const out = [];
    if (sections.has(path)) out.push(path);
    const variants = [...sections.keys()].filter(id => variantOf(id)?.base === path);
    variants.sort((a, b) => {
      const la = variantOf(a).label, lb = variantOf(b).label;
      return (la === '' ? -1 : 0) - (lb === '' ? -1 : 0) || la.localeCompare(lb);
    });
    return out.concat(variants);
  }

  /** Adds the sections a Rust-only field's type makes. */
  function rustShapes(path, rf) {
    const defs = refsOf(rf.type, rf.owner.source);
    if (!defs.length) return;
    const node = parseType(rf.type);
    const inner = node.name === 'Option' ? node.args[0] : node;
    const array = ['Vec', 'VecDeque'].includes(inner?.name);
    for (const d of defs) {
      if (d.shape.variants) {
        section(path);
        const rule = arg(serdeOf(d.attributes), 'rename_all');
        for (const v of d.shape.variants) {
          if (v.fields.some(f => f.name)) section(`${path}[${arg(serdeOf(v.attributes), 'rename') ?? applyCase(v.name, rule, true)}]`);
        }
      } else section(array ? `${path}[]` : path);
    }
  }

  const unlisted = [];
  /** A section's rows: sing-box's fields and the listed extensions where
   * sing-box has the object, or else sail's own fields. */
  function rowsOf(id) {
    const s = sections.get(id);
    const rust = rustSection(id);
    const typed = variantOf(id) && variantOf(id).label !== '';
    // A typed entry's `type` is its generic entry's field.
    const fields = (rust?.fields || []).filter(rf => !(typed && rf.name === 'type'));
    const match = key => fields.find(f => f.name === key || f.aliases.includes(key)) || null;
    const rows = [];
    if (s.singbox) {
      const seen = new Set();
      for (const path of s.rows) {
        const key = parentOf(path).key;
        const rf = match(key);
        seen.add(key);
        if (rf) seen.add(rf.name);
        rows.push({ key, path, info: info.get(path), rust: rf });
      }
      if (!rust?.flat) {
        for (const rf of fields) if (!seen.has(rf.name) && !rf.aliases.some(a => seen.has(a))) unlisted.push(id ? `${id}.${rf.name}` : rf.name);
      }
    } else {
      // Sail's own object: its Rust fields in order, the listed
      // extensions' notes on those they name.
      const listed = new Map(s.rows.map(path => [parentOf(path).key, path]));
      for (const rf of fields) {
        const key = [rf.name, ...rf.aliases].find(k => listed.has(k)) ?? rf.name;
        const path = listed.get(key) ?? (id ? `${id}.${rf.name}` : rf.name);
        listed.delete(key);
        rows.push({ key: rf.name, path, info: info.get(path) ?? { path, origin: 'extension', tier: 'supported' }, rust: rf });
        rustShapes(path, rf);
      }
      for (const path of listed.values()) rows.push({ key: parentOf(path).key, path, info: info.get(path), rust: null });
    }
    for (const row of rows) {
      if (row.info.origin === 'extension' && row.rust && !sections.has(row.path) && !shapesOf(row.path).length) rustShapes(row.path, row.rust);
    }
    return rows;
  }

  /** Whether a variant is a type sail does not implement, as the sing-box
   * support table lists them: that table's row, or null. */
  function missing(id) {
    const row = lacking.get(id);
    if (!row) return null;
    if (rustSection(id) && !rustSection(id).flat) throw new Error(`The support table says sail lacks ${id}, which it reads`);
    return row;
  }
  const descendants = id => [...info.values()].filter(f => f.path.startsWith(id + '.') || f.path.startsWith(id + '['));

  return { info, sections, rustSection, rowsOf, shapesOf, missing, descendants, resolve, unlisted, functions: extract.functions, defs };
}

/** The types the sing-box support table says sail does not implement:
 * `| \`inbounds[naive]\` | Error | note | 94 |` under its heading. */
export function lackingTypes(text) {
  const out = new Map();
  let inside = false;
  for (const line of text.split('\n')) {
    if (line.startsWith('### ')) inside = line === '### Types sail does not implement';
    if (!inside) continue;
    const m = /^\| `([^`]+)` \| ([^|]+) \| (.*) \| (\d+) \|$/.exec(line);
    if (m) out.set(m[1], { tier: { Supported: 'supported', Warned: 'ignored', Error: 'unsupported' }[m[2].trim()], reason: m[3].replace(/\\\|/g, '|'), count: Number(m[4]) });
  }
  return out;
}

// ---------------------------------------------------------------- cells

/** The JSON type of a Rust field, as sing-box's registry words them. */
export function rustJson(model, ty, from, meta, w) {
  const via = arg(meta || '', 'with') || arg(meta || '', 'deserialize_with');
  const node = parseType(ty);
  if (via) {
    const last = via.split('::').pop();
    if (last === 'duration') return 'duration';
    if (last === 'duration_or_seconds') return w.seconds;
    if (last === 'listable') {
      const inner = node.name === 'Vec' ? describe(model, node.args[0], from, w) : describe(model, node, from, w);
      return `${inner}${w.or}${w.arrayOf} ${inner}`;
    }
  }
  return describe(model, node, from, w);
}

function describe(model, node, from, w) {
  const n = node.name;
  if (n === 'array' || n === 'tuple') return 'array';
  if (['Option', 'Box', 'Arc', 'Rc', 'Secret'].includes(n) && node.args.length) return describe(model, node.args[0], from, w);
  if (['Vec', 'VecDeque', 'HashSet', 'BTreeSet', 'IndexSet'].includes(n)) return `${w.arrayOf} ${describe(model, node.args[0], from, w)}`;
  if (['HashMap', 'BTreeMap', 'IndexMap', 'Map'].includes(n)) {
    return node.args.length === 2 ? `${w.objectOf} ${describe(model, node.args[1], from, w)}` : w.object;
  }
  if (['String', 'str', 'PathBuf', 'Cow', 'IpAddr', 'Ipv4Addr', 'Ipv6Addr', 'SocketAddr', 'IpNet', 'Prefix'].includes(n) && !model.resolve(node, from)) return 'string';
  if (n === 'bool') return 'bool';
  if (/^(u|i)(8|16|32|64|128|size)$|^f(32|64)$/.test(n)) return 'number';
  if (n === 'Duration') return 'duration';
  if (n === 'Value' || n === 'IgnoredAny') return w.any;
  const d = model.resolve(node, from);
  if (!d) return `\`${node.path.join('::')}\``;
  const meta = serdeOf(d.attributes);
  if (d.shape.fields) {
    if (d.shape.fields.some(f => f.name)) return w.object;
    if (d.shape.fields.length === 1) return describe(model, parseType(d.shape.fields[0].type), d.source, w);
    return 'array';
  }
  const rule = arg(meta, 'rename_all');
  const variants = d.shape.variants;
  if (/\buntagged\b/.test(meta)) {
    const kinds = [...new Set(variants.map(v => (v.fields.length === 1 && !v.fields[0].name ? describe(model, parseType(v.fields[0].type), d.source, w) : v.fields.length ? w.object : 'null')))];
    return kinds.join(w.or);
  }
  if (arg(meta, 'tag')) return w.object;
  if (variants.every(v => !v.fields.length)) {
    const values = variants.map(v => `\`${arg(serdeOf(v.attributes), 'rename') ?? applyCase(v.name, rule, true)}\``);
    return `string, ${w.oneOf} ${values.join(', ')}`;
  }
  return `\`${d.name}\``;
}

/** What a field is when the configuration leaves it out. */
export function rustDefault(model, rf, w) {
  const meta = rf.meta;
  const fn = arg(meta, 'default');
  if (fn) {
    const name = fn.split('::').pop();
    const candidates = model.functions.filter(f => f.name === name);
    const body = (candidates.find(f => f.source === rf.owner.source) || (candidates.length === 1 ? candidates[0] : null))?.body;
    const literal = body && literalOf(body);
    return literal ? `\`${literal}\`` : `\`${name}()\``;
  }
  const node = parseType(rf.type || 'String');
  const listable = /\bwith\s*=\s*"[^"]*listable"/.test(meta);
  if (node.name === 'Option') return w.unset;
  if (/\bdefault\b/.test(meta)) {
    if (node.name === 'bool') return '`false`';
    if (listable || ['Vec', 'VecDeque', 'HashSet', 'BTreeSet'].includes(node.name)) return '`[]`';
    if (['HashMap', 'BTreeMap', 'IndexMap', 'Map'].includes(node.name)) return '`{}`';
    if (node.name === 'String') return '`""`';
    if (/^(u|i)(8|16|32|64|128|size)$/.test(node.name)) return '`0`';
    const d = node.name && model.resolve(node, rf.owner.source);
    const derived = d && d.attributes.metadata.some(m => /^derive\b/.test(m) && /\bDefault\b/.test(m));
    if (derived && d.shape.variants) {
      const v = d.shape.variants.find(v => v.attributes.metadata.includes('default'));
      if (v && !v.fields.length) return `\`${arg(serdeOf(v.attributes), 'rename') ?? applyCase(v.name, arg(serdeOf(d.attributes), 'rename_all'), true)}\``;
    }
    if (derived && d.shape.fields) return w.fieldsDefault;
    return w.typeDefault;
  }
  if (rf.containerDefault) return w.objectDefault;
  if (rf.tagOf) return w.required;
  return w.required;
}

/** A default function's body when it is a literal. */
export function literalOf(body) {
  const b = body.replace(/\s+/g, ' ').trim();
  let m = /^("(?:[^"\\]|\\.)*")\s*(?:\.\s*(?:into|to_string|to_owned)\s*\(\s*\))?$/.exec(b);
  if (m) return m[1];
  m = /^String\s*::\s*from\s*\(\s*("(?:[^"\\]|\\.)*")\s*\)$/.exec(b);
  if (m) return m[1];
  if (/^(true|false|-?[0-9][0-9_]*(\.[0-9]+)?)$/.test(b)) return b.replace(/_/g, '');
  return null;
}

/** `cfg` conditions, the outer `any(...)` of an inner feature dropped. */
export function simplifyGates(gates) {
  const unique = [...new Set(gates)];
  return unique.filter(g => !unique.some(h => h !== g && g.includes(h)));
}

const esc = text => String(text).replaceAll('|', '\\|').replaceAll('\n', ' ');

// ---------------------------------------------------------------- pages

export const PAGES = [
  { slug: 'common', roots: ['', 'log', 'certificate', 'http_clients', 'ntp', 'experimental', 'api', 'clash_api', 'outbound_providers', 'certificate_providers', 'network_namespaces', 'services'] },
  { slug: 'dns', roots: ['dns'] },
  { slug: 'inbounds', roots: ['inbounds'] },
  { slug: 'outbounds', roots: ['outbounds'] },
  { slug: 'endpoints', roots: ['endpoints'] },
  { slug: 'route', roots: ['route'] },
];
export const SHARED = 'shared';

const TITLES = {
  en: { common: 'Top level and common', dns: 'DNS', inbounds: 'Inbounds', outbounds: 'Outbounds and groups', endpoints: 'Endpoints', route: 'Route', shared: 'Shared objects', compatibility: 'Compatibility' },
  zh: { common: '顶层与通用', dns: 'DNS', inbounds: '入站', outbounds: '出站与策略组', endpoints: '端点', route: '路由', shared: '共用对象', compatibility: '兼容性' },
};

/** Front matter, its strings quoted: YAML reads `a: b` in one as a map. */
export const frontmatter = (title, description) => `---\ntitle: ${JSON.stringify(title)}\ndescription: ${JSON.stringify(description)}\n---\n\n`;

function intro(lang, version) {
  return lang === 'zh'
    ? `本页由 \`website/scripts/build-config.mjs\` 生成，请勿手改：它读取 sail 的配置类型（Rust 源码）、sing-box 字段注册表（\`sail/src/config/singbox/fields.json\`，sing-box ${version}）及注册表测试实测的分级（\`fields.tiers.json\`）。修改源码注释或上述文件后在 \`website/\` 下执行 \`npm run docs:config\`。

- **状态**：sing-box 的字段按注册表测试逐一实测：**支持**（读取并生效，不接受的取值仍报错）、**警告**（忽略并警告）、**报错**（拒绝该配置），并附理由；**sail 扩展** 为 sing-box 没有的字段与类型。
- **类型**：sing-box 字段取 sing-box 的 JSON 类型；扩展字段取自 sail 的 Rust 定义。
- **默认**：取自 sail 的 serde 声明；“未设置”表示可省略，省略时的行为见说明。只有 sail 读取的字段才列默认值。
- **说明**：sail 源码注释，保留原文；没有注释的扩展字段取注册表测试的说明。
- **构建条件**：Rust 源码中的 \`cfg\` 条件（Cargo feature 与平台）。

用 \`sail -c config.json -T\` 校验配置。Clash 与 Surge 的支持表见[兼容性](/sail/zh/reference/compatibility/)。\n\n`
    : `Generated by \`website/scripts/build-config.mjs\`; do not edit. It reads sail's configuration types (its Rust source), sing-box's field registry (\`sail/src/config/singbox/fields.json\`, sing-box ${version}) and the tiers the registry test measured (\`fields.tiers.json\`). Change the source comments or those files, then run \`npm run docs:config\` in \`website/\`.

- **Status**: each sing-box field as the registry test measured it: **Supported** (read and acted on; a value sail cannot take is still an error), **Warned** (dropped with a warning) or **Error** (the configuration is refused), with the reason; **sail extension** marks fields and types sing-box does not have.
- **Type**: sing-box's JSON type for its fields; from sail's Rust definitions for extensions.
- **Default**: from sail's serde declarations; *unset* means the field may be left out, and the description says what applies then. Only fields sail reads have one.
- **Description**: sail's source comments, in their source language; for an extension without one, the registry test's note.
- **Build**: the \`cfg\` conditions in the Rust source (Cargo features and platforms).

Validate a configuration with \`sail -c config.json -T\`. The Clash and Surge support tables are under [Compatibility](/sail/reference/compatibility/).\n\n`;
}

/** Renders every page, in both languages: { 'reference/x.md': text }. */
export function render({ fields, tiers, extract, compat, pages = PAGES }) {
  const model = buildModel({ fields, tiers, extract, compat });
  const version = fields.sing_box;

  // Which page and which H2 each top section is on.
  const units = new Map();
  const pageOfRoot = new Map();
  for (const page of pages) {
    for (const root of page.roots) {
      pageOfRoot.set(root, page.slug);
      const list = root === '' ? [''] : model.shapesOf(root);
      if (root !== '' && !list.length) {
        // An extension object sail reads from Rust alone.
        model.rowsOf('');
        const again = model.shapesOf(root);
        if (!again.length) throw new Error(`No section for ${root}`);
        list.push(...again);
      }
      for (const id of list) units.set(id, page.slug);
      // The root's arrays of typed entries (dns.servers, route.rules) are
      // top sections too.
      if (root !== '' && list[0] === root) {
        for (const row of model.rowsOf(root)) {
          const shapes = model.shapesOf(row.path);
          if (shapes.some(s => variantOf(s)?.base === row.path)) for (const s of shapes) units.set(s, page.slug);
        }
      }
    }
  }

  // Rows, in words-free form, for every section reachable from a unit.
  const rowsMemo = new Map();
  const rowsOf = id => {
    if (!rowsMemo.has(id)) rowsMemo.set(id, model.rowsOf(id));
    return rowsMemo.get(id);
  };
  const children = row => (row.path === '' ? [] : model.shapesOf(row.path));

  const keyMemo = new Map();
  const W = WORDS.en;
  function cells(row, w) {
    const i = row.info;
    let type;
    if (i.origin === 'sing-box') type = i.enum ? `${i.json}, ${w.oneOf} ${i.enum.map(v => `\`${v}\``).join(', ')}` : i.json;
    else if (row.rust?.tagOf) {
      const d = row.rust.tagOf;
      const rule = arg(serdeOf(d.attributes), 'rename_all');
      type = `string, ${w.oneOf} ${d.shape.variants.map(v => `\`${arg(serdeOf(v.attributes), 'rename') ?? applyCase(v.name, rule, true)}\``).join(', ')}`;
    } else if (row.rust) type = rustJson(model, row.rust.type, row.rust.owner.source, row.rust.meta, w);
    else type = '—';
    const def = row.rust && i.tier === 'supported' ? rustDefault(model, row.rust, w) : i.required ? w.required : '—';
    let status = i.origin === 'extension' ? w.extension : w[i.tier];
    if (i.reason) status += `${w.colon}${i.reason}`;
    if (i.deprecated) status += ` (${w.deprecated})`;
    let doc = row.rust?.docs || i.what || '—';
    const gates = simplifyGates(row.rust?.gates || []);
    if (gates.length) doc += ` ${w.build}${w.colon}${gates.map(g => `\`${g}\``).join(w.and)}`;
    return { type, def, status, doc };
  }
  function contentKey(id) {
    if (keyMemo.has(id)) return keyMemo.get(id);
    keyMemo.set(id, 'cycle:' + id);
    const rust = model.rustSection(id);
    const key = JSON.stringify([
      (rust?.defs || []).map(d => d.name + '@' + d.source),
      rowsOf(id).map(r => [r.key, cells(r, W), children(r).map(c => [variantOf(c)?.label ?? null, contentKey(c)])]),
    ]);
    keyMemo.set(id, key);
    return key;
  }

  // Nested sections: shared where two or more have the same content.
  const nested = new Map();
  const visit = (id, unit) => {
    for (const row of rowsOf(id)) {
      for (const c of children(row)) {
        if (units.has(c) || nested.has(c) || model.missing(c)) continue;
        nested.set(c, unit);
        visit(c, unit);
      }
    }
  };
  for (const id of units.keys()) if (!model.missing(id)) visit(id, id);
  const byKey = new Map();
  for (const id of nested.keys()) {
    const k = contentKey(id);
    if (!byKey.has(k)) byKey.set(k, []);
    byKey.get(k).push(id);
  }
  const shared = new Map();
  const sharedList = [];
  for (const [k, ids] of byKey) {
    if (ids.length < 2) continue;
    const entry = { key: k, ids, name: [...new Set(ids.map(id => splitPath(id).pop()))].join(' / ') };
    sharedList.push(entry);
    for (const id of ids) shared.set(id, entry);
  }
  const scope = id => {
    const t = splitPath(id).map(s => s.replace(/\[.*\]$/, ''));
    return ['dns', 'route', 'experimental'].includes(t[0]) && t.length > 2 ? `${t[0]}.${t[1]}` : t[0];
  };
  const byName = new Map();
  for (const e of sharedList) {
    if (!byName.has(e.name)) byName.set(e.name, []);
    byName.get(e.name).push(e);
  }
  for (const [name, list] of byName) {
    for (const e of list) {
      e.scopes = [...new Set(e.ids.map(scope))];
      e.qualifier = list.length === 1 ? '' : e.scopes.length > 3 ? `${e.scopes.slice(0, 3).join(', ')}, …` : e.scopes.join(', ');
      e.title = e.qualifier ? `${name} — ${e.qualifier}` : name;
    }
    const titles = new Map();
    for (const e of list) {
      const n = (titles.get(e.title) || 0) + 1;
      titles.set(e.title, n);
      if (n > 1) {
        e.title += ` (${n})`;
        e.qualifier += ` (${n})`;
      }
    }
    for (const e of list) e.anchor = slug(e.title);
  }
  sharedList.sort((a, b) => a.title.localeCompare(b.title));
  const anchors = new Set();
  for (const e of sharedList) {
    if (anchors.has(e.anchor)) throw new Error(`Anchor collision on the shared page: ${e.anchor}`);
    anchors.add(e.anchor);
  }

  const covered = new Set();
  const files = {};
  for (const lang of ['en', 'zh']) {
    const w = WORDS[lang];
    const prefix = lang === 'zh' ? '/sail/zh/reference/' : '/sail/reference/';
    const hrefOf = (id, here) => {
      const v = variantOf(id);
      if (v && model.missing(id)) {
        const page = units.get(id) ?? pageOfRoot.get(splitPath(v.base)[0]);
        return `${page === here ? '' : prefix + page + '/'}#${slug(v.base + '-missing')}`;
      }
      if (shared.has(id)) return `${here === SHARED ? '' : prefix + SHARED + '/'}#${shared.get(id).anchor}`;
      if (units.has(id)) return `${units.get(id) === here ? '' : prefix + units.get(id) + '/'}#${slug(id)}`;
      if (nested.has(id)) {
        const page = units.get(nested.get(id));
        return `${page === here ? '' : prefix + page + '/'}#${slug(id)}`;
      }
      throw new Error(`No place for ${id}`);
    };
    const labelOf = (row, c) => (c === row.path ? w.object : `[${variantOf(c).label}]`);
    const table = (id, here) => {
      let out = `| ${w.field} | ${w.type} | ${w.default} | ${w.status} | ${w.doc} |\n| --- | --- | --- | --- | --- |\n`;
      for (const row of rowsOf(id)) {
        if (lang === 'en') covered.add(row.path);
        const c = cells(row, w);
        const shapes = children(row);
        let type = esc(c.type);
        if (shapes.length) type += ` → ${shapes.map(s => `[${esc(labelOf(row, s))}](${hrefOf(s, here)})`).join(', ')}`;
        out += `| \`${esc(row.key)}\` | ${type} | ${esc(c.def)} | ${esc(c.status)} | ${esc(c.doc)} |\n`;
      }
      return out + '\n';
    };
    const meta = id => {
      const rust = model.rustSection(id);
      const parts = [];
      if (rust?.defs?.length) parts.push(`${w.rust}${w.colon}${rust.defs.map(d => `[\`${d.name}\`](${REPO}${d.source})`).join(', ')}`);
      const gates = simplifyGates(rust?.gates || []);
      if (gates.length) parts.push(`${w.build}${w.colon}${gates.map(g => `\`${g}\``).join(w.and)}`);
      if (!model.sections.get(id).singbox && id !== '') parts.push(`**${w.extension}**`);
      return parts.length ? parts.join(' · ') + '\n\n' : '';
    };
    const inline = (unit, here) => {
      let out = '';
      const walk = id => {
        for (const row of rowsOf(id)) {
          for (const c of children(row)) {
            if (nested.get(c) !== unit || shared.has(c) || done.has(c)) continue;
            done.add(c);
            out += `<a id="${slug(c)}"></a>\n\n### \`${c}\`\n\n${meta(c)}${table(c, here)}`;
            walk(c);
          }
        }
      };
      const done = new Set();
      walk(unit);
      return out;
    };
    const missingTable = (base, here) => {
      const ids = model.shapesOf(base).filter(model.missing);
      if (!ids.length) return '';
      let out = `<a id="${slug(base + '-missing')}"></a>\n\n## ${w.missing}${w.colon}\`${base}\`\n\n| ${w.type} | ${w.status} | ${w.fieldsCount} |\n| --- | --- | --: |\n`;
      for (const id of ids) {
        const all = model.descendants(id);
        if (lang === 'en') all.forEach(f => covered.add(f.path));
        const m = model.missing(id);
        out += `| \`${id}\` | ${esc(`${w[m.tier]}${w.colon}${m.reason}`)} | ${m.count} |\n`;
      }
      return out + '\n';
    };

    for (const page of pages) {
      let body = frontmatter(TITLES[lang][page.slug], lang === 'zh' ? `sail 原生配置格式（sing-box ${version} JSON 与 sail 扩展）的逐字段参考。` : `Field-by-field reference of sail's native format: sing-box ${version} JSON and sail's extensions.`);
      body += intro(lang, version);
      const bases = new Set();
      for (const [id, slugOf] of units) {
        if (slugOf !== page.slug) continue;
        if (model.missing(id)) {
          bases.add(variantOf(id).base);
          continue;
        }
        body += `<a id="${slug(id)}"></a>\n\n## ${id === '' ? w.top : `\`${id}\``}\n\n${meta(id)}${table(id, page.slug)}${inline(id, page.slug)}`;
        const v = variantOf(id);
        if (v) bases.add(v.base);
      }
      for (const base of bases) body += missingTable(base, page.slug);
      files[`${lang === 'zh' ? 'zh/' : ''}reference/${page.slug}.md`] = body;
    }

    let body = `${frontmatter(TITLES[lang].shared, lang === 'zh' ? '多处取用的配置对象，统一列出。' : 'Configuration objects several fields take, written once.')}${intro(lang, version)}${w.sharedIntro}\n\n`;
    for (const e of sharedList) {
      const at = collapse(e.ids).map(p => `\`${p}\``).join(', ');
      body += `<a id="${e.anchor}"></a>\n\n## \`${e.name}\`${e.qualifier ? ` — ${e.qualifier}` : ''}\n\n${w.usedAt}${w.colon}${at}\n\n${meta(e.ids[0])}${table(e.ids[0], SHARED)}`;
      if (lang === 'en') for (const id of e.ids.slice(1)) for (const r of rowsOf(id)) covered.add(r.path);
    }
    files[`${lang === 'zh' ? 'zh/' : ''}reference/${SHARED}.md`] = body;
    files[`${lang === 'zh' ? 'zh/' : ''}reference/compatibility.md`] = compatibilityPage(lang, compat, version);
  }

  for (const [name, text] of Object.entries(files)) {
    const ids = [...text.matchAll(/<a id="([^"]+)"><\/a>/g)].map(m => m[1]);
    const twice = ids.filter((id, i) => ids.indexOf(id) !== i);
    if (twice.length) throw new Error(`Anchors given twice in ${name}: ${[...new Set(twice)].join(', ')}`);
  }
  const broken = brokenLinks(files);
  if (broken.length) throw new Error(`Links to no anchor: ${broken.slice(0, 10).join(', ')}`);
  const lost = [...model.info.keys()].filter(p => !covered.has(p));
  if (lost.length) throw new Error(`Fields on no page: ${lost.slice(0, 20).join(', ')}${lost.length > 20 ? ` and ${lost.length - 20} more` : ''}`);

  const undocumented = [];
  for (const id of new Set([...units.keys(), ...nested.keys()])) {
    if (model.missing(id)) continue;
    for (const r of rowsOf(id)) if (r.rust && !r.rust.docs && r.info.tier === 'supported') undocumented.push(`${r.rust.owner.name}.${r.rust.name} (${r.path})`);
  }
  return { files, undocumented: [...new Set(undocumented)].sort(), unlisted: [...new Set(model.unlisted)].sort() };
}

/** Links into the reference that point to no anchor. */
export function brokenLinks(files) {
  const ids = new Map();
  for (const [name, text] of Object.entries(files)) ids.set(name, new Set([...text.matchAll(/<a id="([^"]+)"><\/a>/g)].map(m => m[1])));
  const out = [];
  for (const [name, text] of Object.entries(files)) {
    for (const m of text.matchAll(/\]\(((?:\/sail\/(zh\/)?reference\/([a-z-]+)\/)?#([^)]+))\)/g)) {
      const target = m[3] ? `${m[2] ?? ''}reference/${m[3]}.md` : name;
      if (!ids.get(target)?.has(m[4])) out.push(`${name}: ${m[1]}`);
    }
  }
  return out;
}

/** Paths that differ in one variant label, written as one. */
export function collapse(ids) {
  const groups = new Map();
  for (const id of ids) {
    const t = splitPath(id);
    const i = t.findIndex(s => /\[[^\]]+\]$/.test(s));
    const key = i < 0 ? id : [...t.slice(0, i), t[i].replace(/\[[^\]]+\]$/, '[*]'), ...t.slice(i + 1)].join('.');
    if (!groups.has(key)) groups.set(key, { index: i, labels: [], id });
    if (i >= 0) groups.get(key).labels.push(/\[([^\]]+)\]$/.exec(t[i])[1]);
  }
  return [...groups.entries()].map(([key, g]) => (g.index < 0 || g.labels.length === 1 ? g.id : key.replace('[*]', `[${g.labels.join(', ')}]`)));
}

// ---------------------------------------------------------------- compat

export const COMPAT = [
  { file: 'sing-box.md', name: 'sing-box' },
  { file: 'clash.md', name: 'Clash / Mihomo' },
  { file: 'surge.md', name: 'Surge' },
];

/** The landing page: each support table's title, first table and links. */
export function compatibilityPage(lang, compat, version) {
  const w = WORDS[lang];
  let body = frontmatter(TITLES[lang].compatibility, lang === 'zh' ? 'sail 对 sing-box、Clash / Mihomo 与 Surge 配置的支持表。' : 'How sail reads sing-box, Clash / Mihomo and Surge configurations: the support tables.');
  body += lang === 'zh'
    ? `sail 直接读取 sing-box、Clash / Mihomo 与 Surge 的配置。每种格式都有一张由注册表测试生成的支持表（\`docs/compat/\`），逐字段列出 sail 实测的处理方式。原生格式（sing-box ${version} JSON 与 sail 扩展）的逐字段说明见本节其他页面，从[顶层与通用](/sail/zh/reference/common/)开始。\n\n`
    : `sail reads sing-box, Clash / Mihomo and Surge configurations as they are. Each format has a support table generated by its registry test (\`docs/compat/\`), listing every field with how sail was measured to treat it. The native format (sing-box ${version} JSON and sail's extensions) is described field by field on the other pages of this section, starting at [Top level and common](/sail/reference/common/).\n\n`;
  for (const c of COMPAT) {
    const en = compat[c.file];
    const zh = compat[`zh/${c.file}`];
    body += `## ${c.name}\n\n`;
    const text = lang === 'zh' ? zh ?? en : en;
    if (!text) {
      body += `${w.notIn}\n\n`;
      continue;
    }
    body += `${w.table}${w.colon}[docs/compat/${c.file}](${REPO}docs/compat/${c.file})`;
    if (zh) body += ` · ${w.zhTable}${w.colon}[docs/compat/zh/${c.file}](${REPO}docs/compat/zh/${c.file})`;
    body += '\n\n';
    const lines = text.split('\n');
    const start = lines.findIndex(l => l.startsWith('|'));
    if (start >= 0) {
      let end = start;
      while (end < lines.length && lines[end].startsWith('|')) end++;
      body += `### ${w.summary}\n\n${lines.slice(start, end).join('\n')}\n\n`;
    }
  }
  return body;
}

/** Generated pages that differ from what is on disk, or are left over. */
export function stale(files, read, list) {
  const out = [];
  for (const [name, text] of Object.entries(files)) if (read(name) !== text) out.push(name);
  for (const name of list()) if (!(name in files)) out.push(name);
  return out;
}
