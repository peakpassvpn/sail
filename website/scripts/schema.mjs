// The JSON schema of sail's native format, from the same model as the
// reference pages: every object the model has, its fields typed as the
// sing-box registry has them (or as sail's Rust types are, for extensions),
// and sail's measured tier on each. Pure, like reference.mjs.
//
// - A field sail refuses is `not: {}`, its reason the description, so that
//   an editor marks it.
// - A field sail drops with a warning is `deprecated`, with the reason.
// - An object takes no field it does not list, as sail takes none.
// - Entries of a list of types are told apart by `type` (`if`/`then`); a
//   type sail does not implement is not among the values `type` takes.
// - A rule's action fields are in the rule's object, as sing-box writes
//   them; a logical rule's rules are rules without actions.

import { applyCase, parseType, serdeOf, splitPath, variantOf, labelValue } from './reference.mjs';

const arg = (meta, name) => meta.match(new RegExp(`\\b${name}\\s*=\\s*"([^"]+)"`))?.[1];

/** A registry kind (`listable-string`, `number|duration`) as a schema. */
export function kindSchema(kind, shaped = {}) {
  const one = k => {
    if (k.startsWith('listable-')) {
      const inner = one(k.slice('listable-'.length));
      return { anyOf: [inner, { type: 'array', items: inner }] };
    }
    switch (k) {
      case 'string': return { type: 'string' };
      case 'bool': return { type: 'boolean' };
      case 'number': return { type: 'number' };
      case 'duration': return { type: 'string' };
      case 'object': return shaped.object ?? { type: 'object' };
      case 'map': return shaped.object ?? { type: 'object' };
      case 'array': return shaped.array ?? { type: 'array' };
      case 'any': return {};
      default: throw new Error(`Unknown kind: ${k}`);
    }
  };
  // `listable-number|string`: one of these, or a list of them.
  const parts = kind.split('|');
  const scalars = ['string', 'bool', 'number', 'duration'];
  if (parts.length > 1 && parts[0].startsWith('listable-') && parts.slice(1).every(p => scalars.includes(p))) {
    const inner = { anyOf: [parts[0].slice('listable-'.length), ...parts.slice(1)].map(one) };
    return { anyOf: [inner, { type: 'array', items: inner }] };
  }
  const schemas = parts.map(one);
  return schemas.length === 1 ? schemas[0] : { anyOf: schemas };
}

/** A Rust field's kind, in the registry's words, and its values if it is
 * an enum of names. */
export function rustKind(model, ty, from, meta = '') {
  const via = arg(meta, 'with') || arg(meta, 'deserialize_with');
  const node = parseType(ty);
  if (via) {
    const last = via.split('::').pop();
    if (last === 'duration') return { kind: 'duration' };
    if (last === 'duration_or_seconds') return { kind: 'number|duration' };
    if (last === 'listable') {
      const inner = rustKind(model, node.name === 'Vec' ? typeText(node.args[0]) : ty, from);
      return { kind: inner.kind.split('|').map(k => (k.startsWith('listable-') ? k : `listable-${k}`)).join('|'), enum: inner.enum };
    }
  }
  return kindOf(model, node, from);
}

const typeText = node => (node.args.length ? `${node.path.join('::')}<${node.args.map(typeText).join(',')}>` : node.path.join('::'));

function kindOf(model, node, from) {
  const n = node.name;
  if (n === 'array' || n === 'tuple') return { kind: 'array' };
  if (['Option', 'Box', 'Arc', 'Rc', 'Secret'].includes(n) && node.args.length) return kindOf(model, node.args[0], from);
  if (['Vec', 'VecDeque', 'HashSet', 'BTreeSet', 'IndexSet'].includes(n)) return { kind: 'array' };
  if (['HashMap', 'BTreeMap', 'IndexMap', 'Map'].includes(n)) return { kind: 'map' };
  if (['String', 'str', 'PathBuf', 'Cow', 'IpAddr', 'Ipv4Addr', 'Ipv6Addr', 'SocketAddr', 'IpNet', 'Prefix'].includes(n) && !model.resolve(node, from)) return { kind: 'string' };
  if (n === 'bool') return { kind: 'bool' };
  if (/^(u|i)(8|16|32|64|128|size)$|^f(32|64)$/.test(n)) return { kind: 'number' };
  if (n === 'Duration') return { kind: 'duration' };
  if (n === 'Value' || n === 'IgnoredAny') return { kind: 'any' };
  const d = model.resolve(node, from);
  if (!d) return { kind: 'any' };
  const meta = serdeOf(d.attributes);
  if (d.shape.fields) {
    if (d.shape.fields.some(f => f.name)) return { kind: 'object' };
    if (d.shape.fields.length === 1) return kindOf(model, parseType(d.shape.fields[0].type), d.source);
    return { kind: 'array' };
  }
  const variants = d.shape.variants;
  if (/\buntagged\b/.test(meta)) {
    const kinds = new Set();
    for (const v of variants) {
      if (v.fields.length === 1 && !v.fields[0].name) kindOf(model, parseType(v.fields[0].type), d.source).kind.split('|').forEach(k => kinds.add(k));
      else kinds.add(v.fields.length ? 'object' : 'any');
    }
    return { kind: kinds.has('any') ? 'any' : [...kinds].join('|') };
  }
  if (arg(meta, 'tag')) return { kind: 'object' };
  if (variants.every(v => !v.fields.length)) {
    const rule = arg(meta, 'rename_all');
    return { kind: 'string', enum: variants.map(v => arg(serdeOf(v.attributes), 'rename') ?? applyCase(v.name, rule, true)) };
  }
  return { kind: 'any' };
}

/** The key that tells a list's entries apart: `type`, or an action's. */
const keyOf = label => (label.includes('=') ? label.slice(0, label.indexOf('=')) : 'type');

/** The schema, its objects under `$defs` by their registry path. */
export function buildSchema(model, { version, id, title, description }) {
  const defs = {};
  const ref = name => ({ $ref: `#/$defs/${encodeURIComponent(name)}` });

  /** What a row says beside its type: its doc, and sail's tier. */
  function annotate(schema, row) {
    const i = row.info;
    const doc = row.rust?.docs || i.what || '';
    if (i.tier === 'unsupported') return { not: {}, description: `sail refuses this field: ${i.reason}` };
    const out = { ...schema };
    if (i.tier === 'ignored') {
      out.deprecated = true;
      out.description = `sail ignores this field, with a warning: ${i.reason}${doc ? `. ${doc}` : ''}`;
    } else if (doc) out.description = doc;
    if (i.deprecated) out.deprecated = true;
    return out;
  }

  /** A field's value: its kind, with the objects the model has for it. */
  function valueOf(row) {
    const shapes = model.shapesOf(row.path);
    const variants = shapes.filter(s => variantOf(s)?.base === row.path);
    const listed = /array|listable/.test(row.info.json || row.rust?.type || '') || /\bVec\b|listable/.test(`${row.rust?.type} ${row.rust?.meta}`);
    const shaped = {};
    if (variants.some(s => variantOf(s).label !== '')) {
      // Entries of types: a list's, or one object's whose `type` picks.
      const entry = entryOf(row.path, shapes);
      if (shapes.includes(`${row.path}[]`) || (!shapes.includes(row.path) && listed)) shaped.array = { type: 'array', items: entry };
      else shaped.object = entry;
    } else {
      if (shapes.includes(`${row.path}[]`)) shaped.array = { type: 'array', items: objectOf(`${row.path}[]`) };
      // A map's object is its values': any key, each such an object.
      if (shapes.includes(row.path)) shaped.object = isMap(row) ? { type: 'object', additionalProperties: objectOf(row.path) } : objectOf(row.path);
    }
    // A logical rule's rules: rules as the list it is in has them, without
    // their actions.
    const v = variantOf(splitPath(row.path).slice(0, -1).join('.'));
    if (row.key === 'rules' && v?.label === 'logical' && !shapes.length) shaped.array = { type: 'array', items: ref(nestedRules(v.base)) };
    // One entry or a list of them.
    if (shaped.array?.items && !shaped.object) shaped.object = shaped.array.items;

    let kind, values, hints;
    if (row.info.origin === 'sing-box') {
      kind = row.info.json;
      // sail's own enum is what it takes; sing-box's list is a hint, as
      // sail takes more than some of them (aliases, its own values).
      const own = row.rust && !row.rust.tagOf ? rustKind(model, row.rust.type, row.rust.owner.source, row.rust.meta).enum : null;
      if (own) values = own;
      else hints = row.info.enum;
    } else if (row.rust?.tagOf) {
      const d = row.rust.tagOf;
      const rule = arg(serdeOf(d.attributes), 'rename_all');
      kind = 'string';
      values = d.shape.variants.map(v => arg(serdeOf(v.attributes), 'rename') ?? applyCase(v.name, rule, true));
    } else if (row.rust) {
      ({ kind, enum: values } = rustKind(model, row.rust.type, row.rust.owner.source, row.rust.meta));
    } else kind = 'any';
    if (kind === 'any' && (shaped.array || shaped.object)) kind = shaped.array ? 'array' : 'object';
    let schema = kindSchema(kind, shaped);
    if (values) schema = withEnum(schema, values);
    if (hints) schema = { ...schema, examples: hints };
    return schema;
  }

  const withEnum = (schema, values) => {
    if (schema.type === 'string' || schema.type === 'number') return { ...schema, enum: values };
    if (schema.anyOf) return { anyOf: schema.anyOf.map(s => withEnum(s, values)) };
    if (schema.type === 'array' && schema.items) return { ...schema, items: withEnum(schema.items, values) };
    return schema;
  };

  const isMap = row => row.info.json === 'map' || /^(Option<)?(std::collections::)?(HashMap|BTreeMap|IndexMap)</.test((row.rust?.type || '').replace(/\s+/g, ''));
  const hasOwnFields = id => model.rowsOf(id).some(r => r.key !== 'type');
  const building = new Set();

  /** An object's schema: its rows, closed, under `$defs`. */
  function objectOf(id, extra = [], name = id || 'config', more = {}) {
    if (!(name in defs) && !building.has(name)) {
      building.add(name);
      const properties = {};
      const required = [];
      for (const row of [...model.rowsOf(id), ...extra]) {
        if (row.key in properties) continue;
        properties[row.key] = annotate(valueOf(row), row);
        if (row.info.required && row.info.tier === 'supported') required.push(row.key);
      }
      for (const [k, p] of Object.entries(more)) if (!(k in properties)) properties[k] = p;
      const v = variantOf(id);
      if (v && v.label !== '' && !(keyOf(v.label) in properties)) properties[keyOf(v.label)] = { const: labelValue(v.label) };
      const def = { type: 'object', properties, additionalProperties: false };
      if (required.length) def.required = required;
      defs[name] = def;
      building.delete(name);
    }
    return ref(name);
  }

  /** An entry of the list (or the object) `base`, by its type and action. */
  function entryOf(base, shapes) {
    const variants = shapes.filter(s => variantOf(s)?.base === base);
    // A type sail does not implement but warns of is taken (and dropped);
    // one it refuses is not among the values.
    const taken = s => !model.missing(s) || model.missing(s).tier === 'ignored';
    const typed = variants.filter(s => variantOf(s).label !== '' && !variantOf(s).label.includes('=') && taken(s));
    const actions = variants.filter(s => variantOf(s).label.includes('=') && taken(s));
    const plain = variants.find(s => variantOf(s).label === '');
    // The action key is the plain entry's; every shape of entry takes it.
    const actionKeys = [...new Set(actions.map(s => keyOf(variantOf(s).label)))];
    const actionRows = [...(plain ? model.rowsOf(plain).filter(r => actionKeys.includes(r.key)) : []), ...actions.flatMap(s => model.rowsOf(s))];
    // An action key the model has no row for takes the actions' names.
    const more = {};
    for (const k of actionKeys) {
      if (!actionRows.some(r => r.key === k)) more[k] = { enum: actions.filter(s => keyOf(variantOf(s).label) === k).map(s => labelValue(variantOf(s).label)) };
    }
    const suffix = actions.length ? '+actions' : '';
    const dflt = plain && hasOwnFields(plain) ? plain : null;
    const labels = typed.map(s => variantOf(s).label);
    const branches = typed.map(s => ({
      if: { properties: { type: { const: variantOf(s).label } }, required: ['type'] },
      then: model.missing(s) ? { deprecated: true, description: `sail ignores this type, with a warning: ${model.missing(s).reason}` } : objectOf(s, actionRows, s + suffix, more),
    }));
    if (!typed.length && dflt) return objectOf(dflt, actionRows, dflt + suffix, more);
    // The `type` field: in the list's plain entry, or in the object.
    const holderAt = plain ?? (shapes.includes(base) ? base : null);
    const holder = holderAt ? model.rowsOf(holderAt).find(r => r.key === 'type') : null;
    const values = [...labels];
    if (dflt) {
      // The type an entry is without one, as sing-box names it.
      for (const v of holder?.info.enum || []) if (!values.includes(v) && !shapes.includes(`${base}[${v}]`)) values.push(v);
      branches.push({ if: { properties: { type: { enum: labels } }, required: ['type'] }, else: objectOf(dflt, actionRows, dflt + suffix, more) });
    }
    const entry = { type: 'object', properties: { type: { enum: values } }, allOf: branches };
    if (!dflt) entry.required = ['type'];
    if (holder?.rust?.docs) entry.properties.type.description = holder.rust.docs;
    return entry;
  }

  /** The rules a logical rule of `base` combines: its own and the default
   * rule's conditions, no actions. */
  function nestedRules(base) {
    const name = `${base}[nested]`;
    if (name in defs || building.has(name)) return name;
    building.add(name);
    const shapes = model.shapesOf(base);
    const plain = `${base}[]`;
    const logical = `${base}[logical]`;
    const conditions = model.rowsOf(plain).filter(r => r.key !== 'action');
    const def = {
      type: 'object',
      properties: { type: { enum: ['default', 'logical'] } },
      allOf: [
        {
          if: { properties: { type: { const: 'logical' } }, required: ['type'] },
          then: shapes.includes(logical) ? objectOf(logical, [], `${logical}[nested]`) : {},
          else: objectOf(plain, [], `${plain}[conditions]`),
        },
      ],
    };
    // Its conditions without actions, the action field kept off.
    defs[`${plain}[conditions]`] = closedWithout(defs[`${plain}[conditions]`], ['action']);
    defs[name] = def;
    building.delete(name);
    return name;
  }
  const closedWithout = (def, keys) => {
    if (!def) return def;
    const properties = { ...def.properties };
    for (const k of keys) delete properties[k];
    return { ...def, properties };
  };

  const root = objectOf('');
  const schema = {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: id,
    title,
    description: `${description} (sing-box ${version} JSON and sail's extensions)`,
    ...defs.config,
    $defs: Object.fromEntries(Object.entries(defs).filter(([k]) => k !== 'config').sort(([a], [b]) => a.localeCompare(b))),
  };
  void root;
  return schema;
}

// ---------------------------------------------------------------- checking

/** What `value` breaks of `schema`, as `path: what` lines; none if it is
 * valid. Only the keywords `buildSchema` writes. */
export function validate(schema, value) {
  const errors = [];
  const resolve = r => {
    const name = decodeURIComponent(r.replace(/^#\/\$defs\//, ''));
    const def = schema.$defs?.[name];
    if (!def) throw new Error(`No definition: ${r}`);
    return def;
  };
  const typeOf = v => (v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v === 'boolean' ? 'boolean' : typeof v);
  const check = (s, v, at, out) => {
    if (s === true || s === undefined) return;
    if (s === false) return out.push(`${at}: not allowed`);
    if (s.$ref) check(resolve(s.$ref), v, at, out);
    if (s.not) {
      const inner = [];
      check(s.not, v, at, inner);
      if (!inner.length) out.push(`${at}: ${s.description || 'not allowed'}`);
    }
    if (s.type) {
      const t = typeOf(v);
      const ok = s.type === t || (s.type === 'number' && t === 'number') || (s.type === 'integer' && Number.isInteger(v));
      if (!ok) return out.push(`${at}: ${t}, not ${s.type}`);
    }
    if ('const' in s && v !== s.const) out.push(`${at}: ${JSON.stringify(v)}, not ${JSON.stringify(s.const)}`);
    if (s.enum && !s.enum.includes(v)) out.push(`${at}: ${JSON.stringify(v)} is none of ${s.enum.join(', ')}`);
    if (s.anyOf) {
      const tries = s.anyOf.map(a => {
        const e = [];
        check(a, v, at, e);
        return e;
      });
      if (!tries.some(e => !e.length)) out.push(...tries.reduce((a, b) => (b.length < a.length ? b : a)));
    }
    if (s.allOf) for (const a of s.allOf) check(a, v, at, out);
    if (s.if) {
      const cond = [];
      check(s.if, v, at, cond);
      if (!cond.length) check(s.then, v, at, out);
      else check(s.else, v, at, out);
    }
    if (typeOf(v) === 'object') {
      for (const k of s.required || []) if (!(k in v)) out.push(`${at}: ${k} is required`);
      if (s.properties) {
        for (const [k, x] of Object.entries(v)) {
          const p = `${at ? at + '.' : ''}${k}`;
          if (k in s.properties) check(s.properties[k], x, p, out);
          else if (s.additionalProperties === false) out.push(`${p}: not a field here`);
          else check(s.additionalProperties, x, p, out);
        }
      } else if (s.additionalProperties !== undefined) {
        for (const [k, x] of Object.entries(v)) check(s.additionalProperties, x, `${at ? at + '.' : ''}${k}`, out);
      }
    }
    if (typeOf(v) === 'array' && s.items) v.forEach((x, i) => check(s.items, x, `${at}[${i}]`, out));
  };
  check(schema, value, '', errors);
  return errors;
}
