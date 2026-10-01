// Writes the configuration reference (website/src/content/docs/reference and
// its Chinese twin) and the configuration's JSON schema (public/schema.json)
// from sail's source and the sing-box field registry.
//
//   node scripts/build-config.mjs           write the pages
//   node scripts/build-config.mjs --check   fail if a page is not current
//   node scripts/build-config.mjs --report  also list the fields sail reads
//                                           without a doc comment, and those
//                                           it reads that the registry lacks
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { COMPAT, buildModel, render, stale } from './reference.mjs';
import { buildSchema } from './schema.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const docs = path.join(root, 'website/src/content/docs');
const args = new Set(process.argv.slice(2));

const run = spawnSync('cargo', ['run', '--quiet', '--manifest-path', path.join(root, 'website/tools/config-extract/Cargo.toml'), '--', root], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
if (run.status !== 0) throw new Error(run.stderr || String(run.error));
const extract = JSON.parse(run.stdout);
const json = file => JSON.parse(readFileSync(path.join(root, file), 'utf8'));
const fields = json('sail/src/config/singbox/fields.json');
const tiers = json('sail/src/config/singbox/fields.tiers.json');
const compat = {};
for (const c of COMPAT) {
  for (const file of [c.file, `zh/${c.file}`]) {
    const at = path.join(root, 'docs/compat', file);
    compat[file] = existsSync(at) ? readFileSync(at, 'utf8') : null;
  }
}

const { files, undocumented, unlisted } = render({ fields, tiers, extract, compat });
const schema = buildSchema(buildModel({ fields, tiers, extract, compat }), {
  version: fields.sing_box,
  id: 'https://peakpassvpn.github.io/sail/schema.json',
  title: 'sail configuration',
  description: "sail's native configuration format",
});
const schemaAt = path.join(root, 'website/public/schema.json');
const schemaText = JSON.stringify(schema, null, 1) + '\n';

const read = name => {
  const at = path.join(docs, name);
  return existsSync(at) ? readFileSync(at, 'utf8') : null;
};
const list = () => ['reference', 'zh/reference'].flatMap(dir => (existsSync(path.join(docs, dir)) ? readdirSync(path.join(docs, dir)).filter(f => f.endsWith('.md')).map(f => `${dir}/${f}`) : []));

if (args.has('--check')) {
  const bad = stale(files, read, list);
  if (!existsSync(schemaAt) || readFileSync(schemaAt, 'utf8') !== schemaText) bad.push('public/schema.json');
  if (bad.length) {
    console.error(`The configuration reference is not current: ${bad.join(', ')}.\nRun \`npm run docs:config\` in website/ and commit the result.`);
    process.exit(1);
  }
  console.log(`The configuration reference is current (${Object.keys(files).length} pages).`);
} else {
  for (const name of list()) if (!(name in files)) throw new Error(`Not generated, remove it or the generator's page list: ${name}`);
  for (const [name, text] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(docs, name)), { recursive: true });
    writeFileSync(path.join(docs, name), text);
  }
  writeFileSync(schemaAt, schemaText);
  console.log(`Generated ${Object.keys(files).length} reference pages from ${extract.definitions.length} definitions and ${fields.fields.length} sing-box fields.`);
}
if (args.has('--report')) {
  console.log(`\nFields sail reads without a doc comment (${undocumented.length}):\n${undocumented.join('\n')}`);
  console.log(`\nFields sail reads where sing-box has the object, in neither the registry nor its extensions (${unlisted.length}):\n${unlisted.join('\n')}`);
}
