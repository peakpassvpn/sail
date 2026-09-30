import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = fileURLToPath(new URL('../../', import.meta.url));
const run = spawnSync('cargo', ['run', '--quiet', '--manifest-path', path.join(root, 'website/tools/config-extract/Cargo.toml'), '--', root], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
if (run.status !== 0) throw new Error(run.stderr || String(run.error));
const definitions = JSON.parse(run.stdout);
const groups = {
  common: definitions.filter(d => d.source.endsWith('config/model.rs') || d.source.endsWith('net/dial/fields.rs')),
  inbounds: definitions.filter(d => d.source.includes('/protocol/') && (d.source.includes('/inbound') || /Inbound/.test(d.name))),
  outbounds: definitions.filter(d => d.source.includes('/protocol/') && !d.source.includes('/inbound') && !/Inbound/.test(d.name)),
  transport: definitions.filter(d => d.source.includes('/transport/')),
};
const esc = text => String(text).replaceAll('|', '\\|').replaceAll('\n', ' ');
const meta = attrs => attrs.metadata.filter(a => a.startsWith('serde')).join(' ');
const rename = (name, attrs) => meta(attrs).match(/\brename\s*=\s*"([^"]+)"/)?.[1] ?? name;
for (const zh of [false, true]) {
  const titles = zh ? ['通用配置', '入站配置', '出站与策略组', '传输层配置'] : ['Common configuration', 'Inbound configuration', 'Outbounds and groups', 'Transport configuration'];
  const directory = path.join(root, 'website/src/content/docs', zh ? 'zh/reference' : 'reference');
  mkdirSync(directory, { recursive: true });
  let i = 0;
  for (const [group, items] of Object.entries(groups)) {
    if (!items.length) throw new Error(`Empty configuration group: ${group}`);
    let body = `---\ntitle: ${titles[i++]}\ndescription: ${zh ? '从 Sail 配置源码自动提取的字段、类型与序列化规则。' : 'Fields, types and serialization rules extracted from Sail configuration source.'}\n---\n\n`;
    body += zh ? '本页由 Rust 语法树自动生成，请修改源码注释后重新构建。类型使用源码记法；`Option<T>` 表示可省略，`Vec<T>` 表示数组。源码注释保留原文。\n\n' : 'Generated from the Rust syntax tree. Update source comments and rebuild to change this page. `Option<T>` is optional; `Vec<T>` is an array. Comments retain their source language.\n\n';
    body += zh ? '本表反映反序列化声明，不是完整的运行时校验 schema。条件编译可能限制当前平台或构建可用的协议；复杂默认值、组合支持及跨字段约束请结合[配置指南](/sail/zh/configuration/)与所链接源码，并执行 `sail -c config.json -T` 验证。\n\n' : 'These declarations are not a complete runtime validation schema. Features and platform gates affect availability. Consult the [configuration guide](/sail/configuration/) and linked source for computed defaults, supported combinations and cross-field constraints; validate with `sail -c config.json -T`.\n\n';
    for (const d of items) {
      body += `## ${d.name}\n\n[${zh ? '配置定义源码' : 'Configuration source'}](https://github.com/peakpassvpn/sail/blob/dev/${d.source})\n\n`;
      if (d.attributes.docs) body += `${esc(d.attributes.docs)}\n\n`;
      const container = meta(d.attributes);
      if (container) body += `Serde: \`${esc(container)}\`\n\n`;
      if (d.shape.fields) {
        body += zh ? '| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |\n| --- | --- | --- | --- |\n' : '| Field | Type | Omission / flattening | Source notes |\n| --- | --- | --- | --- |\n';
        for (const f of d.shape.fields) {
          const m = meta(f.attributes);
          const fallback = m.match(/default\s*=\s*"([^"]+)"/)?.[1];
          let rule = /flatten/.test(m) ? (zh ? '展开到当前对象，不是独立键' : 'Flattened into this object') : fallback ? `default: ${fallback}()` : /\bdefault\b/.test(m) ? 'Default::default()' : /^Option\s*</.test(f.type) ? (zh ? '可省略（None）' : 'Optional (None)') : /\bdefault\b/.test(container) ? (zh ? '继承对象默认值' : 'Container default') : (zh ? '必填' : 'Required');
          body += `| \`${esc(rename(f.name, f.attributes))}\` | \`${esc(f.type)}\` | ${esc(rule)} | ${esc(f.attributes.docs || '—')}${m ? `<br/>\`${esc(m)}\`` : ''} |\n`;
        }
        body += '\n';
      } else {
        const convention = container.match(/rename_all\s*=\s*"([^"]+)"/)?.[1];
        const untagged = /\buntagged\b/.test(container);
        body += zh ? '| 可选值 / 形态 | 源码说明 |\n| --- | --- |\n' : '| Value / shape | Source notes |\n| --- | --- |\n';
        for (const v of d.shape.variants) {
          let name = convention === 'lowercase' ? v.name.toLowerCase() : convention === 'snake_case' ? v.name.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase() : v.name;
          name = rename(name, v.attributes);
          const value = untagged ? v.payload : name + (v.payload ? ` ${v.payload}` : '');
          body += `| \`${esc(value)}\`${v.attributes.metadata.includes('default') ? ' (default)' : ''} | ${esc(v.attributes.docs || '—')} |\n`;
        }
        body += '\n';
      }
    }
    writeFileSync(path.join(directory, `${group}.md`), body);
  }
}
console.log(`Generated 8 reference pages from ${definitions.length} configuration definitions.`);
