// Dependency-free export and integrity verification for synthetic portfolio evidence.
// Hash verification is NOT signature verification, customer authorization or safety certification.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, lstatSync, readdirSync, mkdtempSync, renameSync, rmSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const NAMES = ['results.json', 'report.md', 'index.html'];
const MAX_BYTES = 4 * 1024 * 1024;
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const escapeHtml = value => String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const regular = path => {
  const s = lstatSync(path);
  assert.ok(s.isFile() && !s.isSymbolicLink() && s.nlink === 1, 'Expected unlinked regular file');
  assert.ok(s.size <= MAX_BYTES, 'Artifact exceeds limit'); return s;
};
const outputPath = path => {
  // lstat sees dangling symlinks too; only an absent entry is safe to create.
  if (lstatSync(path, { throwIfNoEntry: false }) !== undefined) regular(path);
};
export function provenance(root = resolve('.')) {
  const git = (...args) => execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: MAX_BYTES }).trim();
  try {
    const commit = git('rev-parse', 'HEAD'), tree = git('rev-parse', 'HEAD^{tree}');
    const paths = git('ls-files', '-z', '--', 'src', 'scripts', 'test', 'fixtures', 'contracts', 'package.json', 'package-lock.json').split('\0').filter(Boolean).sort();
    return { commit, tree, dirty: git('status', '--porcelain', '--untracked-files=normal') !== '', node: process.version,
      files: Object.fromEntries(paths.map(path => { regular(join(root, path)); return [path, sha256(readFileSync(join(root, path)))]; })) };
  } catch { return { commit: null, tree: null, dirty: null, node: process.version, files: {}, note: 'Source revision could not be verified; do not claim a pinned source build.' }; }
}
function table(rows) {
  return ['| Case | Result |', '|---|---|', ...rows.map(r => `| ${String(r.id).replace(/[|\r\n]/g, ' ')} | ${String(r.status).replace(/[|\r\n]/g, ' ')} |`)];
}
export function writeBundle(report, directory = resolve('artifacts/practitioner')) {
  assert.ok(report && typeof report.title === 'string' && Array.isArray(report.rows) && Array.isArray(report.limitations), 'Invalid portfolio report');
  assert.ok(report.scope === 'synthetic-local-only', 'Only synthetic local reports are exportable');
  const serialized = JSON.stringify(report, null, 2) + '\n';
  assert.ok(!/Bearer\s+[A-Za-z0-9_-]{20,}/i.test(serialized), 'Credential-shaped content rejected');
  const text = ['# ' + report.title, '', '**Synthetic local evidence. Not customer pentesting or production certification.**', '',
    '## Result summary', '', ...table(report.rows), '', '## Limits', '', ...report.limitations.map(x => '- ' + x), '',
    '## Full evidence', '', 'See results.json. Source commit and exact source-file hashes are recorded where available.',
    'manifest.json checks accidental or untrusted changes; it does not authenticate the author.', ''].join('\n');
  const html = '<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">' +
    '<title>' + escapeHtml(report.title) + '</title><style>body{font:16px/1.65 system-ui;max-width:1000px;margin:2rem auto;padding:0 1rem}table{border-collapse:collapse;width:100%}td,th{padding:.5rem;border:1px solid #ccc;text-align:left}pre{white-space:pre-wrap;overflow-wrap:anywhere}small{display:block;margin:1rem 0}</style>' +
    '<h1>' + escapeHtml(report.title) + '</h1><p><strong>合成データ・ローカル検証。顧客診断実績や本番安全性の証明ではありません。</strong></p><table><tr><th>Case</th><th>Result</th></tr>' +
    report.rows.map(r => '<tr><td>' + escapeHtml(r.id) + '</td><td>' + escapeHtml(r.status) + '</td></tr>').join('') + '</table><h2>Limitations</h2><ul>' +
    report.limitations.map(x => '<li>' + escapeHtml(x) + '</li>').join('') + '</ul><h2>Evidence</h2><pre>' + escapeHtml(serialized) + '</pre></html>\n';
  mkdirSync(directory, { recursive: true });
  assert.ok(lstatSync(directory).isDirectory() && !lstatSync(directory).isSymbolicLink(), 'Artifact directory must not be a symlink');
  assert.ok(readdirSync(directory).every(n => [...NAMES, 'manifest.json'].includes(n)), 'Unexpected files in artifact directory');
  const files = { 'results.json': serialized, 'report.md': text, 'index.html': html }, entries = {};
  for (const [name, data] of Object.entries(files)) {
    assert.ok(Buffer.byteLength(data) <= MAX_BYTES);
    entries[name] = { bytes: Buffer.byteLength(data), sha256: sha256(data) };
  }
  const manifest = { schema_version: 'synthetic-portfolio-bundle/1.0', authenticity_verified: false, files: entries };
  files['manifest.json'] = JSON.stringify(manifest, null, 2) + '\n';
  // Validate every destination before changing any existing report or manifest.
  for (const name of Object.keys(files)) outputPath(join(directory, name));
  const staging = mkdtempSync(join(directory, '.bundle-'));
  try {
    for (const [name, data] of Object.entries(files)) {
      writeFileSync(join(staging, name), data, { flag: 'wx', mode: 0o600 });
    }
    for (const name of Object.keys(files)) outputPath(join(directory, name));
    // Renaming a fresh file never opens/follows the destination link target.
    // The caller must own the directory; concurrent directory replacement is unsupported.
    for (const name of Object.keys(files)) renameSync(join(staging, name), join(directory, name));
  } finally { rmSync(staging, { recursive: true, force: true }); }
  return verifyBundle(directory);
}
export function verifyBundle(directory = resolve('artifacts/practitioner')) {
  assert.ok(lstatSync(directory).isDirectory() && !lstatSync(directory).isSymbolicLink(), 'Artifact directory must not be a symlink');
  assert.deepEqual(readdirSync(directory).sort(), [...NAMES, 'manifest.json'].sort(), 'Unexpected/missing artifact');
  const manifestPath = join(directory, 'manifest.json'); regular(manifestPath);
  assert.ok(lstatSync(manifestPath).size <= 4096, 'Manifest too large');
  const raw = readFileSync(manifestPath), manifest = JSON.parse(raw);
  assert.equal(manifest.schema_version, 'synthetic-portfolio-bundle/1.0'); assert.equal(manifest.authenticity_verified, false);
  assert.deepEqual(Object.keys(manifest.files).sort(), [...NAMES].sort(), 'Invalid manifest paths');
  for (const name of NAMES) {
    const e = manifest.files[name]; assert.ok(e && /^[a-f0-9]{64}$/.test(e.sha256) && Number.isSafeInteger(e.bytes) && e.bytes >= 0 && e.bytes <= MAX_BYTES, 'Invalid manifest entry');
    const path = join(directory, name); regular(path); const data = readFileSync(path);
    assert.equal(data.length, e.bytes, 'Length mismatch: ' + name); assert.equal(sha256(data), e.sha256, 'Hash mismatch: ' + name);
  }
  return { integrity_verified: true, authenticity_verified: false, files: NAMES.length, manifest_sha256: sha256(raw) };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  assert.deepEqual(process.argv.slice(2), ['verify'], 'Usage: node scripts/portfolio-bundle.mjs verify');
  console.log(JSON.stringify(verifyBundle(), null, 2));
}
