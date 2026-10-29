import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, unlinkSync, symlinkSync, linkSync, mkdirSync, lstatSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { writeBundle, verifyBundle } from '../scripts/portfolio-bundle.mjs';
const example = { title: '<script>fictional</script>', scope: 'synthetic-local-only', rows: [{ id: 'example', status: 'PASS' }], limitations: ['Not production evidence.'] };
function isolated(fn) { const dir = mkdtempSync(join(tmpdir(), 'portfolio-test-')); try { return fn(dir); } finally { rmSync(dir, { recursive: true, force: true }); } }
test('bundle hashes all evidence and renders hostile-looking text inert', () => isolated(dir => {
  assert.equal(writeBundle(example, dir).files, 3); assert.equal(verifyBundle(dir).authenticity_verified, false);
  const html = readFileSync(join(dir, 'index.html'), 'utf8'); assert.doesNotMatch(html, /<script>/); assert.match(html, /&lt;script&gt;/);
}));
test('evidence modification fails verification', () => isolated(dir => {
  writeBundle(example, dir); writeFileSync(join(dir, 'report.md'), 'tampered'); assert.throws(() => verifyBundle(dir), /mismatch/);
}));
test('manifest path traversal fails before reading it', () => isolated(dir => {
  writeBundle(example, dir); const path = join(dir, 'manifest.json'), m = JSON.parse(readFileSync(path));
  m.files['../outside'] = m.files['results.json']; writeFileSync(path, JSON.stringify(m)); assert.throws(() => verifyBundle(dir), /manifest paths/);
}));
test('missing evidence and symbolic links are rejected', () => isolated(dir => {
  writeBundle(example, dir); unlinkSync(join(dir, 'report.md')); assert.throws(() => verifyBundle(dir), /missing/);
  symlinkSync(join(dir, 'results.json'), join(dir, 'report.md')); assert.throws(() => verifyBundle(dir), /regular file/);
}));
test('credential-like output and non-synthetic scope are not exportable', () => isolated(dir => {
  assert.throws(() => writeBundle({ ...example, title: 'Bearer ' + 'x'.repeat(40) }, dir), /Credential/);
  assert.throws(() => writeBundle({ ...example, scope: 'customer-production' }, dir), /synthetic/);
}));

const outputs = ['results.json', 'report.md', 'index.html', 'manifest.json'];
for (const name of outputs) {
  for (const kind of ['dangling symlink', 'symlink', 'hard link', 'directory']) {
    test(`export rejects ${kind} at ${name} before changing any output`, () => isolated(root => {
      const dir = join(root, 'bundle'), outside = join(root, 'outside');
      writeBundle(example, dir);
      const original = Object.fromEntries(outputs.map(file => [file, readFileSync(join(dir, file))]));
      unlinkSync(join(dir, name));
      if (kind !== 'dangling symlink') writeFileSync(outside, 'outside must remain unchanged');
      if (kind.includes('symlink')) symlinkSync(outside, join(dir, name));
      else if (kind === 'hard link') linkSync(outside, join(dir, name));
      else mkdirSync(join(dir, name));
      assert.throws(() => writeBundle({ ...example, title: 'changed report' }, dir), /regular file/);
      if (kind === 'dangling symlink') assert.equal(lstatSync(outside, { throwIfNoEntry: false }), undefined);
      else assert.equal(readFileSync(outside, 'utf8'), 'outside must remain unchanged');
      for (const file of outputs.filter(file => file !== name)) {
        assert.deepEqual(readFileSync(join(dir, file)), original[file], file + ' must remain unchanged');
      }
    }));
  }
}

test('regular bundle files can be refreshed and verified', () => isolated(dir => {
  writeBundle(example, dir);
  assert.equal(writeBundle({ ...example, title: 'updated report' }, dir).integrity_verified, true);
  assert.equal(JSON.parse(readFileSync(join(dir, 'results.json'))).title, 'updated report');
}));
