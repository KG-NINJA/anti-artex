import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const read = path => JSON.parse(readFileSync(new URL('../' + path, import.meta.url), 'utf8'));
const anti = read('package.json').name === 'anti-artex';
const output = anti ? '../dist/src/' : '../dist/';
const { verifyEvidence, verifyEvidenceDetailed, sealEvidence } = await import(output + 'evidence-contract.js');
const { verifyEvidenceJson, MAX_EVIDENCE_BYTES, MAX_JSON_DEPTH } = await import(output + 'evidence-json.js');
const goldens = read('contracts/fixtures/evidence-v2.json');
const ok = { valid: true, schema_version: '2.0.0' };
const fail = code => ({ valid: false, code });
const json = JSON.stringify(goldens[0]);

test('raw UTF-8 and text verification accept both source profiles without changing v2 goldens', async () => {
  assert.deepEqual(read('fixtures/verify-example.json'), goldens[0]);
  for (const event of goldens) {
    assert.deepEqual(await verifyEvidenceDetailed(event), ok);
    for (const text of [JSON.stringify(event), JSON.stringify(event, null, 2)]) {
      assert.deepEqual(await verifyEvidenceJson(text), ok);
      assert.deepEqual(await verifyEvidenceJson(new TextEncoder().encode(text)), ok);
    }
  }
});

test('duplicate top-level and escaped property names are rejected before JSON.parse loses them', async () => {
  for (const key of ['schema_version', '\\u0073chema_version', 'schema_\\u0076ersion']) {
    const ambiguous = '{"' + key + '":"untrusted-original",' + json.slice(1);
    assert.equal(await verifyEvidence(JSON.parse(ambiguous)), true); // the old object-only boundary cannot see duplicates
    assert.deepEqual(await verifyEvidenceJson(ambiguous), fail('duplicate_key'));
  }
  const duplicateHash = '{"content_hash":"untrusted-original",' + json.slice(1);
  assert.deepEqual(await verifyEvidenceJson(duplicateHash), fail('duplicate_key'));
});

test('nested duplicates fail independently of key escaping or which value comes last', async () => {
  for (const text of [
    json.replace('"value":0.65', '"value":0.2,"value":0.65'),
    json.replace('"value":0.65', '"value":0.65,"value":0.2'),
    json.replace('"indicators":', '"\\u0069ndicators":[],"indicators":'),
    '{"__proto__":{},"__proto__":{}}'
  ]) assert.deepEqual(await verifyEvidenceJson(text), fail('duplicate_key'));
  assert.equal(Object.hasOwn(Object.prototype, 'polluted'), false);
});

test('quoted punctuation and escaped quotes are data; repeated names in separate objects are not duplicates', async () => {
  const payload = { ...goldens[1], evidence: { path: '/observation', observation: '日本語 🐕 { "path": ["x", "x"] } \\ : ,' } };
  delete payload.event_id; delete payload.content_hash;
  const event = await sealEvidence(payload);
  assert.deepEqual(await verifyEvidenceJson(JSON.stringify(event)), ok);
  assert.deepEqual(await verifyEvidenceJson('[{"name":1},{"name":2}]'), fail('invalid_shape'));
});

test('byte cap includes whitespace and multibyte text; exact boundary succeeds', async () => {
  const padded = json + ' '.repeat(MAX_EVIDENCE_BYTES - Buffer.byteLength(json));
  assert.deepEqual(await verifyEvidenceJson(padded), ok);
  assert.deepEqual(await verifyEvidenceJson(padded + ' '), fail('input_too_large'));
  assert.deepEqual(await verifyEvidenceJson(new Uint8Array(MAX_EVIDENCE_BYTES + 1)), fail('input_too_large'));
  const multibyte = '"' + '日'.repeat(22000) + '"';
  assert.ok(multibyte.length < MAX_EVIDENCE_BYTES);
  assert.deepEqual(await verifyEvidenceJson(multibyte), fail('input_too_large'));
});

test('excessive nesting is rejected before parsing; exact depth and malformed syntax have stable codes', async () => {
  assert.deepEqual(await verifyEvidenceJson('['.repeat(MAX_JSON_DEPTH + 1) + '0' + ']'.repeat(MAX_JSON_DEPTH + 1)), fail('nesting_limit'));
  assert.deepEqual(await verifyEvidenceJson('['.repeat(MAX_JSON_DEPTH) + '0' + ']'.repeat(MAX_JSON_DEPTH)), fail('invalid_shape'));
  for (const text of ['', '{', '[}', '{"x":}', '{"x":1,}', '{"x":"unterminated}', '{"x":"\\q"}', json + '{}', '\ufeff' + json])
    assert.deepEqual(await verifyEvidenceJson(text), fail('invalid_json'), text.slice(0, 16));
});

test('invalid UTF-8 and invalid Unicode fail without replacement or parser/input disclosure', async () => {
  for (const bytes of [[0xff], [0xc0, 0xaf], [0xed, 0xa0, 0x80]])
    assert.deepEqual(await verifyEvidenceJson(Uint8Array.from(bytes)), fail('invalid_utf8'));
  assert.deepEqual(await verifyEvidenceJson(JSON.stringify({ ...goldens[0], remediation: '\ud800' })), fail('invalid_encoding'));
  assert.deepEqual(await verifyEvidenceJson('{"secret-fixture-value": malformed}'), fail('invalid_json'));
});

test('detailed errors distinguish version, shape, event identity and content integrity while boolean API is preserved', async () => {
  const invalid = [
    [{ ...goldens[0], schema_version: '1.0' }, 'unsupported_version'],
    [{ ...goldens[0], confidence: 'high' }, 'invalid_shape'],
    [{ ...goldens[0], remediation: 'Modified' }, 'event_id_mismatch'],
    [{ ...goldens[0], content_hash: 'sha256:' + '0'.repeat(64) }, 'content_hash_mismatch']
  ];
  for (const [event, code] of invalid) {
    assert.deepEqual(await verifyEvidenceDetailed(event), fail(code));
    assert.deepEqual(await verifyEvidenceJson(JSON.stringify(event)), fail(code));
    assert.equal(await verifyEvidence(event), false);
  }
});

test('raw verifier neither fetches nor mutates caller buffers', async () => {
  const oldFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error('External request forbidden'); };
  try {
    const bytes = Buffer.from(json), before = Buffer.from(bytes);
    assert.deepEqual(await verifyEvidenceJson(bytes), ok); assert.deepEqual(bytes, before);
  } finally { globalThis.fetch = oldFetch; }
});

const cli = (args, input) => spawnSync(process.execPath, [fileURLToPath(new URL('../scripts/verify-evidence.mjs', import.meta.url)), ...args], { input, encoding: 'utf8', timeout: 5000 });
test('offline CLI supports a file or stdin and emits machine-readable results and exit codes', () => {
  const dir = mkdtempSync(join(tmpdir(), 'evidence-cli-'));
  try {
    const path = join(dir, 'event.json'); writeFileSync(path, json);
    for (const [args, input] of [[[path], undefined], [['-'], json]]) {
      const result = cli(args, input);
      assert.equal(result.status, 0, result.stderr); assert.deepEqual(JSON.parse(result.stdout), ok);
    }
    const duplicate = cli(['-'], '{"schema_version":"hidden",' + json.slice(1));
    assert.equal(duplicate.status, 1); assert.deepEqual(JSON.parse(duplicate.stdout), fail('duplicate_key'));
    const large = cli(['-'], ' '.repeat(MAX_EVIDENCE_BYTES + 1));
    assert.equal(large.status, 1); assert.deepEqual(JSON.parse(large.stdout), fail('input_too_large'));
    for (const [args, code] of [[[], 'usage_error'], [[join(dir, 'missing-secret-file.json')], 'read_error']]) {
      const result = cli(args);
      assert.equal(result.status, 2); assert.deepEqual(JSON.parse(result.stdout), fail(code));
      assert.doesNotMatch(result.stdout + result.stderr, /missing-secret-file/);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
