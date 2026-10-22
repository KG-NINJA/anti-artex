import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import Ajv2020 from 'ajv/dist/2020.js';
import Ajv from 'ajv';
import formats from 'ajv-formats';

const read = path => JSON.parse(readFileSync(new URL('../' + path, import.meta.url), 'utf8'));
const anti = read('package.json').name === 'anti-artex';
const output = anti ? '../dist/src/' : '../dist/';
const { canonical, digest, sealEvidence, verifyEvidence } = await import(output + 'evidence-contract.js');
const producer = await import(output + 'evidence.js');
const schema = read('contracts/evidence-v2.schema.json');
const ajv = new Ajv2020({ allErrors: true }); formats(ajv);
const validate = ajv.compile(schema);
const goldens = read('contracts/fixtures/evidence-v2.json');
const inputs = read('contracts/fixtures/producer-inputs.json');
const legacyAnti = read('contracts/fixtures/legacy-anti-artex-v1.json');
const legacyMetadata = read('contracts/fixtures/legacy-mcp-security-evidence-v1.json');
const sha = value => createHash('sha256').update(canonical(value), 'utf8').digest('hex');
// Independent Node crypto implementation; deliberately bypasses shape validation for negative vectors.
const uncheckedSeal = event => {
  const payload = { ...event }; delete payload.event_id; delete payload.content_hash;
  const body = { ...payload, event_id: sha(payload) };
  return { ...body, content_hash: 'sha256:' + sha(body) };
};

test('legacy proposals accept their own artifact and reject the counterpart', () => {
  const legacyAjv = anti ? new Ajv2020() : new Ajv(); formats(legacyAjv);
  const legacy = legacyAjv.compile(read(anti ? 'docs/evidence-v1.schema.json' : 'schema/evidence-v1.json'));
  assert.equal(legacy(anti ? legacyAnti : legacyMetadata), true);
  assert.equal(legacy(anti ? legacyMetadata : legacyAnti), false);
  for (const event of goldens) assert.equal(legacy(event), false);
});

test('both producer profiles validate against common v2 schema and independent golden hashes', async () => {
  for (const event of goldens) {
    assert.ok(validate(event), JSON.stringify(validate.errors));
    assert.deepEqual(uncheckedSeal(event), event);
    assert.equal(await verifyEvidence(event), true);
  }
});

test('real local producer matches pinned synthetic golden artifacts', async () => {
  const generated = anti ? [await producer.makeEvidence(inputs.honeypot.finding, inputs.honeypot.flags, inputs.observed_at, inputs.assessment_id)] :
    await producer.assess(inputs.metadata, inputs.assessment_id, inputs.observed_at);
  assert.deepEqual(generated, goldens.filter(e => e.source_type === (anti ? 'mcp_honeypot' : 'submitted_mcp_metadata')));
});

test('UTF-8, escaping, nested key ordering, arrays and finite numbers match fixed vectors', async () => {
  for (const v of read('contracts/fixtures/canonical-vectors.json')) {
    assert.equal(canonical(v.value), v.canonical, v.name);
    assert.equal(await digest(v.value), v.sha256, v.name);
  }
  assert.equal(canonical(-0), '0');
  assert.notEqual(await digest('é'), await digest('e\u0301')); // no implicit normalization
});

test('key insertion order is irrelevant; array order is integrity protected', async () => {
  for (const event of goldens) {
    const reverse = v => Array.isArray(v) ? v.map(reverse) : v && typeof v === 'object' ?
      Object.fromEntries(Object.entries(v).reverse().map(([k, val]) => [k, reverse(val)])) : v;
    assert.equal(await verifyEvidence(reverse(event)), true);
    assert.equal(await verifyEvidence({ ...event, limitations: [...event.limitations].reverse() }), false);
  }
});

test('every payload field, event ID and content hash is bound; recomputing only content hash is insufficient', async () => {
  for (const event of goldens) {
    for (const key of Object.keys(event)) {
      const changed = structuredClone(event);
      if (key === 'event_id') changed[key] = '0'.repeat(64);
      else if (key === 'content_hash') changed[key] = 'sha256:' + '0'.repeat(64);
      else if (key === 'evidence') changed[key] = event.source_type === 'mcp_honeypot' ? { indicators: ['changed'] } : { path: '/', observation: 'Changed' };
      else if (key === 'confidence') changed[key].value = event.source_type === 'mcp_honeypot' ? 0.25 : 'low';
      else if (key === 'limitations') changed[key] = ['Changed'];
      else changed[key] = 'changed';
      assert.equal(await verifyEvidence(changed), false, key);
    }
    const { content_hash: oldHash, ...body } = { ...event, event_id: '0'.repeat(64) };
    assert.notEqual(oldHash, 'sha256:' + sha(body));
    assert.equal(await verifyEvidence({ ...body, content_hash: 'sha256:' + sha(body) }), false);
    const changed = { ...event, remediation: 'Changed', content_hash: undefined };
    delete changed.content_hash;
    assert.equal(await verifyEvidence({ ...changed, content_hash: 'sha256:' + sha(changed) }), false);
  }
});

test('schema and verifier reject wrong versions, coercions, unknown fields and invalid source profiles even with correct hashes', async () => {
  const changes = [
    e => { e.schema_version = '1'; }, e => { e.schema_version = '2.1.0'; },
    e => { e.schema_version = 2; }, e => { delete e.assessment_id; },
    e => { e.severity = ['low']; }, e => { e.confidence.value = ['medium']; },
    e => { e.confidence = 'medium'; }, e => { e.confidence = 0.65; },
    e => { e.confidence.extra = 'unknown'; }, e => { e.raw_headers = 'forbidden'; },
    e => { e.evidence.raw_body = 'forbidden'; }, e => { e.source_type = 'AI agent'; },
    e => { e.assessment_id = ''; }, e => { e.assessment_id = 'x'.repeat(129); },
    e => { e.observed_at = '2026-02-30T00:00:00.000Z'; },
    e => { e.observed_at = '2026-10-21T00:00:00Z'; },
    e => { e.observed_at = '2026-10-21T09:00:00.000+09:00'; },
    e => { e.limitations = []; }, e => { e.limitations = Array(17).fill('x'); },
    e => { e.limitations = ['x'.repeat(513)]; }, e => { e.remediation = ''; },
    e => { e.remediation = 'x'.repeat(1025); }, e => { e.finding_type = 'X'.repeat(65); }
  ];
  for (const event of goldens) {
    for (const change of changes) {
      const candidate = structuredClone(event); change(candidate);
      const sealed = uncheckedSeal(candidate);
      assert.equal(validate(sealed), false, change.toString());
      assert.equal(await verifyEvidence(sealed), false, change.toString());
    }
  }
  const negatives = [
    { ...goldens[0], confidence: { scale: 'heuristic_score', value: 1.1 } },
    { ...goldens[0], confidence: { scale: 'heuristic_score', value: -0.1 } },
    { ...goldens[0], confidence: { scale: 'heuristic_score', value: '0.65' } },
    { ...goldens[0], confidence: { scale: 'ordinal', value: 'medium' } },
    { ...goldens[0], evidence: { indicators: ['a', 'a'] } },
    { ...goldens[0], evidence: { indicators: [] } },
    { ...goldens[0], evidence: { indicators: ['a'], preview: null } },
    { ...goldens[0], evidence: { indicators: ['a'], preview: 'x'.repeat(257) } },
    { ...goldens[0], severity: 'critical' },
    { ...goldens[1], confidence: { scale: 'heuristic_score', value: 0.65 } },
    { ...goldens[1], evidence: { indicators: ['a'] } },
    { ...goldens[1], evidence: { path: '/bad~2escape', observation: 'x' } },
    { ...goldens[1], evidence: { path: '/', observation: '' } }
  ];
  for (const candidate of negatives) {
    const sealed = uncheckedSeal(candidate);
    assert.equal(validate(sealed), false, JSON.stringify(candidate));
    assert.equal(await verifyEvidence(sealed), false);
  }
});

test('v1 evidence is rejected without coercion, relabeling or rehashing', async () => {
  for (const legacy of [legacyAnti, legacyMetadata]) {
    const original = structuredClone(legacy);
    assert.equal(validate(legacy), false);
    assert.equal(await verifyEvidence(legacy), false);
    assert.deepEqual(legacy, original);
  }
});

test('Unicode previews and optional absence have explicit, distinct hash encodings', async () => {
  const event = goldens[0];
  for (const preview of ['', '日本語 🐕', '🐕'.repeat(256)]) {
    const candidate = uncheckedSeal({ ...event, evidence: { ...event.evidence, preview } });
    assert.ok(validate(candidate), JSON.stringify(validate.errors));
    assert.equal(await verifyEvidence(candidate), true);
    assert.notEqual(candidate.content_hash, event.content_hash);
  }
  if (anti) assert.equal(producer.redact('🐕🐕', 1), '🐕');
});

test('non-JSON values, invalid Unicode, deep/cyclic data and malformed envelopes fail closed', async () => {
  const cycle = {}; cycle.self = cycle;
  const values = [undefined, NaN, Infinity, 1n, () => {}, Symbol('x'), new Date(), [undefined], Array(1), { x: undefined }, '\ud800', '\udc00', cycle];
  for (const v of values) assert.throws(() => canonical(v));
  for (const v of [null, {}, [], 'x', { ...goldens[0], remediation: '\ud800' }, { ...goldens[0], confidence: { scale: 'heuristic_score', value: NaN } }])
    assert.equal(await verifyEvidence(v), false);
  await assert.rejects(sealEvidence({ ...goldens[0] })); // must not silently overwrite supplied IDs
});

test('both-profile verification is read-only and performs zero outbound requests', async () => {
  const oldFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error('External requests forbidden'); };
  try {
    const before = structuredClone(goldens);
    for (const event of goldens) assert.equal(await verifyEvidence(event), true);
    assert.deepEqual(goldens, before);
  } finally { globalThis.fetch = oldFetch; }
});
