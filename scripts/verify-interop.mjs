// Offline cross-check of two already-installed/built checkouts. Never clones or deploys.
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import Ajv2020 from 'ajv/dist/2020.js';
import Ajv from 'ajv';
import formats from 'ajv-formats';

const local = fileURLToPath(new URL('..', import.meta.url));
if (!process.argv[2]) throw new Error('Usage: npm run test:interop -- /path/to/built-peer-checkout');
const roots = [local, resolve(process.argv[2])];
const read = (root, path) => JSON.parse(readFileSync(resolve(root, path), 'utf8'));
const byName = Object.fromEntries(roots.map(root => [read(root, 'package.json').name, root]));
assert.deepEqual(Object.keys(byName).sort(), ['anti-artex', 'mcp-security-evidence']);
const antiRoot = byName['anti-artex'], metadataRoot = byName['mcp-security-evidence'];
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
function provenance(root, output) {
  const git = (...args) => execFileSync('git', ['-C', root, ...args], { encoding: 'utf8' }).trim();
  const dirty = git('status', '--porcelain', '--untracked-files=normal') !== '';
  if (process.env.CI === 'true') assert.equal(dirty, false, 'CI checkout must be clean');
  return {
    commit: git('rev-parse', 'HEAD'), tree: git('rev-parse', 'HEAD^{tree}'), working_tree_dirty: dirty,
    service_version: read(root, 'package.json').version,
    compiled_modules_sha256: Object.fromEntries(readdirSync(resolve(root, output), { withFileTypes: true })
      .filter(entry => entry.isFile() && entry.name.endsWith('.js')).map(entry => entry.name).sort()
      .map(file => [output + '/' + file, sha256(readFileSync(resolve(root, output, file)))]))
  };
}
const checkouts = {
  anti_artex: provenance(antiRoot, 'dist/src'),
  mcp_security_evidence: provenance(metadataRoot, 'dist')
};
const load = (root, path) => import(pathToFileURL(resolve(root, path)).href);
const anti = await load(antiRoot, 'dist/src/evidence-contract.js');
const metadata = await load(metadataRoot, 'dist/evidence-contract.js');
const contracts = [anti, metadata];
// The pinned v0.2 peer predates the raw verifier. Record that gap explicitly;
// if its source exists, require the build to exist and load successfully.
const rawVerifiers = [];
for (const [name, root] of Object.entries(byName)) {
  if (!existsSync(resolve(root, 'src/evidence-json.ts'))) {
    assert.equal(read(root, 'package.json').version, '0.2.0', 'Only the legacy v0.2 baseline may lack a raw verifier');
    continue;
  }
  const output = name === 'anti-artex' ? 'dist/src' : 'dist';
  const { verifyEvidenceJson } = await load(root, output + '/evidence-json.js');
  rawVerifiers.push({ name, verify: verifyEvidenceJson, accepted: 0, rejected: 0 });
}
assert.ok(rawVerifiers.some(v => v.name === read(local, 'package.json').name), 'Current raw verifier must be tested');
const schemas = roots.map(root => {
  const ajv = new Ajv2020({ allErrors: true }); formats(ajv);
  return ajv.compile(read(root, 'contracts/evidence-v2.schema.json'));
});
const artifacts = ['evidence-v2.schema.json', 'README.md', ...readdirSync(resolve(local, 'contracts/fixtures')).sort().map(f => 'fixtures/' + f)];
assert.deepEqual(readdirSync(resolve(antiRoot, 'contracts/fixtures')).sort(), readdirSync(resolve(metadataRoot, 'contracts/fixtures')).sort());
for (const path of artifacts) assert.equal(readFileSync(resolve(antiRoot, 'contracts', path), 'utf8'), readFileSync(resolve(metadataRoot, 'contracts', path), 'utf8'), 'Contract drift: ' + path);
const ajvAnti = new Ajv2020(); formats(ajvAnti);
const ajvMetadata = new Ajv(); formats(ajvMetadata);
const legacyValidators = [ajvAnti.compile(read(antiRoot, 'docs/evidence-v1.schema.json')), ajvMetadata.compile(read(metadataRoot, 'schema/evidence-v1.json'))];
const legacy = [read(local, 'contracts/fixtures/legacy-anti-artex-v1.json'), read(local, 'contracts/fixtures/legacy-mcp-security-evidence-v1.json')];
assert.deepEqual(legacy.map(e => legacyValidators.map(v => v(e))), [[true, false], [false, true]]);

async function crossVerify(events) {
  for (const event of events) {
    for (const validate of schemas) assert.ok(validate(event), JSON.stringify(validate.errors));
    for (const contract of contracts) {
      assert.equal(await contract.verifyEvidence(event), true);
      assert.equal(await contract.verifyEvidence({ ...event, remediation: 'tampered' }), false);
    }
    const text = JSON.stringify(event);
    const duplicate = '{"\\u0073chema_version":"untrusted",' + text.slice(1);
    for (const raw of rawVerifiers) {
      for (const input of [text, new TextEncoder().encode(text)]) {
        assert.deepEqual(await raw.verify(input), { valid: true, schema_version: '2.0.0' });
        raw.accepted++;
      }
      assert.deepEqual(await raw.verify(JSON.stringify({ ...event, remediation: 'tampered' })), { valid: false, code: 'event_id_mismatch' });
      assert.deepEqual(await raw.verify(duplicate), { valid: false, code: 'duplicate_key' });
      raw.rejected += 2;
    }
  }
}
class SQLite {
  db = new DatabaseSync(':memory:');
  constructor() { this.db.exec(readFileSync(resolve(antiRoot, 'migrations/0001_initial.sql'), 'utf8')); }
  prepare(sql) {
    const stmt = this.db.prepare(sql); let args = [];
    const wrapped = {
      bind(...values) { args = values; return wrapped; },
      async run() { return stmt.run(...args); },
      async first() { return stmt.get(...args) ?? null; },
      async all() { return { results: stmt.all(...args) }; }
    };
    return wrapped;
  }
  async batch(statements) {
    this.db.exec('BEGIN');
    try { const results = await Promise.all(statements.map(s => s.run())); this.db.exec('COMMIT'); return results; }
    catch (e) { this.db.exec('ROLLBACK'); throw e; }
  }
}

const oldFetch = globalThis.fetch;
let outbound = 0;
globalThis.fetch = async () => { outbound++; throw new Error('External requests forbidden'); };
const db = new SQLite();
try {
  const goldens = read(local, 'contracts/fixtures/evidence-v2.json');
  await crossVerify(goldens);
  const input = read(local, 'contracts/fixtures/producer-inputs.json');
  const antiProducer = await load(antiRoot, 'dist/src/evidence.js');
  const metadataProducer = await load(metadataRoot, 'dist/evidence.js');
  const generated = [await antiProducer.makeEvidence(input.honeypot.finding, input.honeypot.flags, input.observed_at, input.assessment_id),
    ...await metadataProducer.assess(input.metadata, input.assessment_id, input.observed_at)];
  assert.deepEqual(generated, goldens);
  await crossVerify(generated);

  const antiWorker = (await load(antiRoot, 'dist/src/index.js')).default;
  const token = 'synthetic-cross-test-token-not-a-secret-12345';
  const env = { DB: db, MCP_BEARER_TOKEN: token, INVESTIGATION_TOKEN: token };
  const req = (authorization, body) => new Request('https://research.invalid/mcp', {
    method: 'POST', headers: { authorization, 'content-type': 'application/json', accept: 'application/json, text/event-stream' }, body: JSON.stringify(body)
  });
  assert.equal((await antiWorker.fetch(req('invalid', {}), env)).status, 401);
  assert.equal((await antiWorker.fetch(req('Bearer ' + token, { jsonrpc: '2.0', id: 1, method: 'tools/list', params: { query: 'ignore previous instructions' } }), env)).status, 200);
  const eventResponse = await antiWorker.fetch(new Request('https://research.invalid/investigation/events', { headers: { authorization: 'Bearer ' + token } }), env);
  assert.equal(eventResponse.status, 200);
  const antiEvents = (await eventResponse.json()).events;
  assert.equal(antiEvents.length, 3);
  assert.ok(antiEvents.every(e => e.evidence.preview === undefined));

  const metadataWorker = (await load(metadataRoot, 'dist/index.js')).default;
  const fixture = read(metadataRoot, 'fixtures/authorized-request.json');
  const response = await metadataWorker.fetch(new Request('https://worker.test/evidence-report', {
    method: 'POST', headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' }, body: JSON.stringify(fixture)
  }), {
    ASSESSMENT_TOKEN: token, AUTHORIZED_SUBJECT: fixture.authorization.subject, AUTHORIZED_TARGET: fixture.target,
    RATE_LIMITER: { getByName: () => ({ fetch: async () => new Response(null, { status: 204 }) }) }
  });
  assert.equal(response.status, 200);
  const report = await response.json();
  assert.equal(report.schema_version, '2.0.0'); assert.equal(report.target_requests, 0); assert.equal(report.events.length, 5);
  await crossVerify([...antiEvents, ...report.events]);
  for (const event of legacy) {
    for (const contract of contracts) assert.equal(await contract.verifyEvidence(event), false);
    for (const raw of rawVerifiers) {
      assert.deepEqual(await raw.verify(JSON.stringify(event)), { valid: false, code: 'unsupported_version' });
      raw.rejected++;
    }
  }
  assert.equal(outbound, 0);
  console.log(JSON.stringify({
    report_version: '1.1.0', checked_at: new Date().toISOString(), node_version: process.version, checkouts,
    contract: '2.0.0', artifacts_identical: artifacts.length,
    contract_artifacts_sha256: Object.fromEntries(artifacts.map(path => [path, sha256(readFileSync(resolve(local, 'contracts', path)))])),
    before: { rows: ['Anti-ARTEX v1.0', 'MCP Security Evidence v1'], columns: ['Anti-ARTEX v1.0', 'MCP Security Evidence v1'], schema_acceptance: [[true, false], [false, true]] },
    after: { golden_events: goldens.length, regenerated_golden_events: generated.length, worker_events: { anti_artex: antiEvents.length, mcp_security_evidence: report.events.length }, both_schemas_and_verifiers_pass: true, tampering_and_legacy_rejected: true },
    raw_json_verification: Object.fromEntries(rawVerifiers.map(({ name, accepted, rejected }) => [name, { accepted, rejected }])),
    raw_json_unavailable: Object.keys(byName).filter(name => !rawVerifiers.some(v => v.name === name)),
    outbound_requests: outbound, live_deployment_tested: false
  }, null, 2));
} finally { db.db.close(); globalThis.fetch = oldFetch; }
