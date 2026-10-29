import assert from 'node:assert/strict';
import { runLab } from './validation-lab.mjs';
import { evaluate } from './prompt-triage-benchmark.mjs';
import { provenance, writeBundle } from './portfolio-bundle.mjs';
assert.equal(process.argv.length, 2, 'This command accepts no target, URL or credential arguments');
const worker = await runLab(), benchmark = evaluate();
const report = {
  title: 'Anti-ARTEX — Practitioner Portfolio v1', scope: 'synthetic-local-only',
  generated_at: new Date().toISOString(), source: provenance(),
  rows: [{ id: 'Actual Worker/SQLite synthetic scenarios', status: `${worker.results.length} cases; bounded reads and authorization checked` },
    { id: 'Prompt triage benchmark', status: `${benchmark.n} labeled examples; errors disclosed, not a security pass score` },
    { id: 'False positives', status: String(benchmark.confusion_matrix.fp) },
    { id: 'False negatives', status: String(benchmark.confusion_matrix.fn) }],
  worker, benchmark, limitations: [...benchmark.limitations,
    'The benchmark is a curated regression set, not a blinded or independently reviewed evaluation.',
    'SHA-256 verifies stored bytes, not author identity or source authenticity.',
    'No paid API usage, live attack, customer diagnosis or deployment is claimed.']
};
console.log(JSON.stringify({ cases: benchmark.n, matrix: benchmark.confusion_matrix, bundle: writeBundle(report) }, null, 2));
