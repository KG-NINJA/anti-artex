import test from 'node:test';
import assert from 'node:assert/strict';
import { runLab, formatMarkdown } from '../scripts/validation-lab.mjs';

test('isolated MCP lab records evidence, rejection, and synthetic detection metrics', async () => {
  const report = await runLab();
  assert.equal(report.scope.includes('no outbound requests'), true);
  assert.deepEqual(report.metrics, { tp: 3, fn: 0, fp: 1, tn: 2, precision: 0.75, recall: 1 });
  assert.equal(report.authentication_denied, true);
  assert.equal(report.stalled_body_rejected, true);
  assert.equal(report.protocol_metadata_not_scanned, true);
  assert.equal(report.results.length, 6);
  const markdown = formatMarkdown(report);
  assert.match(markdown, /Quoted malicious phrases/);
  assert.doesNotMatch(markdown, /invalid-synthetic-credential/);
});
