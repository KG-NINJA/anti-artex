import test from 'node:test';
import assert from 'node:assert/strict';
import {evaluate,render} from '../scripts/prompt-triage-benchmark.mjs';
test('offline assessment reproduces all labeled cases, exposing errors without claiming real-world accuracy',()=>{
 const report=evaluate();
 assert.equal(report.n,16);
 assert.equal(report.results.length,16);
 assert.equal(report.results.filter(x=>x.label==='suspicious').length,8);
 assert.equal(report.results.filter(x=>x.label==='benign').length,8);
 assert.deepEqual(report.confusion_matrix,{tp:7,fp:3,fn:1,tn:5});
 assert.equal(report.precision,7/10);
 assert.equal(report.recall,7/8);
 assert.equal(report.false_positive_rate,3/8);
 assert.deepEqual(evaluate(),report);
 assert.ok(render(report).includes('manual analyst review'));
 assert.doesNotMatch(JSON.stringify(report.results),/synthetic-only\) curl/);
});
