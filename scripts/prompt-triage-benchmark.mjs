// Offline, deterministic practitioner benchmark. No LLM calls, real targets or external traffic.
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { indicatorsForRpc } from '../dist/src/evidence.js';

const source = new URL('../fixtures/prompt-triage-benchmark.json', import.meta.url);
function ratio(n,d) { return d ? n/d : null; }
function percentage(n) { return n === null ? 'N/A' : (100*n).toFixed(1)+'%'; }
export function evaluate() {
  const raw = readFileSync(source);
  const benchmark = JSON.parse(raw);
  if(benchmark.version !== '1.0' || !Array.isArray(benchmark.cases)) throw Error('Unsupported benchmark');
  const ids = new Set();
  const results = benchmark.cases.map(c => {
    if(ids.has(c.id) || !['benign','suspicious'].includes(c.label)) throw Error('Bad fixture');
    ids.add(c.id);
    const message = {jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'lookup_research_note',arguments:{query:c.query}}};
    const flags = indicatorsForRpc(message);
    const detected = flags.length > 0;
    return {id:c.id,label:c.label,context:c.context,detected,indicators:flags,
      outcome:c.label === 'suspicious' ? (detected?'TP':'FN'):(detected?'FP':'TN')};
  });
  const count=k=>results.filter(r=>r.outcome===k).length;
  const matrix={tp:count('TP'),fp:count('FP'),fn:count('FN'),tn:count('TN')};
  const summary={schema_version:'security-evaluation-offline/v1',dataset:'synthetic-curated-16',
    fixture_sha256:createHash('sha256').update(raw).digest('hex'),
    evaluator:'anti-artex indicatorsForRpc only; no machine learning',
    n:results.length,confusion_matrix:matrix,
    precision:ratio(matrix.tp,matrix.tp+matrix.fp),recall:ratio(matrix.tp,matrix.tp+matrix.fn),
    false_positive_rate:ratio(matrix.fp,matrix.fp+matrix.tn),
    results,limitations:[
      'Synthetic hand-labelled cases; no claims about field effectiveness or adversarial robustness.',
      'Heuristic pattern matching is not a confirmed exploit or client attribution.',
      'Labels were not blinded; no human adjudication or second reviewer.',
      'Prompt-injection content is treated as data; no commands or LLM/tool actions are executed.'
    ]};
  if(summary.n!==16 || matrix.tp+matrix.fp+matrix.fn+matrix.tn!==16) throw Error('Invalid counts');
  return summary;
}
export function render(summary) {
  const m=summary.confusion_matrix;
  const lines=['# Security triage evaluation — offline synthetic benchmark','',
    '**Not a penetration test, security certification, or real-world performance measurement.**','',
    'Dataset: '+summary.dataset+'; SHA-256: '+summary.fixture_sha256,'',
    '| TP | FP | FN | TN | Precision | Recall | False positive rate |',
    '|---:|---:|---:|---:|---:|---:|---:|',
    `| ${m.tp} | ${m.fp} | ${m.fn} | ${m.tn} | ${percentage(summary.precision)} | ${percentage(summary.recall)} | ${percentage(summary.false_positive_rate)} |`,'',
    '| Case | Expected label | Outcome | Detection flags |',
    '|---|---|---|---|',
    ...summary.results.map(x=>`| ${x.id} | ${x.label} | ${x.outcome} | ${x.indicators.join(', ')||'none'} |`),
    '', '## Triage for reviewer', '',
    ...summary.results.filter(x=>['FP','FN'].includes(x.outcome)).map(x=>`- ${x.id} (${x.outcome}, ${x.context}): manual analyst review recommended`),
    '', '## Limitations','',...summary.limitations.map(x=>'- '+x),''];
  return lines.join('\n');
}
if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const summary=evaluate();const dir=resolve('artifacts/triage');
  mkdirSync(dir,{recursive:true});
  writeFileSync(resolve(dir,'report.json'),JSON.stringify(summary,null,2)+'\n');
  writeFileSync(resolve(dir,'report.md'),render(summary));
  console.log(render(summary));
}
