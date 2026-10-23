import { createReadStream, readFileSync } from 'node:fs';

const anti = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).name === 'anti-artex';
const { MAX_EVIDENCE_BYTES, verifyEvidenceJson } = await import(anti ? '../dist/src/evidence-json.js' : '../dist/evidence-json.js');

async function run() {
  const args = process.argv.slice(2);
  if (args.length !== 1) return { result: { valid: false, code: 'usage_error' }, exit: 2 };
  const input = args[0] === '-' ? process.stdin : createReadStream(args[0]);
  const chunks = []; let size = 0;
  try {
    for await (const chunk of input) {
      size += chunk.byteLength;
      if (size > MAX_EVIDENCE_BYTES) {
        input.destroy();
        return { result: { valid: false, code: 'input_too_large' }, exit: 1 };
      }
      chunks.push(chunk);
    }
  } catch { return { result: { valid: false, code: 'read_error' }, exit: 2 }; }
  const result = await verifyEvidenceJson(Buffer.concat(chunks, size));
  return { result, exit: result.valid ? 0 : 1 };
}
const { result, exit } = await run();
process.stdout.write(JSON.stringify(result) + '\n');
process.exitCode = exit;
