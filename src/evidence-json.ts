import { verifyEvidenceDetailed, type VerificationResult } from './evidence-contract.js';

export const MAX_EVIDENCE_BYTES = 64 * 1024;
export const MAX_JSON_DEPTH = 20;
type JsonError = 'input_too_large' | 'invalid_utf8' | 'invalid_json' | 'nesting_limit' | 'duplicate_key';
export type JsonVerificationResult = VerificationResult | { valid: false; code: JsonError };

// Scan containers/keys before JSON.parse discards duplicate members. JSON.parse
// still owns syntax validation; this scanner never interprets or executes values.
function checkStructure(text: string): JsonError | undefined {
  const containers: (Set<string> | null)[] = [];
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      const start = i;
      for (i++; i < text.length; i++) {
        if (text[i] === '\\') i++;
        else if (text[i] === '"') break;
      }
      if (i >= text.length) return 'invalid_json';
      let next = i + 1;
      while (next < text.length && /[ \t\r\n]/.test(text[next]!)) next++;
      if (text[next] === ':') {
        const keys = containers.at(-1);
        if (!keys) return 'invalid_json';
        let name: string;
        try { name = JSON.parse(text.slice(start, i + 1)) as string; }
        catch { return 'invalid_json'; }
        if (keys.has(name)) return 'duplicate_key';
        keys.add(name);
      }
    } else if (c === '{' || c === '[') {
      containers.push(c === '{' ? new Set() : null);
      if (containers.length > MAX_JSON_DEPTH) return 'nesting_limit';
    } else if (c === '}' || c === ']') {
      if (!containers.length || (c === '}' ? containers.at(-1) === null : containers.at(-1) !== null)) return 'invalid_json';
      containers.pop();
    }
  }
  return containers.length ? 'invalid_json' : undefined;
}

// Pure, bounded verification of one raw UTF-8 JSON event. Results never echo
// input values, duplicate field names, file paths, or parser exception messages.
// Hash validity is not proof of origin/authorization. No import endpoint exists.
export async function verifyEvidenceJson(input: string | Uint8Array): Promise<JsonVerificationResult> {
  let text: string;
  if (typeof input === 'string') {
    if (input.length > MAX_EVIDENCE_BYTES || new TextEncoder().encode(input).byteLength > MAX_EVIDENCE_BYTES)
      return { valid: false, code: 'input_too_large' };
    text = input;
  } else if (input instanceof Uint8Array) {
    if (input.byteLength > MAX_EVIDENCE_BYTES) return { valid: false, code: 'input_too_large' };
    try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(input); }
    catch { return { valid: false, code: 'invalid_utf8' }; }
  } else return { valid: false, code: 'invalid_json' };
  const error = checkStructure(text);
  if (error) return { valid: false, code: error };
  let value: unknown;
  try { value = JSON.parse(text); }
  catch { return { valid: false, code: 'invalid_json' }; }
  return verifyEvidenceDetailed(value);
}
