import { EVIDENCE_VERSION, sealEvidence, type HoneypotEvidence } from './evidence-contract.js';
// Preserve the bare digest helper used by authentication; the envelope hash is prefixed.
export { canonical, digest as hash, verifyEvidence } from './evidence-contract.js';
export type Evidence = HoneypotEvidence;
export type Finding = Evidence['finding_type'];
export function indicators(text: string): string[] {
  const rules: [string, RegExp][] = [
    ['instruction_override', /ignore\s+(all\s+)?(previous|prior|system)\s+instructions/i],
    ['secret_exfiltration_request', /\b(reveal|print|send|exfiltrate)\b.{0,60}\b(secret|token|password|credential|api.?key)s?\b/i],
    ['role_spoofing', /<\|(?:system|developer)\|>|\[SYSTEM\]/i],
    ['shell_like_payload', /\$\(|\b(?:curl|wget)\s+https?:|\brm\s+-rf\b/i]
  ];
  return rules.filter(([, re]) => re.test(text)).map(([name]) => name).sort();
}
// Treat protocol fields, tool names and client metadata as data, not prompts.
// The heuristic operates only on the simulated tool's free-text query.
export function indicatorsForRpc(rpc: unknown): string[] {
  if (rpc === null || typeof rpc !== 'object' || Array.isArray(rpc)) return [];
  const message = rpc as Record<string, unknown>;
  if (message.method !== 'tools/call') return [];
  const params = message.params;
  if (params === null || typeof params !== 'object' || Array.isArray(params)) return [];
  const argumentsValue = (params as Record<string, unknown>).arguments;
  if (argumentsValue === null || typeof argumentsValue !== 'object' || Array.isArray(argumentsValue)) return [];
  const query = (argumentsValue as Record<string, unknown>).query;
  return typeof query === 'string' ? indicators(query) : [];
}
// Optional previews are always redacted BEFORE truncation; default is no preview.
export function redact(text: string, limit: number): string {
  const redacted = text.replace(/https?:\/\/[^\s"<>]+/gi, '[URL]')
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[EMAIL]')
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[IP]')
    .replace(/(?:bearer\s+)[^\s",}]+/gi, 'Bearer [REDACTED]')
    .replace(/((?:["']?(?:api[_-]?key|token|secret|password|authorization)["']?)\s*[:=]\s*)(?:"[^"\n]*"|'[^'\n]*'|[^\s,}]+)/gi, '$1[REDACTED]')
    .replace(/\b[A-Za-z0-9_+\/-]{24,}={0,2}\b/g, '[OPAQUE]')
    .replace(/[\u0000-\u001f\u007f]/g, ' ');
  // Do not split a supplementary Unicode character at the preview boundary.
  return [...redacted].slice(0, limit).join('');
}
export async function makeEvidence(finding: Finding, flags: string[], at: string, assessment: string, preview?: string): Promise<Evidence> {
  const evidence = { indicators: [...new Set(flags)].sort(), ...(preview ? { preview } : {}) };
  const base = {
    schema_version: EVIDENCE_VERSION, observed_at: at, source_type: 'mcp_honeypot' as const,
    assessment_id: assessment, finding_type: finding,
    severity: finding === 'possible_prompt_injection' ? 'medium' as const : 'low' as const,
    evidence, confidence: { scale: 'heuristic_score' as const, value: finding === 'possible_prompt_injection' ? 0.65 : 0.9 },
    limitations: ['Synthetic tool surface; no payload execution.', 'Heuristic classification can be wrong; client identity and AI-agent attribution are unknown.'],
    remediation: 'Review minimized evidence in the protected interface; do not execute submitted content.'
  };
  return sealEvidence(base);
}
