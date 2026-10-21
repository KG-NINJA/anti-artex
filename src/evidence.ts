export type Finding = 'possible_prompt_injection' | 'invalid_authentication' | 'anomalous_sequence' | 'malformed_request';
export interface Evidence {
  schema_version: '1.0';
  event_id: string;
  observed_at: string;
  source_type: 'mcp_honeypot';
  assessment_id: string;
  finding_type: Finding;
  severity: 'low' | 'medium';
  evidence: { indicators: string[]; preview?: string };
  confidence: number;
  limitations: string[];
  remediation: string;
  content_hash: string;
}
export function canonical(value: unknown): string {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value !== null && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    return '{' + Object.keys(obj).sort().map(k => JSON.stringify(k) + ':' + canonical(obj[k])).join(',') + '}';
  }
  return JSON.stringify(value);
}
export async function hash(value: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(canonical(value));
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
}
export function indicators(text: string): string[] {
  const rules: [string, RegExp][] = [
    ['instruction_override', /ignore\s+(all\s+)?(previous|prior|system)\s+instructions/i],
    ['secret_exfiltration_request', /\b(reveal|print|send|exfiltrate)\b.{0,60}\b(secret|token|password|credential|api.?key)s?\b/i],
    ['role_spoofing', /<\|(?:system|developer)\|>|\[SYSTEM\]/i],
    ['shell_like_payload', /\$\(|\b(?:curl|wget)\s+https?:|\brm\s+-rf\b/i]
  ];
  return rules.filter(([, re]) => re.test(text)).map(([name]) => name).sort();
}
// Optional previews are always redacted BEFORE truncation; default is no preview.
export function redact(text: string, limit: number): string {
  return text.replace(/https?:\/\/[^\s"<>]+/gi, '[URL]')
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[EMAIL]')
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[IP]')
    .replace(/(?:bearer\s+)[^\s",}]+/gi, 'Bearer [REDACTED]')
    .replace(/((?:["']?(?:api[_-]?key|token|secret|password|authorization)["']?)\s*[:=]\s*)(?:"[^"\n]*"|'[^'\n]*'|[^\s,}]+)/gi, '$1[REDACTED]')
    .replace(/\b[A-Za-z0-9_+\/-]{24,}={0,2}\b/g, '[OPAQUE]')
    .replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, limit);
}
export async function makeEvidence(finding: Finding, flags: string[], at: string, assessment: string, preview?: string): Promise<Evidence> {
  const evidence = { indicators: [...new Set(flags)].sort(), ...(preview ? { preview } : {}) };
  const base = {
    schema_version: '1.0' as const, observed_at: at, source_type: 'mcp_honeypot' as const,
    assessment_id: assessment, finding_type: finding,
    severity: finding === 'possible_prompt_injection' ? 'medium' as const : 'low' as const,
    evidence, confidence: finding === 'possible_prompt_injection' ? 0.65 : 0.9,
    limitations: ['Synthetic tool surface; no payload execution.', 'Heuristic classification can be wrong; client identity and AI-agent attribution are unknown.'],
    remediation: 'Review minimized evidence in the protected interface; do not execute submitted content.'
  };
  const event_id = await hash(base);
  const envelope = { ...base, event_id };
  return { ...envelope, content_hash: await hash(envelope) };
}
