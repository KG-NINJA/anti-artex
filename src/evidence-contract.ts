// Evidence contract 2.0.0. Vendored locally; no partner runtime/package dependency.
export const EVIDENCE_VERSION = '2.0.0' as const;
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Confidence = { scale: 'heuristic_score'; value: number } | { scale: 'ordinal'; value: 'low' | 'medium' | 'high' };
export interface Envelope {
  schema_version: typeof EVIDENCE_VERSION;
  event_id: string; observed_at: string; assessment_id: string;
  finding_type: string; severity: Severity; confidence: Confidence;
  limitations: string[]; remediation: string; content_hash: string;
}
export type HoneypotEvidence = Envelope & {
  source_type: 'mcp_honeypot';
  finding_type: 'possible_prompt_injection' | 'invalid_authentication' | 'anomalous_sequence' | 'malformed_request';
  severity: 'low' | 'medium';
  confidence: { scale: 'heuristic_score'; value: number };
  evidence: { indicators: string[]; preview?: string };
};
export type MetadataEvidence = Envelope & {
  source_type: 'submitted_mcp_metadata';
  confidence: { scale: 'ordinal'; value: 'low' | 'medium' | 'high' };
  evidence: { path: string; observation: string };
};
export type SharedEvidence = HoneypotEvidence | MetadataEvidence;
export type EvidencePayload = Omit<HoneypotEvidence, 'event_id' | 'content_hash'> | Omit<MetadataEvidence, 'event_id' | 'content_hash'>;

// Bounded JSON encoding, NOT a general-purpose RFC 8785 implementation.
// Key ordering is ECMAScript UTF-16 order; strings are not Unicode-normalized.
export function canonical(value: unknown, depth = 0): string {
  if (depth > 20) throw new TypeError('JSON nesting limit');
  if (value === null) return 'null';
  if (typeof value === 'string') {
    for (const c of value) {
      const n = c.charCodeAt(0);
      if (c.length === 1 && n >= 0xd800 && n <= 0xdfff) throw new TypeError('Unpaired surrogate');
    }
    return JSON.stringify(value);
  }
  if (typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value))) return JSON.stringify(value);
  if (Array.isArray(value)) {
    if (Object.keys(value).length !== value.length) throw new TypeError('Non-JSON array');
    return '[' + Array.from(value, v => canonical(v, depth + 1)).join(',') + ']';
  }
  if (value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    const o = value as Record<string, unknown>;
    if (Object.getOwnPropertySymbols(o).length) throw new TypeError('Non-JSON key');
    return '{' + Object.keys(o).sort().map(k => canonical(k, depth + 1) + ':' + canonical(o[k], depth + 1)).join(',') + '}';
  }
  throw new TypeError('Non-JSON value');
}
export async function digest(value: unknown): Promise<string> {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical(value)));
  return Array.from(new Uint8Array(bytes), n => n.toString(16).padStart(2, '0')).join('');
}
export async function sealEvidence<T extends EvidencePayload>(payload: T): Promise<T & { event_id: string; content_hash: string }> {
  // Reject unknown fields, including caller-supplied IDs/hashes, before hashing.
  if (!validShape({ ...payload, event_id: '0'.repeat(64), content_hash: 'sha256:' + '0'.repeat(64) }) ||
      'event_id' in payload || 'content_hash' in payload) throw new TypeError('Invalid evidence payload');
  const event_id = await digest(payload);
  return { ...payload, event_id, content_hash: 'sha256:' + await digest({ ...payload, event_id }) };
}
function object(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
}
function keys(v: Record<string, unknown>, required: string[], optional: string[] = []): boolean {
  return required.every(k => Object.hasOwn(v, k)) && Object.keys(v).every(k => required.includes(k) || optional.includes(k));
}
function str(v: unknown, min: number, max: number): v is string {
  return typeof v === 'string' && v.length <= max * 2 && [...v].length >= min && [...v].length <= max;
}
function strings(v: unknown, min: number, max: number, width: number): v is string[] {
  return Array.isArray(v) && v.length >= min && v.length <= max && v.every(s => str(s, 1, width));
}
function validShape(v: unknown): v is SharedEvidence {
  if (!object(v) || !keys(v, ['schema_version', 'event_id', 'observed_at', 'source_type', 'assessment_id', 'finding_type', 'severity', 'evidence', 'confidence', 'limitations', 'remediation', 'content_hash'])) return false;
  if (v.schema_version !== EVIDENCE_VERSION || typeof v.event_id !== 'string' || !/^[0-9a-f]{64}$/.test(v.event_id) ||
      typeof v.content_hash !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(v.content_hash)) return false;
  if (typeof v.observed_at !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(v.observed_at) ||
      !Number.isFinite(Date.parse(v.observed_at)) || new Date(v.observed_at).toISOString() !== v.observed_at) return false;
  if (!str(v.assessment_id, 1, 128) || !str(v.finding_type, 1, 64) || !/^[a-z][a-z0-9_]*$/.test(v.finding_type) ||
      typeof v.severity !== 'string' || !['info', 'low', 'medium', 'high', 'critical'].includes(v.severity) ||
      !strings(v.limitations, 1, 16, 512) || !str(v.remediation, 1, 1024) || !object(v.evidence) || !object(v.confidence) || !keys(v.confidence, ['scale', 'value'])) return false;
  if (v.source_type === 'mcp_honeypot') {
    return ['possible_prompt_injection', 'invalid_authentication', 'anomalous_sequence', 'malformed_request'].includes(v.finding_type) &&
      ['low', 'medium'].includes(v.severity) && v.confidence.scale === 'heuristic_score' &&
      typeof v.confidence.value === 'number' && Number.isFinite(v.confidence.value) && v.confidence.value >= 0 && v.confidence.value <= 1 &&
      keys(v.evidence, ['indicators'], ['preview']) && strings(v.evidence.indicators, 1, 16, 64) &&
      new Set(v.evidence.indicators).size === v.evidence.indicators.length &&
      (!Object.hasOwn(v.evidence, 'preview') || str(v.evidence.preview, 0, 256));
  }
  if (v.source_type === 'submitted_mcp_metadata') {
    return v.confidence.scale === 'ordinal' && typeof v.confidence.value === 'string' && ['low', 'medium', 'high'].includes(v.confidence.value) &&
      keys(v.evidence, ['path', 'observation']) && str(v.evidence.path, 0, 512) && /^(?:\/(?:[^~/]|~[01])*)*$/.test(v.evidence.path) &&
      str(v.evidence.observation, 1, 1024);
  }
  return false;
}
// A pure verifier: no importing, storage, callbacks, execution or network access.
// Callers must still establish authorization/provenance; hashes are not signatures.
export async function verifyEvidence(value: unknown): Promise<boolean> {
  try {
    if (!validShape(value)) return false;
    const { content_hash, event_id, ...payload } = value;
    return event_id === await digest(payload) && content_hash === 'sha256:' + await digest({ ...payload, event_id });
  } catch { return false; }
}
