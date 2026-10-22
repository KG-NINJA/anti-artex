import { hash, indicators, makeEvidence, redact, type Finding } from './evidence.js';

export interface Statement {
  bind(...args: unknown[]): Statement;
  run(): Promise<unknown>;
  first<T = Record<string, unknown>>(): Promise<T | null>;
  all<T = Record<string, unknown>>(): Promise<{ results: T[] }>;
}
export interface Database { prepare(sql: string): Statement; batch(statements: Statement[]): Promise<unknown>; }
export interface Env {
  DB: Database;
  INVESTIGATION_TOKEN?: string;
  MCP_BEARER_TOKEN?: string;
  RETENTION_HOURS?: string; MAX_EVENTS?: string; MAX_SESSIONS?: string;
  MAX_BODY_BYTES?: string; PREVIEW_CHARS?: string; DAILY_REQUEST_LIMIT?: string; SESSION_TTL_SECONDS?: string;
}
function number(value: string | undefined, fallback: number, min: number, max: number): number {
  if (value === undefined) return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < min || n > max) throw new Error('Invalid configuration');
  return n;
}
function config(env: Env) {
  return {
    retention: number(env.RETENTION_HOURS, 24, 1, 168),
    events: number(env.MAX_EVENTS, 1000, 1, 10000),
    sessions: number(env.MAX_SESSIONS, 100, 1, 1000),
    body: number(env.MAX_BODY_BYTES, 8192, 256, 32768),
    preview: number(env.PREVIEW_CHARS, 0, 0, 256),
    daily: number(env.DAILY_REQUEST_LIMIT, 1000, 1, 10000),
    ttl: number(env.SESSION_TTL_SECONDS, 900, 60, 3600)
  };
}
function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return Response.json(body, { status, headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...headers } });
}
async function authorized(request: Request, token?: string): Promise<boolean> {
  if (!token || token.length < 32) return false;
  const received = request.headers.get('authorization') ?? '';
  if (received.length > 512) return false;
  const [a, b] = await Promise.all([hash(received), hash('Bearer ' + token)]);
  let different = 0;
  for (let i = 0; i < a.length; i++) different |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return different === 0;
}
async function readBody(request: Request, max: number): Promise<string | null> {
  if (Number(request.headers.get('content-length')) > max) return null;
  if (!request.body) return '';
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) { await reader.cancel(); return null; }
    chunks.push(value);
  }
  const all = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { all.set(chunk, offset); offset += chunk.length; }
  return new TextDecoder('utf-8', { fatal: true }).decode(all);
}
function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
const tools = [{
  name: 'lookup_research_note',
  description: 'SIMULATION ONLY. Returns a fixed fictional research note. No network, filesystem, shell, or credentials.',
  inputSchema: { type: 'object', properties: { query: { type: 'string', maxLength: 512 } }, required: ['query'], additionalProperties: false }
}];
async function cleanup(env: Env, at = new Date().toISOString()): Promise<void> {
  config(env);
  await env.DB.batch([
    env.DB.prepare('DELETE FROM events WHERE expires_at <= ?').bind(at),
    env.DB.prepare('DELETE FROM sessions WHERE expires_at <= ?').bind(at),
    env.DB.prepare('DELETE FROM daily_budget WHERE day < ?').bind(at.slice(0, 10))
  ]);
}
const worker = {
  async scheduled(_controller: unknown, env: Env): Promise<void> { await cleanup(env); },
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === '/health' && request.method === 'GET') return json({ status: 'ok', mode: 'isolated-simulation' });
    if (!['/mcp', '/investigation/events', '/investigation/report'].includes(url.pathname)) return json({ error: 'Not found' }, 404);
    try {
      const c = config(env);
      if (url.pathname.startsWith('/investigation/')) {
        if (!(await authorized(request, env.INVESTIGATION_TOKEN))) return json({ error: 'Unauthorized' }, 401);
        if (request.method !== 'GET') return json({ error: 'Read only' }, 405, { Allow: 'GET' });
        const at = new Date().toISOString();
        if (url.pathname.endsWith('/report')) {
          const rows = await env.DB.prepare('SELECT finding_type, COUNT(*) AS count FROM events WHERE expires_at > ? GROUP BY finding_type ORDER BY finding_type').bind(at).all();
          return json({ attribution: 'unknown client; no AI-agent attribution', counts: rows.results });
        }
        const limit = number(url.searchParams.get('limit') ?? undefined, 20, 1, 100);
        const rows = await env.DB.prepare('SELECT envelope FROM events WHERE expires_at > ? ORDER BY observed_at DESC, event_id DESC LIMIT ?').bind(at, limit).all<{ envelope: string }>();
        // Retained pre-v2 envelopes keep their original version and hash. No implicit migration.
        return json({ events: rows.results.map(r => JSON.parse(r.envelope) as unknown), limit });
      }
      // Browsers are not an intended client. Deny every Origin, preventing DNS-rebinding/browser access.
      if (request.headers.has('origin')) return json({ error: 'Origin forbidden' }, 403);
      if (!['POST', 'GET', 'DELETE'].includes(request.method)) return json({ error: 'Method not allowed' }, 405, { Allow: 'POST, GET, DELETE' });
      if (!env.MCP_BEARER_TOKEN || env.MCP_BEARER_TOKEN.length < 32) return json({ error: 'MCP authentication not configured' }, 503);
      const at = new Date().toISOString();
      const day = at.slice(0, 10);
      // An atomic quota claim prevents concurrent requests overshooting the daily work cap.
      const claim = await env.DB.prepare('INSERT INTO daily_budget(day, requests) VALUES (?, 1) ON CONFLICT(day) DO UPDATE SET requests = requests + 1 WHERE requests < ? RETURNING requests').bind(day, c.daily).first();
      if (!claim) return json({ error: 'Daily research quota exhausted' }, 429);
      await env.DB.batch([
        env.DB.prepare('DELETE FROM events WHERE expires_at <= ?').bind(at),
        env.DB.prepare('DELETE FROM sessions WHERE expires_at <= ?').bind(at),
        env.DB.prepare('DELETE FROM daily_budget WHERE day < ?').bind(day)
      ]);
      const assessment = crypto.randomUUID();
      const record = async (finding: Finding, flags: string[], text = '') => {
        const e = await makeEvidence(finding, flags, at, assessment, c.preview ? redact(text, c.preview) : undefined);
        await env.DB.prepare('INSERT OR IGNORE INTO events(event_id, observed_at, expires_at, finding_type, envelope) SELECT ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM events) < ?')
          .bind(e.event_id, at, new Date(Date.parse(at) + c.retention * 3600000).toISOString(), finding, JSON.stringify(e), c.events).run();
      };
      if (!(await authorized(request, env.MCP_BEARER_TOKEN))) {
        await record('invalid_authentication', ['missing_or_invalid_bearer']);
        return json({ error: 'Unauthorized' }, 401);
      }
      if (request.method === 'GET') return json({ error: 'SSE stream not offered; use POST' }, 405, { Allow: 'POST, DELETE' });
      const sessionId = request.headers.get('mcp-session-id');
      if (sessionId && !/^[0-9a-f-]{36}$/.test(sessionId)) return json({ error: 'Session not found' }, 404);
      const session = sessionId ? await env.DB.prepare('SELECT initialized FROM sessions WHERE id = ? AND expires_at > ?').bind(sessionId, at).first<{ initialized: number }>() : null;
      if (sessionId && !session) return json({ error: 'Session not found' }, 404);
      if (request.method === 'DELETE') {
        if (!sessionId) return json({ error: 'Session required' }, 400);
        await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(sessionId).run();
        return new Response(null, { status: 204 });
      }
      const accept = request.headers.get('accept') ?? '';
      if (!accept.includes('application/json') || !accept.includes('text/event-stream')) return json({ error: 'Accept must include application/json and text/event-stream' }, 406);
      if (!(request.headers.get('content-type') ?? '').split(';')[0]?.trim().toLowerCase().match(/^application\/json$/)) return json({ error: 'JSON required' }, 415);
      let text: string | null;
      try { text = await readBody(request, c.body); } catch { await record('malformed_request', ['invalid_body_encoding']); return json({ error: 'Invalid body' }, 400); }
      if (text === null) { await record('malformed_request', ['body_limit_exceeded']); return json({ error: 'Body too large' }, 413); }
      let rpc: unknown;
      try { rpc = JSON.parse(text); } catch { await record('malformed_request', ['invalid_json']); return json({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }, 400); }
      if (!object(rpc) || rpc.jsonrpc !== '2.0' || typeof rpc.method !== 'string' || (rpc.id !== undefined && !(typeof rpc.id === 'string' || (typeof rpc.id === 'number' && Number.isFinite(rpc.id)))) || (rpc.params !== undefined && !object(rpc.params))) {
        await record('malformed_request', ['invalid_json_rpc']);
        return json({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } }, 400);
      }
      const flags = indicators(text);
      if (flags.length) await record('possible_prompt_injection', flags, text);
      const notification = rpc.id === undefined;
      const result = (value: unknown, headers: Record<string, string> = {}) => notification ? new Response(null, { status: 202 }) : json({ jsonrpc: '2.0', id: rpc.id, result: value }, 200, headers);
      const error = (code: number, message: string) => notification ? new Response(null, { status: 202 }) : json({ jsonrpc: '2.0', id: rpc.id, error: { code, message } });
      const params = object(rpc.params) ? rpc.params : {};
      if (rpc.method === 'initialize') {
        if (notification) return new Response(null, { status: 202 });
        if (session) { await record('anomalous_sequence', ['repeated_initialize']); return error(-32600, 'Already initialized'); }
        if (params.protocolVersion !== '2025-03-26' && params.protocolVersion !== '2025-06-18') return error(-32602, 'Supported protocols: 2025-03-26, 2025-06-18');
        const id = crypto.randomUUID();
        const inserted = await env.DB.prepare('INSERT INTO sessions(id, initialized, expires_at) SELECT ?, 0, ? WHERE (SELECT COUNT(*) FROM sessions) < ? RETURNING id').bind(id, new Date(Date.parse(at) + c.ttl * 1000).toISOString(), c.sessions).first();
        if (!inserted) return json({ error: 'Session capacity reached' }, 429);
        return result({ protocolVersion: params.protocolVersion, capabilities: { tools: { listChanged: false } }, serverInfo: { name: 'anti-artex-simulation', version: '0.3.0' }, instructions: 'Research simulation only. All content is fictional.' }, { 'Mcp-Session-Id': id });
      }
      if (!session) { await record('anomalous_sequence', ['request_before_initialize']); return error(-32000, 'Initialize a session first'); }
      if (!['2025-03-26', '2025-06-18'].includes(request.headers.get('mcp-protocol-version') ?? '')) return json({ error: 'Supported MCP-Protocol-Version required' }, 400);
      if (rpc.method === 'notifications/initialized' && notification) {
        await env.DB.prepare('UPDATE sessions SET initialized = 1 WHERE id = ?').bind(sessionId).run();
        return new Response(null, { status: 202 });
      }
      if (!session.initialized) { await record('anomalous_sequence', ['request_before_initialized_notification']); return error(-32000, 'Send notifications/initialized first'); }
      if (rpc.method === 'ping') return result({});
      if (rpc.method === 'tools/list') return result({ tools });
      if (rpc.method === 'tools/call') {
        if (params.name !== 'lookup_research_note') return error(-32602, 'Unknown simulated tool');
        const args = params.arguments;
        if (!object(args) || Object.keys(args).some(k => k !== 'query') || typeof args.query !== 'string' || args.query.length > 512) return error(-32602, 'Expected query string of at most 512 characters');
        return result({ content: [{ type: 'text', text: 'SIMULATED research note: specimen ALPHA is fictional. No action was performed.' }], isError: false });
      }
      return error(-32601, 'Method not found');
    } catch {
      // Never expose SQL, payloads, headers, tokens, or internal exceptions.
      return json({ error: 'Research service unavailable or invalid configuration' }, 503);
    }
  }
};
export default worker;
