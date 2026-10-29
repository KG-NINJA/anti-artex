import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import worker from '../dist/src/index.js';

class LocalDatabase {
  constructor() {
    this.db = new DatabaseSync(':memory:');
    this.db.exec(readFileSync(new URL('../migrations/0001_initial.sql', import.meta.url), 'utf8'));
  }
  prepare(sql) {
    const stmt = this.db.prepare(sql);
    let args = [];
    const wrapped = {
      bind(...values) { args = values; return wrapped; },
      async run() { return stmt.run(...args); },
      async first() { return stmt.get(...args) ?? null; },
      async all() { return { results: stmt.all(...args) }; }
    };
    return wrapped;
  }
  async batch(statements) {
    this.db.exec('BEGIN');
    try {
      const results = [];
      for (const statement of statements) results.push(await statement.run());
      this.db.exec('COMMIT');
      return results;
    } catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
}
const token = 'synthetic-deadline-test-only-00000000000000';
const payload = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } });

test('deadline cancels a complete JSON prefix without accepting it or creating a session', { timeout: 10000 }, async () => {
  const DB = new LocalDatabase();
  let cancelled = false;
  try {
    const request = new Request('https://deadline.invalid/mcp', {
      method: 'POST', duplex: 'half',
      headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
      body: new ReadableStream({
        start(controller) { controller.enqueue(new TextEncoder().encode(payload)); },
        cancel() { cancelled = true; }
      })
    });
    const response = await worker.fetch(request, { DB, MCP_BEARER_TOKEN: token });
    assert.equal(response.status, 400, 'complete JSON must not bypass an unfinished stream deadline');
    assert.equal(cancelled, true);
    assert.equal(DB.db.prepare('SELECT COUNT(*) AS n FROM sessions').get().n, 0);
    const events = DB.db.prepare('SELECT envelope FROM events').all().map(row => JSON.parse(row.envelope));
    assert.ok(events.some(event => event.finding_type === 'malformed_request' && event.evidence.indicators.includes('body_read_deadline_exceeded')));
  } finally { DB.db.close(); }
});

test('a completed valid stream remains accepted', async () => {
  const DB = new LocalDatabase();
  try {
    const response = await worker.fetch(new Request('https://deadline.invalid/mcp', {
      method: 'POST', headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' }, body: payload
    }), { DB, MCP_BEARER_TOKEN: token });
    assert.equal(response.status, 200);
    assert.ok(response.headers.get('mcp-session-id'));
  } finally { DB.db.close(); }
});
