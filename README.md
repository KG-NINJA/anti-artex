# Anti-ARTEX

Isolated, defensive MCP honeypot **research prototype** for issue #1. The only tool returns a fixed fictional note. Submitted text is data: there is no eval, shell, filesystem access, outbound fetch, model call, real secret lookup, payment, scan, or production integration in the Worker.

## Local development

Requires Node >=22.13 and npm. Use this existing isolated checkout; do not create a worktree. No Cloudflare account, network service, or real credentials are needed for tests.

```sh
npm ci
npm run lint
npm test
npm run bundle
npx wrangler d1 migrations apply anti-artex-research --local
```

Create ignored `.dev.vars` with two **different synthetic local-only** bearer strings, each at least 32 characters:

```dotenv
MCP_BEARER_TOKEN=synthetic-local-mcp-only-0000000000000000
INVESTIGATION_TOKEN=synthetic-local-investigation-only-0000000000000000
```

```sh
WRANGLER_SEND_METRICS=false npx wrangler dev --local --ip 127.0.0.1 --port 8787 --test-scheduled
```

Validate locally with `curl --fail http://127.0.0.1:8787/health`. See [the smoke runner](test/local-smoke.mjs) for the complete synthetic MCP initialize → initialized notification → tools/call → protected evidence flow against that local process (`npm run smoke:local`). It uses only the documented synthetic local tokens above. Never run it against external hosts.

## Surface

- `GET /health`: explicit liveness, no database/secret disclosure. Does not claim D1 readiness.
- `POST /mcp`: Streamable HTTP JSON responses. Require `Accept: application/json, text/event-stream`, `Content-Type: application/json`, and the dedicated MCP bearer token. No SSE stream is offered (`GET` returns 405). JSON-RPC batching is rejected. Protocols `2025-03-26` and `2025-06-18` are supported; initialize negotiates one, returns `Mcp-Session-Id`, then clients send `notifications/initialized`. Subsequent requests require a supported `MCP-Protocol-Version` and the session ID. `DELETE /mcp` terminates a session. Sessions expire without sliding refresh. Notifications receive empty 202 responses, never JSON-RPC responses.
- Supported RPCs: `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`.
- `lookup_research_note({query})`: query must be <=512 characters, no additional fields. Every accepted query gets the same fictional text; no query is reflected in the response.
- `GET /investigation/events?limit=20`: protected evidence JSON (1–100 rows, newest first). No public raw logs and no unauthenticated access.
- `GET /investigation/report`: protected grouped counts and explicit unknown-client attribution. Both investigation routes are read-only and use the separate investigation token.
- Browser Origin headers are rejected on MCP; CORS is not enabled. Responses use `no-store` and `nosniff`.

## Configuration

| Name | Default / bounds | Purpose |
| --- | --- | --- |
| `DB` | required D1 binding | Dedicated research database, never shared with production or partner |
| `MCP_BEARER_TOKEN` | secret, >=32 characters | Restricted synthetic participant access; missing/short fails closed |
| `INVESTIGATION_TOKEN` | separate secret, >=32 characters | Read-only investigator access; missing/short fails closed |
| `RETENTION_HOURS` | 24 / 1–168 | Per-event expiry fixed when inserted |
| `MAX_EVENTS` | 1000 / 1–10000 | Atomic insert cap; new events drop when full |
| `MAX_SESSIONS` | 100 / 1–1000 | Atomic session cap; capacity exhaustion gives 429 |
| `MAX_BODY_BYTES` | 8192 / 256–32768 | Bounded stream read, oversize bodies rejected with 413 |
| `PREVIEW_CHARS` | 0 / 0–256 | Zero stores no input text. Optional redacted preview, truncated after redaction |
| `DAILY_REQUEST_LIMIT` | 1000 / 1–10000 | Shared UTC daily MCP work quota, including bad auth |
| `SESSION_TTL_SECONDS` | 900 / 60–3600 | Session expiry |

Invalid numeric configuration fails closed with 503. Bad requests never log headers, bearer values, IP addresses, user-agent strings, or client identity. Default evidence stores only static rule names. Optional redaction is heuristic, cannot guarantee removal of arbitrary personal data/secrets, and should stay disabled. This prototype does not use application console logging. Cloud provider access logs and backups require separate operator retention settings.

New evidence uses the shared **2.0.0** contract and deterministic canonical JSON SHA-256. A fixed observation tuple has stable IDs/hashes; independent requests have fresh assessment IDs and timestamps. `content_hash` has a `sha256:` prefix and detects changes but is **not a signature or proof of provenance**. Numeric confidence retains its existing value inside `{scale: "heuristic_score", value}`. The [common contract](contracts/README.md) and [JSON Schema](contracts/evidence-v2.schema.json) define both the honeypot and submitted-metadata profiles. No external sharing is automatic.

This is a breaking API change in service 0.2.0. [Legacy v1.0](docs/evidence-v1.md) and its schema/fixture are retained. Stored legacy evidence is returned unchanged until ordinary expiry; consumers select a validator by exact version. Never silently relabel or rehash old records. `verifyEvidence` validates either v2 source profile locally; it does not create an ingestion route or partner connection.

Expiry is enforced on every read. MCP traffic and an hourly scheduled handler physically remove expired events/sessions and old budget rows. Thus stored rows can remain until the next successful cleanup, normally up to an hour beyond expiry; provider outages/backups may extend physical retention. Changing retention only affects new events. Cleanup failures surface as 503 or failed scheduled executions, never success claims.

## Verify JSON and prevent compatibility drift

Service 0.3.0 adds a bounded, offline verifier while keeping evidence contract 2.0.0 unchanged. Run `npm run --silent verify:evidence -- fixtures/verify-example.json` (or pass an event file / `-` for stdin). It rejects duplicate keys, invalid UTF-8/JSON, oversized or deeply nested inputs, unsupported versions and integrity failures using fixed error codes, without echoing input data. No verification endpoint, import or automatic response action is enabled.

The separate **Evidence interoperability** GitHub Actions job tests each change against a pinned reviewed peer commit, then saves a JSON report identifying the actual revisions, compiled modules, contract hashes and results. Existing per-service CI and runtime independence remain intact. See the [verification guide](docs/verification-guide.md) for limits, API/CLI usage, exit codes, peer pins and artifact retention.

## Validation and limits

`npm test` runs real SQLite schema/queries through a minimal D1 adapter, synthetic fixtures from both producers, deterministic schema/hash validation, auth/limits/session/privacy checks, and legacy rejection/preservation. `npm run smoke:local` tests the actual local Worker + D1 runtime. Neither demonstrates deployed Cloudflare behavior. See [threat model](docs/threat-model.md) and [manual operations, rollback and budget](docs/operations.md). No deployment is authorized by these commands.

To verify both implementations together, build both reviewed checkouts and run `npm run test:interop -- /path/to/mcp-security-evidence`. This compares contract bytes and checks both producers and in-process Worker outputs against both schemas/verifiers without external requests. Normal CI uses vendored fixtures and remains independent of the peer. See [compatibility results](docs/compatibility-results.md) for the tested snapshots and limits. Neither implementation shares a database or depends on the other's runtime availability. Production transport and deployment remain unverified.
