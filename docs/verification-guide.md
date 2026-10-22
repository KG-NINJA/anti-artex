# Bounded JSON verification and continuous interoperability

Service **0.3.0** adds raw JSON verification, an offline CLI, and a separate interoperability CI job. The event contract remains **2.0.0**: all seven original contract/spec/fixture artifacts, golden hashes, producer semantics and existing boolean verification results are unchanged. These are additive development capabilities, not a new HTTP endpoint or a live scanner.

## Verify a saved event

After `npm ci`, run from either repository (Node.js 24 is recommended):

```sh
npm run --silent verify:evidence -- fixtures/verify-example.json
npm run --silent verify:evidence -- /path/to/event.json
```

Pass `-` as the argument to read standard input. The input is **one event**, not a report wrapper, array or NDJSON stream. The command builds the local TypeScript and performs verification without fetching, executing, uploading, importing or storing the event. The example is the first synthetic v2 golden event, not real telemetry. Success prints:

```json
{"valid":true,"schema_version":"2.0.0"}
```

Exit code 0 means valid; 1 means rejected evidence; 2 means invalid command usage or file/stream read failure. The CLI caps the stream before accumulating more than 64 KiB. No parser exception, file path, field name or input value is included in its JSON response.

## Library functions

- `verifyEvidenceJson(string | Uint8Array)` in `src/evidence-json.ts`: verify raw JSON text or UTF-8 bytes, including duplicate-member checks **before** parsing discards earlier values. Prefer this for received or saved JSON. Byte inputs require valid UTF-8; a BOM is not accepted. The maximum is 65,536 bytes including whitespace and 20 nested object/array containers.
- `verifyEvidenceDetailed(unknown)` in `src/evidence-contract.ts`: return a fixed result/error code for an already-parsed object. It cannot recover duplicate keys previously discarded by a parser.
- `verifyEvidence(unknown)`: the existing boolean API remains available with the same acceptance behavior.

JSON escapes in property names are decoded when checking uniqueness, so `schema_version` and `\u0073chema_version` collide. The check applies at every object scope, including nested evidence/confidence. Same-named members in separate objects are allowed. Braces, commas, colons and escaped quotes inside strings are treated as data. Native JSON.parse still validates the JSON grammar; the bounded scanner does not interpret evidence content.

| Error code | Meaning |
| --- | --- |
| input_too_large | Raw input exceeds 64 KiB |
| invalid_utf8 | Byte input cannot be decoded strictly as UTF-8 |
| invalid_json | Invalid JSON syntax (including BOM/trailing data) or wrong raw input type |
| nesting_limit | More than 20 nested containers |
| duplicate_key | A decoded member name repeats within an object |
| unsupported_version | An explicit schema_version is not exactly 2.0.0 |
| invalid_shape | Required fields, field types, source profile or bounds are invalid |
| invalid_encoding | Object cannot use the prescribed encoding, e.g. unpaired Unicode surrogate |
| event_id_mismatch | ID does not match the complete payload |
| content_hash_mismatch | Well-formed content hash does not match payload plus ID |
| usage_error / read_error | CLI-only operational errors (exit 2) |

These are deterministic rejection categories, not detailed security findings. Multiple-invalid inputs may return the first detected category. Validity still does **not** establish a producer's identity, authorization, truthfulness, provenance or safety of execution. No automatic action may be inferred from `valid:true`.

## Interoperability CI and evidence of what was tested

The existing `ci.yml` keeps running each service's own security and contract tests. A new, separate `Evidence interoperability` workflow runs on pushes, pull requests and manual dispatch. It checks out the candidate and a **fixed, already merged peer commit**, installs locked dev dependencies with lifecycle scripts disabled, builds both and runs the existing two-checkout test. There is no schedule, deployment, payment or live target check.

| Candidate repository | Pinned peer baseline |
| --- | --- |
| anti-artex | mcp-security-evidence `f4362cbc8b04ab96c7bcab210aadc4d1f3ad327f` |
| mcp-security-evidence | anti-artex `53ce2ea8b9285bd30cbeb47440406680f475cda5` |

Pinning proves compatibility with these reviewed baselines, **not with whatever a moving branch later contains**. Update the peer commit explicitly during a coordinated release, after comparing/testing both candidates. The v2 contract directory remains immutable in this additive change so either candidate can be tested/merged independently. Runtime independence remains unchanged; only this development job checks out peer code.

Workflow permissions are contents:read, checkout credentials are not persisted, third-party action code is pinned to full commit SHAs, the job times out after 10 minutes, and dependency install scripts are disabled. The test blocks global fetch and uses only synthetic inputs, in-memory SQLite and a synthetic limiter. GitHub/package registry access is development setup, not a target scan.

On success, the job uploads `compatibility-report.json` as the **evidence-compatibility** Actions artifact, retained for 7 days. It records report version, timestamp, Node version, both actual checkout commits/trees, service versions, working-tree state, SHA-256 of compiled modules in both build output directories, all seven contract artifact hashes, fixture/Worker event counts and zero-outbound-test status. CI refuses dirty checkouts. A local edited checkout is reported honestly as dirty; its commit SHA alone is not claimed to identify all tested code. Module fingerprints identify the compiled files, not a cryptographically signed attestation or every installed dependency.

To reproduce outside CI, install/build both checkouts and run `npm run test:interop -- /path/to/peer`. To save pure report JSON after both builds, use `node scripts/verify-interop.mjs /path/to/peer > /path/outside/the/checkouts/compatibility-report.json`. Rebuild after source edits; fingerprints record the compiled files available to the test. No report contains input payloads, credentials or local absolute paths.

## Validation for this change

On 2026-10-23 JST, the local suites passed **32/32 tests in each repository** (previously 22/22). Added cases cover valid events from both producers, escaped/nested duplicates, quoted punctuation, exact byte/depth bounds, malformed JSON/UTF-8/Unicode, distinct rejection reasons, absence of outbound calls or input mutation, and CLI file/stdin/exit-code behavior. The original auth, privacy, quota, retention, limiter and no-probing tests still pass.

The two updated checkouts passed the 7-artifact comparison, 6 golden plus 6 regenerated events and 3 honeypot + 5 metadata Worker events against both schemas/verifiers, with zero outbound requests. Wrangler bundle checks use dry-run only. Remote workflow status is reported separately on the PR; local success does not imply remote CI or deployed service success. No merge, external scan, payment, signature or production deployment is performed by this change.
