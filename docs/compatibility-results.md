# Evidence compatibility reconciliation — 2026-10-22

Verified locally at 2026-10-22 05:17 UTC / 14:17 JST, using Node.js 24.19.0. These results describe the changes in this PR and its counterpart; they do not claim that main or any production deployment already contains them.

## Baselines and reproduced problem

| Repository | Inspected main commit | Baseline lint/build/test |
| --- | --- | --- |
| Anti-ARTEX | `5ecdf5fcda78b8edd669f76890f3be271e70a762` | PASS; 10 tests |
| MCP Security Evidence | `e3ebc552de43b851719ecc3ef15a777622fa696b` | PASS; 11 tests |

No competing open fix PR was found when this work began. Both mains were rechecked before publication and still matched these baselines.

The old schemas disagree on version, event identity, confidence, source/evidence profiles, hash prefix and the rules used to assign event IDs. Both content hashes bind all fields except content_hash, but the incompatible event IDs and payload encodings make the complete integrity contracts incompatible. Existing per-repository tests passing did not establish cross-project compatibility.

| Legacy producer artifact | Anti-ARTEX v1.0 schema | Metadata service v1 schema |
| --- | --- | --- |
| Anti-ARTEX v1.0 | PASS | REJECT |
| Metadata service v1 | REJECT | PASS |

This matrix is asserted by the local contract tests and by the explicit two-checkout test.

## Implemented contract and migration boundary

Both repositories vendor the same [contract 2.0.0](../contracts/README.md), JSON Schema and synthetic fixtures. Service versions are 0.2.0. IDs are SHA-256 of the complete payload excluding ID/hash; content hashes use `sha256:` and include the derived ID. Confidence is a tagged score or ordinal so neither existing meaning is lost or fabricated. Strict source profiles retain the honeypot's minimized indicators/optional preview and the metadata service's fixed observations/paths. Both pure verifiers enforce shape, exact version and both hash relations. Unicode preview truncation avoids splitting an emoji into an invalid surrogate.

Old schemas and fixtures remain unchanged. V2 validation rejects legacy data, including silently relabeled/coerced records. Existing unexpired D1 legacy records remain byte-equivalent JSON objects on read; no migration or automatic conversion is performed. New evidence is explicitly v2. Rollout/rollback readers must select the correct version or reject unsupported records.

## Verification after the changes

| Check | Anti-ARTEX | MCP Security Evidence |
| --- | --- | --- |
| Lint / TypeScript build | PASS | PASS |
| Full test suite | 22 PASS, 0 fail/skip | 22 PASS, 0 fail/skip |
| Worker bundle, Wrangler dry-run only | PASS | PASS |
| Synthetic sample report | Covered by fixtures/Worker tests | 5 events; 0 target requests |
| Explicit two-checkout command, run from each repository | PASS | PASS |

The two-checkout script compared **7 contract/spec/fixture files byte-for-byte**, checked 6 pinned golden events, regenerated those 6 events through the real producers, and generated another **3 honeypot + 5 metadata events through the in-process Worker interfaces**. Every event passed **both** JSON Schemas and **both** runtime verifiers. The honeypot Worker used its actual SQLite schema/queries via an in-memory D1 adapter; the metadata Worker used an explicitly synthetic limiter binding (the original limiter's own tests also still pass).

| V2 producer | Anti-ARTEX schema + verifier | Metadata schema + verifier |
| --- | --- | --- |
| Anti-ARTEX | PASS | PASS |
| MCP Security Evidence | PASS | PASS |

Coverage includes every-field tampering, recomputed content hash with a forged ID, key/array ordering, source-profile mismatch, wrong/missing versions, numeric/string/array coercion attempts, unknown fields, limits, invalid timestamps, optional/null previews, Unicode and non-JSON values. Node crypto independently checks golden hashes; fixed expected hashes were calculated separately with Python hashlib. Legacy rejection and unchanged stored legacy reads are tested.

Existing authentication, owner/target scope, no-probing behavior, SSRF lexical denial, request/row/session/rate limits, privacy, read-only reports and retention tests all pass. No production bindings, credentials, databases, ingress, egress, deployment workflows or payment functions were added or modified. Ajv formats is a dev-only addition in the metadata repository; runtime has no new package dependency.

## Reproduction and limits

Run `npm ci`, `npm run lint` and `npm test` in both reviewed checkouts, then from either run `npm run test:interop -- /path/to/the/other/checkout`. For bundles, use `WRANGLER_SEND_METRICS=false npm run bundle` in Anti-ARTEX and `WRANGLER_SEND_METRICS=false npx --no-install wrangler deploy --dry-run --outdir dist/worker` in MCP Security Evidence. These commands do not deploy.

The interoperability test replaced global fetch with a throwing guard and recorded **0 outbound requests**. No live external scan, exploit execution, payment, wallet signature, production deployment, PR merge, shared storage or runtime transport was performed. GitHub/dependency access was solely development activity. No deployed Worker/D1/Durable Object integration, service-binding ingestion, signed provenance or production readiness is established by these tests. The new PRs require review before merge; the original PR #2 reviews do not cover these changes.
