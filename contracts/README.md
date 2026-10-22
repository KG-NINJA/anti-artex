# Security evidence contract 2.0.0

This directory is byte-identical in `KG-NINJA/anti-artex` and `KG-NINJA/mcp-security-evidence`. It specifies **offline JSON artifact interoperability**, not a transport, shared database, importer, signature service, or permission to probe/execute anything. Each service is built, tested and operated independently. No partner package, credentials, storage or runtime availability is required.

## Version and compatibility

Both producers now emit the exact string `schema_version: "2.0.0"`. This is a breaking contract relative to **both** independently developed v1 proposals. The service package versions advance from 0.1.0 to 0.2.0. Consumers must explicitly select the v2 schema and validate both shape and hashes; do not infer compatibility from the leading digit or coerce version strings.

| Field | Anti-ARTEX legacy `1.0` | Metadata service legacy `1` | Common `2.0.0` |
| --- | --- | --- | --- |
| event_id | Content-derived 64 lowercase hex | UUIDv4 | Content-derived 64 lowercase hex, same rule for both |
| confidence | Number in [0, 1] | low / medium / high | Tagged `{scale, value}`; exact source profile below |
| content_hash | Bare lowercase SHA-256 hex | `sha256:` plus lowercase hex | `sha256:` plus 64 lowercase hex |
| source/evidence | Honeypot indicators, optional preview | Metadata path and observation | Strict source-discriminated profiles |
| hash fields | Separate event-ID and content domains | Random ID included in content hash | One event-ID rule and one content rule for both |

The two legacy schemas and original synthetic examples remain available as historical artifacts. V2 verifiers reject both legacy versions. There is **no automatic conversion, relabeling, rehashing, or database migration**. In Anti-ARTEX, already stored unexpired legacy envelopes are returned unchanged with their original version/hash until ordinary retention removes them; readers must dispatch by version. MCP Security Evidence is stateless. Keep existing saved reports unchanged. Upgrading a reader before enabling the new producer avoids treating legacy reports as v2. Rolling back the producer does not convert v2 records; a reader must either support both explicitly or reject the unsupported version.

Future changes to field types, enum meanings, hashing, or source profiles require a new major contract. Even additive changes need an explicit version/schema update and fixtures because `additionalProperties: false` is deliberate. Never change old golden hashes to conceal incompatibility.

## Envelope and source profiles

`evidence-v2.schema.json` is JSON Schema 2020-12 and fixes the 12 top-level fields. All are required; unknown top-level and evidence/confidence properties are rejected. `observed_at` is a real UTC calendar timestamp in `YYYY-MM-DDTHH:mm:ss.sssZ` form. Assessment IDs are opaque nonempty grouping strings, at most 128 Unicode code points, with no client identity semantics. Limits on strings/arrays are part of the contract.

- `mcp_honeypot`: existing four heuristic finding names; severity low/medium; one to sixteen unique indicator strings; optional preview at most 256 code points. Producer sorts/deduplicates indicators before hashing. Preview is absent by default and redacted before truncation when enabled. Confidence is `{ "scale": "heuristic_score", "value": 0.65 }` (any finite value in [0,1]). It is **not a calibrated probability**. Existing 0.65 and 0.9 scores are retained.
- `submitted_mcp_metadata`: a bounded finding name, severity info/low/medium/high/critical, bounded JSON Pointer `path` and fixed `observation`. Confidence is `{ "scale": "ordinal", "value": "medium" }` (low/medium/high). The existing medium assessment is retained. An ordinal is not converted into an invented number, nor are the two scales assumed comparable. Source means submitted assertions, not a live scan.

Both consumers understand both source profiles. Accepting the envelope does not change either service's finding logic, grant authorization or cause an import. No IPs, headers, tokens or raw request bodies are added to producer output. Existing limitations/remediations remain required. A source label is a claim by the producer, not proof of actor identity or AI-agent attribution.

## Canonical encoding and integrity

1. Input is parsed JSON with supported types. Reject non-finite numbers, undefined values, sparse arrays, non-JSON objects, unpaired Unicode surrogates, and nesting deeper than 20. Duplicate JSON member names must be rejected by a raw-text ingestion layer before parsing if one is added; the current object verifier cannot recover duplicates discarded by `JSON.parse`. No raw-text ingestion endpoint is introduced.
2. Recursively sort object keys by ECMAScript UTF-16 string order; preserve array order. Use compact JSON with ECMAScript `JSON.stringify` primitive encoding, no whitespace and **no Unicode normalization**. Finite scores use ECMAScript number serialization (including `-0` as `0`). This bounded encoding is **not a claim of a general RFC 8785 implementation**.
3. Encode the resulting string as UTF-8, without BOM or trailing newline, and compute SHA-256.
4. Let `P` be the complete envelope excluding **both** `event_id` and `content_hash`.
5. `event_id = lowercase_hex(SHA256(UTF8(canonical(P))))`.
6. `content_hash = "sha256:" + lowercase_hex(SHA256(UTF8(canonical({ ...P, event_id }))))`.

Every payload field, including schema_version, source, timestamp, confidence, optional preview, limitations and remediation, is therefore bound. The ID itself is also bound by the content hash. Verification recomputes **both** values after strict shape checks. Merely replacing an ID and recomputing content_hash must fail. Optional preview absence and empty preview are distinct; null is invalid. Reordering object keys is harmless; reordering array elements changes the hashes.

A fixed observation tuple produces identical IDs/hashes. Separate assessment invocations still get fresh assessment UUIDs and timestamps, so equivalent findings in independent runs remain distinct. These are integrity/deduplication rules, **not signatures, producer authentication, authorization evidence, settlement evidence, or proof that a finding is true**. Consumers apply their own provenance/trust policy.

## Fixtures and reproducible validation

Baseline snapshots: Anti-ARTEX `5ecdf5fcda78b8edd669f76890f3be271e70a762`; MCP Security Evidence `e3ebc552de43b851719ecc3ef15a777622fa696b`. Both were main on 2026-10-22 during reconciliation.

- `fixtures/legacy-*.json`: unmodified legacy event data from those snapshots (the metadata event is the first event in the original example report).
- `fixtures/producer-inputs.json`: fixed synthetic observation tuple and submitted metadata; never a target to contact.
- `fixtures/evidence-v2.json`: one honeypot event and five metadata events. Expected IDs/hashes were calculated separately using Python hashlib with sorted, compact UTF-8 JSON for these fixture values, not by importing the production sealer. Tests also verify them with Node crypto.
- `fixtures/canonical-vectors.json`: fixed UTF-8/escaping/nesting/array/number encodings and SHA-256 digests, including Japanese, emoji, composed/decomposed text and ECMAScript exponent notation.

`npm test` in either repository runs all existing security tests plus both-profile schema/hash/golden/negative tests using only local fixtures. `src/evidence-contract.ts` provides a pure `verifyEvidence(unknown): Promise<boolean>` with no runtime dependency; validation does not store or execute the evidence. The JSON Schema checks structural validity; the verifier additionally enforces calendar normalization, Unicode validity and the two hash relations.

For an actual two-checkout check, install/build both reviewed checkouts first, then run from **either** one:

```sh
npm run test:interop -- /absolute/path/to/the/other/checkout
```

The script never downloads a counterpart or changes refs. It requires identical schema/spec/fixture bytes, demonstrates legacy own-pass/cross-fail, regenerates golden records with both real producers, invokes both Workers locally (SQLite-backed D1 adapter and synthetic limiter), and validates each output with **both schemas and both verifiers**. It also rejects tampering/legacy data and aborts any outbound fetch. It fails if the peer still has the old contract or is not built. Normal CI stays independent and runs vendored fixture coverage; run this explicit two-checkout command when coordinating contract releases. Synthetic success does not establish deployed transport compatibility or production readiness.
