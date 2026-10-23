# PR #4 security and compatibility review

Reviewed on 2026-10-23 JST. This is a source review and independent synthetic execution, not a production security certification.

## Scope and revisions

- Anti-ARTEX: base `53ce2ea8b9285bd30cbeb47440406680f475cda5`, original PR head `6d3409bf8c2dc255cd9b062b68c05c2e8f7d6da1` (12 changed files).
- MCP Security Evidence: base `f4362cbc8b04ab96c7bcab210aadc4d1f3ad327f`, original PR head `ead109e7e7a649004d9d53c50ca2e506c05d9ff0` (11 changed files).
- All changed source, tests, scripts, workflows, documentation, examples and package metadata were reviewed. Supporting canonicalization, producer and Worker paths were inspected. The existing threat models remain applicable.
- The review follow-up changes development workflows, regression tests, the cross-check and this documentation; it does not modify runtime validation or the seven v2 contract artifacts.

## Review results and remediation

| Area | Result |
| --- | --- |
| Duplicate members | Each object gets its own Set; quoted strings skip escaped characters; keys are decoded with JSON.parse before comparison. Final JSON.parse rejects malformed grammar. Nested arrays, escaped quotes/slashes/backslashes, control characters, surrogate pairs, every envelope field and both member orders are covered. No duplicate bypass was reproduced. |
| Input bounds | Raw string byte measurement and byte-input length cap precede parsing; the structural scanner rejects more than 20 containers. CLI accumulation is bounded at 65,536 bytes. Exact limit and limit+1 are tested through both file and stdin. |
| Encoding | Strict UTF-8 rejects invalid byte sequences. A BOM is rejected as JSON; invalid Unicode scalar strings fail canonicalization. Equivalent-but-distinct Unicode strings are not normalized. |
| Integrity | Shape validation precedes hashing. event_id binds the complete payload, and content_hash binds payload plus ID. Forging an ID and recomputing only content_hash still fails in both raw verifiers. Contract fixtures and golden hashes are unchanged. |
| Error disclosure | Rejection results contain fixed codes. Added CLI tests assert empty stderr and absence of confidential input/path markers for malformed JSON/UTF-8, BOM, duplicate keys and oversized input. |
| CI dependency controls | The new workflow was already read-only and SHA-pinned. The existing CI still used mutable action tags, persisted checkout credentials and enabled dependency lifecycle scripts. The follow-up pins checkout/setup-node to the same verified official commits, disables credential persistence and install scripts, and bounds the metadata job to ten minutes. Wrangler dry-run uses the installed dependency. This is supply-chain hardening; no compromised dependency or credential disclosure was observed. |
| Interoperability coverage | The original two-checkout script only called the object verifier. It now also verifies raw JSON text and UTF-8 from both producers, rejects tampering/escaped duplicates/legacy events, and records per-verifier counts. A v0.2.0 peer lacking the new API is explicitly reported; other missing raw verifiers fail. |
| Provenance | CI requires clean source checkouts and reports actual commits/trees plus SHA-256 of compiled modules and the seven contract artifacts. Artifact retention remains seven days. The report is not signed and does not attest every installed dependency. |

## Independent validation of the follow-up

- Clean dependency installs used `npm ci --ignore-scripts --no-audit --no-fund`; no package versions or lockfile dependencies changed.
- Both repositories: lint and **36/36 tests passed**, including all prior authorization, privacy, quota/retention, limiter and no-probing tests.
- Both Workers: Wrangler **dry-run only** passed. Metadata sample: five evidence events and zero target requests.
- The cross-check ran from each repository against the other updated checkout. All seven contract artifacts matched; six golden events, six regenerated events, and three Anti-ARTEX plus five metadata Worker events passed both schemas and object verifiers.
- Each raw verifier accepted 40 inputs (text and UTF-8 for 20 events) and rejected 42 inputs (20 modified events, 20 escaped duplicates and two legacy events), in each direction. Neither current verifier was skipped. Outbound fetch count was zero.
- Remote CI is a separate gate: require successful per-service and interoperability jobs for the final PR heads before merging. The CI artifact identifies the actual tested revision, including a synthetic merge revision where applicable.

## Limits and maintained boundaries

This review found no reproducible bypass in the new runtime verifier. The additional changes close a CI coverage gap and harden existing dependency execution. A clean synthetic result does not prove absence of vulnerabilities.

The raw verifier is an offline library/CLI; it is not a new ingestion endpoint or a change to the existing HTTP request parsers. The already-parsed boolean API cannot recover discarded duplicate keys. Integrity hashes do not authenticate a producer or establish authorization, truth or safety of execution. Runtime dependencies, v2 producer semantics and existing functionality remain intact.

Each CI job compares against a pinned, reviewed v0.2.0 peer baseline. The separate local two-candidate check verifies both new raw implementations; the baseline CI alone must not be described as testing both new implementations. No external target scan, real payment, wallet signature or production deployment was performed.
