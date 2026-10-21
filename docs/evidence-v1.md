# Proposed evidence compatibility contract v1

Status: **local proposal; partner compatibility unverified**. Partner `KG-NINJA/mcp-security-evidence` exposed no refs and `main/README.md` returned 404 during this task. No counterpart files were modified. This contract must be reconciled with its documented schema before integration. Deployments remain independent; exchange JSON artifacts only by an approved process, never a shared database.

Required exact fields are specified by `evidence-v1.schema.json`. Version `1.0` is a string. UTC timestamps use ISO 8601 millisecond `Z` form. Source type is `mcp_honeypot`, meaning the observation surface, **not** actor attribution. Assessment ID groups observations from one request and contains no client identity. Finding values describe heuristic observations: possible injection, invalid authentication, anomalous sequence or malformed request. Confidence is a numeric score in [0,1], not a calibrated probability. Severity is `low` or `medium`; no autonomous incident declaration occurs.

Evidence contains sorted unique static indicator names and optionally a redacted preview up to 256 characters (disabled by default). Limitations explicitly state that payloads were not executed and actor identity is unknown. No IPs, authorization headers, user-agent identities or raw request bodies belong in the default evidence. Request identifiers are random UUIDs in live traffic; fixtures use a fixed synthetic ID.

Canonicalization recursively sorts object keys with JavaScript string ordering, preserves array order, has no insignificant whitespace, and uses JSON.stringify primitive encoding. All output values are JSON-compatible and numbers are finite. This is the explicitly bounded v1 encoding, not a general RFC 8785 claim.

`event_id = lowercase_hex(SHA256(UTF8(canonical(envelope without event_id and content_hash))))`.

`content_hash = lowercase_hex(SHA256(UTF8(canonical(envelope without content_hash))))`.

Hash verification does not prove who produced an artifact. A deterministic observation tuple yields identical IDs/hashes; independent live requests have different assessment IDs/timestamps and should not deduplicate merely because their payloads match. Consumers validate schema and hash, then apply their own trust policy. No transport, auto-import, signing or partner compatibility is implied.

Before agreement: compare partner version naming, enum values, timestamps, identifier formats, confidence type, evidence shape, canonicalization/hash input and optional-field handling. Breaking changes require a new major contract and shared synthetic golden fixtures reviewed on both sides. Minor additions must be explicitly accepted because v1 rejects unknown properties. Never silently relabel this proposal as the partner's schema.
