# Threat model

Assets: dedicated research D1 integrity, minimized event confidentiality, investigation access, provider budget, and separation from production. Inputs from clients, tool arguments, JSON-RPC methods and headers are untrusted. A rule match is a possible injection, not proof of intent or an AI agent. No identity inference or live exploitation is performed.

Trust boundaries: restricted participant → MCP endpoint → bounded D1 records; investigator bearer → read-only report. Operator-supplied environment configuration is trusted. Cloudflare secrets are used only for authenticating these two interfaces, never exposed through tools. No production bindings, outbound requests, shared databases or partner callbacks exist. Dependency installation uses ordinary package registries; runtime payloads cannot initiate traffic.

Controls: bounded byte streams, strict JSON-RPC/argument validation, fixed simulated output, no reflection into HTML, no raw event viewer, default no-text storage, separate investigation auth, Origin rejection, capped rows/sessions and daily quota, expiry filtering/cleanup, generic errors. Both auth failures and suspicious sequences are recorded subject to the same quota and row cap. Rule evidence is explicitly heuristic with confidence and limitations.

Residual risks:

- An attacker can consume the global quota/cap and deny research recording; full storage intentionally drops new events rather than growing indefinitely. No claim of lossless telemetry.
- Every admitted request may incur D1 work. Traffic after the quota still performs one quota query. The app cannot enforce provider account billing ceilings or prevent platform-level DDoS costs.
- No-IP storage prevents per-client rate limits and attribution. Session possession is not identity. The session ID is not sufficient without MCP authentication.
- Optional previews can retain sensitive text that redaction misses. Keep `PREVIEW_CHARS=0`, restrict access and do not submit real secrets.
- Retention filtering does not erase provider backups or logs. Operator must configure those separately. Expired physical rows persist until cleanup succeeds.
- D1 availability errors fail closed. Health is only liveness; local tests do not prove deployment/account readiness.
- Bearer compromise permits the corresponding interface's access until rotation. No public investigation UI, browser login, multi-user RBAC or cryptographic evidence signing is implemented.
- The small protocol subset does not implement resources, prompts, server notifications, resumable SSE, OAuth discovery or complete MCP conformance.

All validation uses synthetic payloads and fictional domains. Never scan external services, execute a submitted payload, connect production data, or deploy automatically.
