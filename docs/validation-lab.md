# Isolated MCP security validation lab

**Status: synthetic/local research only.** The `lab:validate` command runs the
real compiled Anti-ARTEX Worker in-process, backed by an in-memory SQLite
adapter that exercises its D1 SQL schema. It never calls an external MCP
server, deploys anything, pays for a service, or executes the simulated tool
input. Only fictional names and synthetic bearer strings are used.

## Reproduce

From this repository, with Node 22.13+:

```bash
npm ci --ignore-scripts
npm test
npm run lab:validate
```

Reports are produced under ignored `artifacts/lab/summary.json` and
`artifacts/lab/summary.md`. The result contains **labels and indicators**,
not raw prompts, bearer values, or client identifiers.

## Case matrix

- Benign simulated lookups, including a quoted attack phrase
- Malicious-looking instruction override, role spoof and shell-like text
- Prompt-shaped text in `initialize.clientInfo` (must not trigger detection)
- Invalid bearer and missing session
- Stream that never sends a body (must be cancelled after a 2-second deadline)

The synthetic expected-vs-observed matrix reports TP, FP, FN, TN, precision,
and recall. These are **unit-test statistics on six curated examples only**,
not measured field effectiveness. The quoted-attack example is deliberately
retained as a **known false positive**, rather than silently manipulating the
test labels to show perfect performance.

## Separation of responsibilities

- `anti-artex` supplies an inert fictional MCP endpoint and minimized
  simulated evidence.
- `mcp-security-evidence` assesses *submitted* metadata only; it does not
  import Anti-ARTEX runtime records or scan external targets.
- Contract v2 interoperability is separately tested by existing pinned CI.

## Boundaries

No production releases, scans, real credentials, exploit payload execution,
payment flows, or cross-service runtime dependencies are authorized by this lab.
Its tests do not establish actual MCP server safety or production readiness.
