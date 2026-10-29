# Practical security evaluation portfolio: Anti-ARTEX

## Scope and use
This is an **offline, synthetic evaluation portfolio**, not a paid penetration test, proof of a production exploit, or evidence of existing customer security failures. It is safe to run locally with no service credentials or network access.

From the reviewed GitHub branch with Node 22.13+:

```sh
npm ci --ignore-scripts
npm test
npm run lab:validate
npm run benchmark:triage
```

Two independent sample reports are written to ignored `artifacts/` directories. GitHub CI validates both commands. To discuss this in an interview, show the repository tests, the score matrix and the *limitations*, not an invented discovery count.

## Assessment process
1. **Scope** — Own synthetic MCP tool and fictional prompts only.
2. **Inventory and threat boundary** — MCP request and declared tool arguments are distinct from untrusted natural-language content. Authentication failures and invalid protocol sequences are separate classes.
3. **Negative controls** — Normal prompts and quoted instructions must be measured; a security phrase inside documentation is not an attack by itself.
4. **Positive controls** — Synthetic instruction overrides, role spoofing, and shell-shaped strings. No payload execution or outbound fetch.
5. **Measurement** — Report TP/FP/FN/TN and conditional precision, recall, and FPR; preserve mistakes.
6. **Triage** — All positives are leads for human review, not confirmed vulnerabilities.
7. **Re-test and evidence** — Evidence Contract v2 and the cross-repository consistency CI validate output structure. Do not confuse SHA-256 integrity with authenticity.

## Safety and professional boundaries
The work is most relevant to entry-level AI/MCP security QA, test automation and evidence reporting. It **does not** establish qualifications to conduct independent customer penetration tests. A real engagement would additionally need written owner authorization, rules of engagement, a target inventory, severity verification, recovery/escalation contacts, and human review before any production changes.
