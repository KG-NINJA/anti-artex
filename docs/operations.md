# Manual deployment, budget and rollback

No deployment, account provisioning, paid upgrade, secret extraction or infrastructure changes were performed. Deployment is a separate explicitly approved operator action. Never modify AVU, SI Dog Park, `mcp-security-evidence` or any production service.

## Before an approved deployment

1. Keep the Worker in a dedicated research project/account context with a new dedicated D1 database. Do not reuse a production binding or credentials. Review current Cloudflare pricing/limits and remain on the Free plan. **Budget ceiling: $0 incremental paid spend; paid upgrades and overage are prohibited.** If a free-only configuration cannot be guaranteed, do not deploy. Configure account notifications where available; alerts are not hard billing caps.
2. Keep research ingress disabled: `workers_dev=false`, `preview_urls=false`, no routes. `database_id` in the committed configuration is an intentionally invalid placeholder. Only after explicit approval, create a new database using `npx wrangler d1 create anti-artex-research` and put its ID in an operator-local config copied from `wrangler.toml`. Never guess an ID or bind an existing database. Apply `npx wrangler d1 migrations apply anti-artex-research --remote --config <local-config>` only after verifying the target account and new database ID.
3. Set distinct, cryptographically random bearer tokens with approved secret tooling (`wrangler secret put MCP_BEARER_TOKEN` / `INVESTIGATION_TOKEN`, using the same local config). Do not write values to version control, shell history, logs or chat. These are research interface secrets only; no provider/production secret belongs in a tool response.
4. Default ceilings: 1000 MCP requests/day, 1000 event rows, 100 sessions, 8 KiB request bodies, 24-hour retention, zero previews. Hard configuration maxima are documented in README. The quota is global UTC, persisted in D1, and fails closed on errors. Investigation reads and platform traffic are not covered by the MCP quota: restrict them at the edge. Provider-enforced account quotas, deny-by-default ingress, rate limiting and an operator kill switch are required before exposure. No global spending guarantee comes from application counters.
5. Run `npm ci`, `npm run lint`, `npm test`, and `npm run bundle`. With explicit approval only, deploy the reviewed version using `npx wrangler deploy --config <local-config>`. Do not enable a public route for this synthetic-only MVP. Access policies, account-level controls, D1 limits and secret rotation must be reviewed before any later exposure decision. No live endpoint smoke tests are part of this issue.

## Cleanup and rollback

Hourly cron deletes expired evidence/sessions and old budget rows; reads hide expired evidence immediately. For immediate deletion or a reduced retention policy, stop ingress first and perform a separately approved D1 cleanup in the dedicated database. Provider backup/log deletion is a separate concern.

If unexpected traffic, costs, data retention or behavior appears: disable ingress/routes and cron using the operator's Cloudflare controls; do not continue probing clients. Revert to the previous reviewed Worker version using Cloudflare's version rollback tooling, or leave ingress disabled if no known-good version exists. Do not roll back migrations against production or delete another service's database. This initial additive schema has no destructive down migration; delete the dedicated research database only with explicit approval and after retention/preservation review. Rotate research bearer tokens if exposed. Verify access stays disabled and account consumption stops using provider-side controls.

## Independence and unresolved integration

Partner schema access was unavailable (empty advertised Git refs, README 404). Contract v1 here is a proposal, not a claim of agreement. Compare the counterpart's documented types, canonicalization, enum values, evidence and hash rules before transferring synthetic envelopes. Record differences in `docs/evidence-v1.md`; no shared DB, automatic export or runtime dependency is permitted. Send no external coordination messages without authorization.
