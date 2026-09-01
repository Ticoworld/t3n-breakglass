# C-0 Material Uncertainties Closure Register

Audit date: 2026-09-01. The strict rule for this register is that no material item is left as a parked `UNKNOWN`. Each row ends in PROVEN, DISPROVEN, PROVEN IMPOSSIBLE / UNAVAILABLE, or NON-MATERIAL and names the evidence.

## Closure register

| Item | Final status | Closure evidence and conservative consequence |
|---|---|---|
| KV compare-and-swap for current world | PROVEN IMPOSSIBLE / UNAVAILABLE | Current `world.wit` and visible host WIT expose no CAS/conditional write; SDK `TenantMapsNamespace.entrySet` returns void. Design cannot assume reservation semantics. |
| Whole-invocation serialization as an external-effect fence | DISPROVEN | Two live simultaneous invocations both issued DELETE and returned 204 in the disposable sandbox. See `research/C-0-race-result.json`. |
| At-most-one destructive request | DISPROVEN | Same race evidence. Final provider absence cannot distinguish one/two idempotent effects, so only request multiplicity is asserted. |
| Wrong-DID reconciliation | DISPROVEN | Code branch precedes caller check; live operator DID reached GET-only reconciliation and state persistence. See `research/C-0-wrong-reconcile-result.json`. |
| Wrong-DID reconciliation can issue DELETE | PROVEN IMPOSSIBLE / UNAVAILABLE in current branch | `reconcile` contains no DELETE call. This does not repair the authorization flaw. |
| Precheck failure leaves no state damage | DISPROVEN | Code persists EXECUTING before GET and returns PRECHECK_FAILED without rollback. |
| Duplicate target authorities are rejected | DISPROVEN | No target index/uniqueness check exists; uniqueness is incident ID only. |
| Contract clock equals operator creation clock | PROVEN IMPOSSIBLE / UNAVAILABLE | Different APIs are used and no atomic comparison artifact exists. TTL guarantees must be stated as contract-time bounds only. |
| Current provider credential is ephemeral | DISPROVEN | Bootstrap stores a long-lived PAT in `z:<tenant>:secrets`; no mint/revoke/rotation path exists in BreakGlass. |
| Normal agent receives PAT | DISPROVEN for process boundary | Agent scripts send only incident ID and do not load PAT. The contract guest does receive plaintext, so “TEE-held only” is not literally true. |
| Event-derived incident authenticity exists | DISPROVEN | Incident creation is operator map write; no webhook ingress, HMAC verifier, delivery ID, or event digest exists in current system. |
| Current proof is an independent receipt | DISPROVEN | `audit_reference` is assembled by `scripts/product.ts`; current WIT does not import T3N audit. |
| T3N host audit/activity APIs exist in the installed SDK | PROVEN | `node_modules/@terminal3/t3n-sdk/dist/index.d.ts` contains `AuditEvent`, `ActivityEntry`, `getAuditEvents`, `getActivityLog`, and transaction metadata types. Availability to this deployed contract/world is not implied. |
| Current BreakGlass imports/uses host audit | PROVEN IMPOSSIBLE / UNAVAILABLE | `contract/wit/world.wit` imports only tenant-context, logging, kv-store, and http; no audit import. |
| GitHub App installation tokens can be repo/permission scoped and expire | PROVEN | GitHub official docs: installation tokens expire after one hour and accept repository/permission subsets. See `C-0-GITHUB-ARCHAEOLOGY.md`. |
| GitHub App private key is itself ephemeral | DISPROVEN | GitHub says App private keys do not expire and require manual revocation/rotation. |
| GitHub deploy-key deletion emits a documented delete webhook | PROVEN IMPOSSIBLE / UNAVAILABLE | Current official `deploy_key` event documentation lists `created`; no documented deleted action was found. Architecture cannot depend on a delete webhook receipt. |
| Webhook authenticity can be verified outside T3N | PROVEN | GitHub documents raw-body HMAC-SHA256 and constant-time comparison. |
| Webhook authenticity can be verified inside current BreakGlass contract | PROVEN IMPOSSIBLE / UNAVAILABLE | No event ingress or signing/crypto import is in current world. A gateway could verify and commit a digest, but that is a new boundary. |
| Provider DELETE is idempotent enough to hide duplicate requests | LIVE-EVIDENCE-PROVEN as an observation, not a guarantee | Both race calls returned 204 and final key was absent. GitHub docs define 204 success but do not promise effect-level idempotency. |
| Existing public competitors have independently proven every README claim | PROVEN IMPOSSIBLE / UNAVAILABLE | Public pages establish claims and code presence, but several live links/artifacts are absent or not independently reproducible. Reports distinguish repo claims from live evidence. |
| C-0 requires a destructive duplicate-target experiment | NON-MATERIAL | Code already proves no target index, and the one-target race experiment falsified the critical side-effect fence. No further destructive mutation is needed to choose the ceiling. |

## Count

Material `UNKNOWN`: **0**. The unavailable items are bounded platform limitations or evidence unavailability with a conservative design consequence; they are not silently deferred requirements.

## Decisions unlocked

- Any next architecture must provide reservation/fencing outside the current plain KV API or explicitly lower its claim to “best-effort idempotent remediation.”
- Reconciliation must have its own authenticated read/state authority and cannot inherit safety from being GET-only.
- A provider App token is a credible JIT improvement, but an App private key or equivalent broker authority remains standing.
- “Verified incident” must be an ingress protocol with HMAC/delivery dedupe/raw-body hashing and T3N anchoring; operator-created map entries are not evidence.
- Independent receipts require the platform audit/activity surface or an externally verifiable signed receipt; application JSON is insufficient.
