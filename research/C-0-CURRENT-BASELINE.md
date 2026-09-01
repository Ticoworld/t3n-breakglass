# C-0 Current BreakGlass Baseline

Audit date: 2026-09-01. Public baseline: `4a077035474337b7a1ad16204820e68ed3020477` (`4a077035474337b7a1ad16204820e68ed3020477`). This document describes code, not the claims in the README.

## System reconstruction

| Boundary | What the baseline actually does | Evidence / status |
|---|---|---|
| Operator | Creates an incident record in the tenant's private `incidents` map, after validating and preflighting a GitHub target. The legacy script can write directly and uses local wall-clock time when no node URL is supplied. | `scripts/incident-create.ts:138-163`, `scripts/create-incident.ts:48-70`. CODE-PROVEN |
| Agent | Receives only `{incident_id}`. The tool schema rejects extra fields. It has no GitHub or operator credential in its process. | `contract/src/authority.rs:6-20`, `scripts/agent-tool.ts`. CODE-PROVEN |
| T3N identity | The contract gets `tenant_context::calling_user_did()` and compares it to the authority DID in the normal ACTIVE path. Agent authentication/delegation and egress are configured outside the contract. | `contract/src/lib.rs:92-110`; `scripts/lib.ts:74-93`. CODE-PROVEN |
| Authority | A JSON `IncidentAuthority` binds incident ID, expected agent DID, fixed action, owner/repository/key ID, creation/expiry, and use count. It is application data in a private tenant map. | `contract/src/authority.rs:22-71`; `contract/src/lib.rs:44-83`. CODE-PROVEN |
| ACLs | Runtime tenant isolation and map permissions are T3N controls. The application does not implement a second map ACL. The tenant owner/control plane retains map authority. | `contract/wit/deps/host-interfaces-2.1.0/package.wit`; T3N z-namespace docs. SOURCE-PROVEN / CODE-PROVEN |
| Credential | One `github_pat` is stored in a private `secrets` map. The contract reads it through `kv_store::get`, converts it to a Rust `String`, and places it in the Authorization header. | `contract/src/lib.rs:357-380`, `scripts/bootstrap.ts:100`. CODE-PROVEN |
| Egress | The contract hard-codes `https://api.github.com`; the agent's T3N grant is configured for that host. This is a host-level ceiling, not a target-specific provider capability. | `contract/src/lib.rs:112-125`, `scripts/configure-agent-egress.ts`. CODE-PROVEN |
| Caller authentication | T3N invocation authentication happens before contract execution. The contract's normal branch additionally compares the caller DID to `authority.agent_did`; reconciliation does not. | `contract/src/lib.rs:85-110,291-354`. CODE-PROVEN; live wrong-DID result below. |
| TTL | The contract enforces `cluster_timestamp_secs` against `created_at`/`expires_at` only after entering the normal ACTIVE branch. Operator creation uses the node HTTP `Date` header. Exact equality of those sources is not established. | `contract/src/lib.rs:92-110`; `scripts/product.ts:103-110`. CODE-PROVEN; material equivalence is PROVEN IMPOSSIBLE / UNAVAILABLE from current artifacts. |
| Target binding | Owner, repository, and numeric deploy-key ID are frozen in the incident. URL segments are checked for a restricted character set and length. No provider conditional version/ETag is used. | `contract/src/authority.rs:100-139`; `contract/src/lib.rs:382-435`. CODE-PROVEN |
| State machine | ACTIVE -> EXECUTING is persisted before the provider precheck. Normal success verifies GET 404 and consumes. Ambiguous delete/verification leads to GET-only reconciliation. | `contract/src/authority.rs:141-203`; `contract/src/lib.rs:112-354`. CODE-PROVEN |
| External precheck | Contract GETs the exact key before DELETE. Transport errors, non-200, or malformed response fail the precheck but leave the authority EXECUTING. | `contract/src/lib.rs:126-155`. CODE-PROVEN |
| DELETE | A DELETE transport error is followed by one GET, never another DELETE. A successful DELETE is followed by GET; 404 consumes, non-404 is failed or reconciliation-required according to response. | `contract/src/lib.rs:158-287`. CODE-PROVEN |
| Post-verification | Exact key GET is authoritative for the contract's decision. The live phase-2 proof also independently checked GET and list after success. | `contract/src/lib.rs:208-287`; `evidence/phase2e/phase2e-live-proof.json`. CODE-PROVEN / LIVE-EVIDENCE-PROVEN |
| Replay | A serial ACTIVE request after CONSUMED is denied. The state field is not a cross-invocation reservation or external side-effect fence. | `contract/src/authority.rs:141-203`; `evidence/phase2e/phase2e-live-proof.json`; `research/C-0-race-result.json`. CODE-PROVEN / LIVE-EVIDENCE-PROVEN |
| MCP | One exact tool calls the agent path and exposes the incident ID only. It does not expose target, PAT, or arbitrary action arguments. | `scripts/agent-tool.ts`, `scripts/agent-execution.ts`. CODE-PROVEN |
| Evidence | The contract returns a JSON proof with target, state, count, HTTP statuses, and a weak application-created `audit_reference`. No current contract import writes a host-stamped audit event or receipt. | `contract/src/lib.rs:439-525`, `scripts/product.ts:28-39,140-154`, `contract/wit/world.wit`. CODE-PROVEN |
| Bootstrap | Scripts create maps, upload/register the component, configure delegation and egress, fund/execute an agent, and inspect GitHub. The phase-2 disposable key is private sandbox evidence, not production architecture. | `scripts/bootstrap.ts`, `scripts/incident-create.ts`, `scripts/agent-execution.ts`, `evidence/phase2e/phase2e-live-proof.json`. CODE-PROVEN / LIVE-EVIDENCE-PROVEN |

## Current security invariants

These are the invariants that survive code inspection. They are deliberately narrower than the public thesis.

1. A normal ACTIVE request can supply only an incident ID, not an arbitrary target or action.
2. A normal ACTIVE request must come from the DID encoded by the authority and must be within the contract's cluster-time window.
3. The action is fixed to `revoke_github_deploy_key`; shape validation rejects other actions, malformed DIDs, unsafe path segments, invalid use bounds, and `max_uses != 1`.
4. Normal successful execution does one contract-requested DELETE at most in the serial path and performs a GET verification; the implementation never retries DELETE after an ambiguous response.
5. The target is fixed in the authority and the HTTP host is fixed in the component.
6. The ordinary agent process does not receive the PAT or operator credential; the contract guest does receive the PAT plaintext from the sealed map.
7. T3N tenant boundaries and runtime egress grants constrain ordinary invocation and cross-tenant map access.
8. A serial replay after CONSUMED is refused.

The following are not valid invariants: at-most-one destructive request under concurrency; caller authorization for reconciliation; event authenticity; provider-token ephemerality; an independently verifiable receipt; or exact equality between operator and contract clocks.

## Current assumptions

- The operator/control-plane principal is trusted to select the right repository/key and create the incident.
- The provider PAT remains available and sufficiently scoped for all emergency actions.
- A normal external call is either observed as a clear result or safely recoverable with GET reconciliation.
- The T3N runtime's invocation authorization and egress grant are correctly configured for the replacement agent.
- A proof returned by the contract is useful evidence even without a host-stamped ledger receipt.

The first, second, and fifth assumptions are not acceptable foundations for evidence-bound authorization. They are product and security debt, not hidden platform guarantees.

## Unproven claims found in the public narrative

| Claim | Finding |
|---|---|
| “One-use” means one destructive effect | DISPROVEN. Two genuinely simultaneous testnet invocations both returned a 204 DELETE path in a fresh disposable sandbox. See `research/C-0-race-result.json`. |
| Reconciliation is harmless to unauthorized callers | DISPROVEN. The branch occurs before caller DID validation and a wrong DID invoked provider GET plus state persistence. See `research/C-0-wrong-reconcile-result.json`. |
| “Sealed” PAT is never accessible to the agent | Narrowly worded claim only. CODE-PROVEN: the normal agent process does not receive it. CODE-PROVEN: the contract reads plaintext into guest memory. |
| Every execution has an independent audit receipt | DISPROVEN for current implementation. `audit_reference` is JSON made by application code; no audit host import exists in `world.wit`. |
| TTL is precisely operator-selected | DISPROVEN as a precision claim. Contract and creation paths use different accessors; same node URL does not prove same sampled timestamp. |

## Product-loop gaps

The baseline closes “operator chooses a key -> authorized agent requests one fixed delete -> provider is checked.” It does not close detection, evidence ingestion, incident triage, policy evaluation, human escalation, automated monitoring, expiry cleanup, provider credential issuance/revocation, post-incident learning, or an independently verifiable cause-to-action-to-outcome receipt. These are complete-system gaps, not requests for more UI.

## T3N dependencies versus application code

T3N supplies tenant identity/context, TEE/WASM execution, private map/sealed-value access, host-controlled egress, agent authentication/delegation, and platform ledger/activity surfaces. BreakGlass application code supplies incident schema, DID comparison, TTL gate, target validation, state machine, effect handling, verification, and proof formatting. The latter are not magically transactional because they run in a TEE.

## Baseline classification

NOT COMPETITIVE ENOUGH for a 50–100-team bounty field. It is a useful bounded primitive and a credible vertical proof, but its race condition, reconciliation authorization flaw, standing provider credential, application-invented incidents, weak receipt, and incomplete operational loop let deeper systems beat it.
