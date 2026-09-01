# BreakGlass Threat Model

Scope: one-use GitHub deploy-key revocation through the Phase 1 Rust/WASM contract and the Phase 2 operator/agent product surfaces. This document records the controls that are implemented and tested; it does not claim protection outside those boundaries.

| Threat | What prevents it | Enforcement location | Out of scope |
| --- | --- | --- | --- |
| Compromised or prompt-injected LLM | The agent tool accepts only `incident_id`; target and action are private authority fields. | MCP schema, agent parser, Rust `deny_unknown_fields`, private map read | A compromised operator workstation or a malicious operator creating a bad authority |
| Agent target substitution | Owner, repository, and key ID are rejected as agent arguments and loaded from the incident record. | Agent interface and contract | An operator deliberately authorizing the wrong target |
| Agent expiry extension | Expiry is not an agent input and the contract compares it with cluster time. | Operator freeze and `begin_execution` in Rust | Clock compromise outside the T3N cluster |
| Agent incident creation | The agent process has no operator client or map-write surface; MCP exposes no creation tool. | Process environment, code surface, T3N authorization | An attacker obtaining the operator key |
| Replay | `CONSUMED` authorities return `REPLAY_REFUSED` before any DELETE. | Contract state machine | Replaying a separate, still-active authority |
| Duplicate delivery or network ambiguity | The contract records `EXECUTING`, does not retry DELETE, and moves to GET-only `RECONCILE_REQUIRED`. | Rust contract | GitHub or T3N being permanently unavailable; operator recovery is required |
| Credential exfiltration | PAT is seeded only by the operator into a private T3N map; agent processes and structured outputs omit it. | Bootstrap path, private map ACL, contract output, logs | Host compromise that defeats the TEE or a PAT revoked outside this workflow |
| Compromised / dishonest GitHub API response | DELETE success is not trusted alone; an authoritative GET must return 404 before consumption. | Rust contract and independent operator verification | A compromised GitHub API returning a false 404 |
| Stale incident | Contract uses cluster time at execution and persists `EXPIRED`. | Rust `cluster_timestamp_secs` gate | An operator failing to monitor a still-active authority before expiry |
| Wrong agent DID | Caller DID must match the authority DID byte-for-byte after canonical hex comparison. | Rust `caller_matches`; operator roster resolution | Compromise of the authorized agent credential |
| Operator mistake | Required target fields, live key preflight, exact preview, explicit confirmation, and fixed action/use policy. | `incident:create` control plane | Human confirmation of an incorrect but valid preview |
| GitHub changes between creation and execution | Preflight happens at creation; execution performs a fresh GET and refuses DELETE unless HTTP 200; after DELETE it verifies 404. | Operator workflow and Rust contract | A key changing between the execution pre-GET and DELETE; the contract handles inconsistent results as reconciliation-required |

## Security invariants

1. The only agent request field is `incident_id`.
2. The only destructive verb is the contract's fixed GitHub DELETE for the authority target.
3. A destructive call is attempted at most once per authority.
4. `CONSUMED` is durable and replay-safe.
5. The agent process never loads operator or GitHub credentials.
6. The 5.2.0 trust-manifest flow is retained; 5.3.0 is not used because its validation contract is incompatible with the observed live manifest.

## Evidence boundary

Phase 1 live evidence is preserved separately from Phase 2 product evidence. The repository contains ignored local disposable SSH private keys under `evidence/raw/` for bootstrap reproducibility; those files are not emitted in structured evidence, logs, or agent output.
