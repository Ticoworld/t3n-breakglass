# C-0 Verification Index

Purpose: let an independent reviewer move from each major C-0 conclusion to the smallest supporting artifact. All paths are relative to repository root. Evidence is intentionally separated into contract-reported output and independent provider observation.

## Baseline and invariants

| Conclusion | Smallest evidence chain |
|---|---|
| Public baseline is frozen | `git rev-parse HEAD` = `4a077035474337b7a1ad16204820e68ed3020477`; `contract/src/lib.rs`; `contract/src/authority.rs`; `contract/wit/world.wit` |
| Agent receives only incident ID | `contract/src/authority.rs:15-18`; `scripts/agent-tool.ts`; `evidence/phase2e/agent-request.json`; `evidence/phase2e/t3n-execution.json` |
| Normal caller/TTL/target checks | `contract/src/lib.rs:44-125`; `contract/src/authority.rs:100-203`; `evidence/phase1-wrong-agent.json`; `evidence/phase2e/trusted-time.json` |
| Serial success/replay path | `contract/src/lib.rs:158-287`; `contract/src/authority.rs:141-203`; `evidence/phase2e/phase2e-live-proof.json`; `evidence/phase2e/replay.json` |

## Concurrency race

| Required fact | Artifact / limitation |
|---|---|
| Exact incident and target | `research/C-0-race-result.json`; `evidence/phase2-incident-inc-c0-race-1788258001834.json` |
| Authority before | `evidence/phase2-incident-inc-c0-race-1788258001834.json` (`status: ACTIVE`, `uses: 0`, `max_uses: 1`) |
| Exact agent-facing request | Protocol/code evidence: `contract/src/authority.rs:15-18`, `scripts/agent-tool.ts`, and both retained result envelopes. The race runner did not separately retain raw child request bodies; no stronger claim is made. |
| Common launch timing | `research/C-0-race-result.json` (`started_at_unix_ms: 1788258027129`). Separate child start timestamps were not captured. |
| Caller identity | `evidence/phase2-incident-inc-c0-race-1788258001834.json` records the authorized agent DID in the authority; both invocation outputs came from the replacement-agent path. The retained race output has no per-child caller field, so per-call attribution is not independently separable. |
| Both contract results | `research/C-0-race-result.json`, `results[0]` and `results[1]`: each reports `previous_status: EXECUTING`, `current_status: CONSUMED`, `destructive_call_count: 1`, `destructive_call_http_status: 204`, verification GET 404. |
| T3N logs | `evidence/c-0-race-t3n-logs.json`: two time-stamped generic result entries in the race window, both no span ID. They are relevant but not individually attributable. |
| Authority after | `research/C-0-race-result.json` (`uses: 1`, `status: CONSUMED`). |
| Independent GitHub before/after | Before target preflight in `evidence/phase2-incident-inc-c0-race-1788258001834.json`; after exact GET 404/list 200/count 0 in `research/C-0-race-result.json`. |
| Correct wording | Contract-reported: two calls each reported DELETE 204. Independent provider observation: key was absent after. The package does **not** claim GitHub independently observed two DELETE requests. |

## Wrong-DID reconciliation

`research/C-0-wrong-reconcile-result.json` contains: incident before `RECONCILE_REQUIRED`, expected authority DID, different operator caller DID, contract result, provider GET attempt, unchanged/persisted reconciliation state, zero DELETE count, and after state. Code path: `contract/src/lib.rs:85-90,291-354`.

## Precheck liveness

`contract/src/lib.rs:112-155` is CODE-PROVEN: EXECUTING is stored before provider GET, and transport/non-200/malformed responses return without restoring ACTIVE. Existing `evidence/phase1-invocation-reconcile-stuck-execution.json` is supporting live evidence of a stuck reconciliation state, not a fault-injection proof of every branch. No fault injection was rerun for this package.

## Duplicate target authorities

`contract/src/authority.rs:22-71` has no target index; `scripts/incident-create.ts:151-163` checks incident key uniqueness only. `research/C-0-CURRENT-BASELINE.md` and `research/C-0-MATERIAL-UNCERTAINTIES.md` record the resulting DISPROVEN claim. A second destructive experiment was unnecessary and not run.

## Time domain

Contract source: `contract/src/lib.rs:92-94` calls `tenant_context::cluster_timestamp_secs()`. Operator source: `scripts/incident-create.ts:138` calls `trustedNodeTimeSeconds`; implementation: `scripts/product.ts:103-110` reads node HTTP `Date`. Existing live timing artifact: `evidence/phase2e/trusted-time.json`. No artifact samples both values atomically; exact equivalence is PROVEN IMPOSSIBLE / UNAVAILABLE.

## Platform-impossibility proof map

| Claim | Search trail | Result and scope |
|---|---|---|
| No CAS/conditional KV | `contract/wit/world.wit`; `contract/wit/deps/host-interfaces-2.1.0/package.wit`; local SDK `TenantMapsNamespace.entrySet` and `WriteDataInput`; T3N [host API](https://docs.terminal3.io/t3n/how-t3n-works/host-api); current/reference WIT search | No CAS/conditional write in the current BreakGlass world or visible tenant-map write surface. PROVEN IMPOSSIBLE / UNAVAILABLE **for current component world**, not the entire T3N platform. |
| No locks/leases | Same current WIT/SDK search; official host API search; reference contract WIT search | No lock/lease capability exposed to this component. PROVEN IMPOSSIBLE / UNAVAILABLE **for current component world**. |
| No webhook ingress | `contract/wit/world.wit`; all BreakGlass scripts; GitHub webhook docs; reference contract search | No event input/HTTP server/verified delivery path in current product. PROVEN IMPOSSIBLE / UNAVAILABLE **for current BreakGlass**. |
| No in-contract HMAC verification | Current WIT imports; local WIT signing/crypto package search; GitHub HMAC docs | Current component has no event input or signing/crypto import. PROVEN IMPOSSIBLE / UNAVAILABLE **for current component world**. |
| No provider-token minting | `contract/wit/world.wit`; SDK type/export search; GitHub App JWT/installation-token docs; reference WIT search | Current component has no App JWT/token-exchange primitive. PROVEN IMPOSSIBLE / UNAVAILABLE **for current BreakGlass**; external broker remains feasible. |
| No host-audit import | `contract/wit/world.wit`; local host-interface package; SDK `AuditEvent`/`getAuditEvents` search; official host/API docs | SDK declarations exist, but current world does not import audit. PROVEN IMPOSSIBLE / UNAVAILABLE **for current deployed component**. |
| No provider-side atomic DELETE fence | GitHub deploy-key REST docs; current `contract/src/lib.rs:414-435`; live race | GitHub documents 204/404 but no CAS/idempotency key; current code sends ordinary DELETE. PROVEN IMPOSSIBLE / UNAVAILABLE as a documented/provider-enforced fence. |
| No documented deploy-key deletion event | Current official webhook event page and event/action search | Reviewed source documents `deploy_key` creation, not deletion. PROVEN IMPOSSIBLE / UNAVAILABLE as a documented dependency. |

## Material uncertainty register

Full register: `research/C-0-MATERIAL-UNCERTAINTIES.md`. Independent check: 23 material concerns are listed, each with a final status and evidence; material `UNKNOWN` count is zero. The register explicitly retains unavailable platform capability claims rather than relabeling them NON-MATERIAL.

## Competitor evidence

Full commit/file/claim classification: `research/C-0-SOURCE-LEDGER.md` competitor section and `research/C-0-FIELD-MAP.md`. The source ledger records exact checked HEADs and distinguishes code, README, live, and mock evidence for Aegis, Release Sentinel, AgentVault, Proofly, MediPass, Conviction Agent, Credora, and Ethereum-Agentic.

## AgentProof

`Ticoworld/agentproof-t3n@e710ddf`: `README.md`, `docs/BUGS.md`, `docs/FEEDBACK.md`, `docs/WALKTHROUGH.md`, and the repo's contract/test artifacts. Fact: partial flight fulfillment and no real-money loop. Inference: a platform-mechanics proof did not close a judge-visible enterprise job. See `research/C-0-AGENTPROOF-AUTOPSY.md` and source ledger.
