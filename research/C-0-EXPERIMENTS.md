# C-0 Falsification Experiments and Results

Date: 2026-09-01. Destructive live work used only a newly created read-only deploy key in the private sandbox repository `Ticoworld/t3n-breakglass-sandbox`; no public main was changed and no secret was printed.

## Completed experiments

| Question | Experiment | Pass/fail criterion | Result | Decision unlocked | Risk |
|---|---|---|---|---|---|
| Can simultaneous invokes duplicate the destructive request? | Create fresh disposable key/incident; launch two child invocations at the same time; capture both outputs and independent GET/list after. | PASS means max one destructive request; FAIL means both issue destructive path. | **FAIL.** Both callers reported `destructive_call_count: 1`, HTTP 204, previous EXECUTING, final CONSUMED; final key absent. | Current at-most-one claim is retired. Any next design needs reservation/fencing outside current plain KV state. | Destructive only to disposable read-only key; before/after captured in `evidence/phase2-incident-inc-c0-race-1788258001834.json`. LIVE-EVIDENCE-PROVEN |
| Can wrong DID invoke reconciliation? | Invoke pre-existing `RECONCILE_REQUIRED` incident with operator DID rather than expected agent DID; inspect provider request and state. | PASS means denial before provider GET/state write; FAIL means reconciliation path runs. | **FAIL.** Provider GET path ran and state remained/persisted RECONCILE_REQUIRED; no DELETE was requested. | Read/state mutation authority must be separately caller-bound. | Non-destructive provider GET; artifact `research/C-0-wrong-reconcile-result.json`. LIVE-EVIDENCE-PROVEN |

## Closed by code (no live mutation needed)

| Question | Smallest check | Result | Evidence |
|---|---|---|---|
| Does precheck failure strand state? | Trace `begin_execution` persistence and every precheck return. | **FAIL.** All transport/non-200/malformed branches return after EXECUTING is stored. | `contract/src/lib.rs:112-155`. CODE-PROVEN |
| Are duplicate target authorities rejected? | Search authority schema/map writes for target index or conditional target check. | **FAIL.** None exists; only incident ID is checked. | `contract/src/authority.rs`, `scripts/incident-create.ts`. CODE-PROVEN |
| Is reconcile caller-authenticated? | Trace branch ordering. | **FAIL.** Reconciliation dispatch precedes caller DID/time validation. | `contract/src/lib.rs:85-90`. CODE-PROVEN |
| Does current contract use host audit/crypto/CAS? | Inspect exact WIT world and SDK method available to component. | **FAIL / UNAVAILABLE.** Current world lacks those imports; SDK declarations alone do not expand WIT. | `contract/wit/world.wit`; SDK `index.d.ts`. CODE-PROVEN |

## Experiments required before a future implementation claim

These are not parked C-0 unknowns; each is a gated validation for a later design whose premise is now explicit.

1. **Exact T3N audit binding:** non-destructively invoke a test contract that writes a host audit event, then retrieve activity/audit by sequence/hash and compare actor, function, request hash, and outcome. Pass requires an independently retrievable host record; fail retires “receipt” claims.
2. **GitHub App JIT path:** in a fresh private installation, sign a short-lived App JWT, mint an installation token restricted to one repository and Administration write, delete a disposable key, explicitly revoke the installation token, and prove a second call fails. Pass requires no PAT and before/after token scope evidence.
3. **Webhook authenticity gateway:** capture raw GitHub delivery, validate HMAC and delivery dedupe, commit only the hash/metadata to T3N, then replay/alter body. Pass requires duplicate/altered delivery cannot create a second authority.
4. **Authority reservation:** if T3N exposes a candidate conditional/nonce mechanism in a later version, run two concurrent calls and require one reservation winner before any provider DELETE. Pass requires one invocation to fail before outbound DELETE.
5. **Post-effect ambiguity:** deliberately drop the provider response after a disposable delete and distinguish no-request/unknown-request/verified-absent with a receipt. Pass requires no blind retry and deterministic human/escalation state.

Each experiment is destructive only where explicitly marked as disposable-provider testing; all other tests are non-destructive.
