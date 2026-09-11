# BreakGlass maintainer handover

This document describes the maintained single-instance runtime frozen at `d26934f52d5fdf84fd0ec5b0d9176dcf54407b96` on `winner-v2-core`.

The supported product path is GitHub push ingress followed by one bounded T3N incident and one exact GitHub deploy-key revocation. Historical proof runners are not part of this operating procedure.

## Start

1. Install the pinned dependencies with `npm install`.
2. Copy [`winner-runtime-coordinator.env.example`](../winner-runtime-coordinator.env.example) to `.env.winner.coordinator` and [`winner-runtime-broker.env.example`](../winner-runtime-broker.env.example) to `.env.winner.broker`.
3. Put real secrets in protected external locations. The data directory must be outside the repository and outside the operating-system temporary directory. The coordinator and broker supervisor load the state-integrity key from `BREAKGLASS_STATE_INTEGRITY_KEY_FILE` to verify their local MAC-protected state; the broker supervisor does not pass that key to the provider-effect child.
4. Configure the exact fixed GitHub App repository and installation. The current source binding is `Ticoworld/t3n-breakglass-sandbox`, `refs/heads/c2-breakglass-demo`, `.breakglass-c2/exposed-deploy-key`.
5. Confirm that the operator, remediation, and broker DIDs are distinct. The operator T3N key must resolve to `C1_OPERATOR_DID`.
6. Run the non-destructive doctor:

   ```powershell
   npm run breakglass:doctor
   ```

7. Create one bounded policy with the coordinator environment. Policy creation is an explicit local mutation and requires an input file plus an operator-reviewed evidence file:

   ```powershell
   npm run breakglass:policy:create -- .\policy-input.json .\trusted-policy-evidence.json
   ```

   The registry creates trusted activation metadata and refuses duplicate identity/version. Use an operator-reviewed evidence file; its recorded identity does not, by itself, prove that the policy predates an original GitHub event timestamp. Do not treat arbitrary caller-supplied provenance or enabled fields as registry truth.

8. Start the coordinator in one service context:

   ```powershell
   npm run breakglass:start
   ```

9. Start the broker in a separate service context:

   ```powershell
   npm run breakglass:broker
   ```

The coordinator receives the GitHub webhook at the configured exact route, normally `/c2-b0/github-push`. The broker is a normal worker; it does not need `C1_BARRIER_FILE`, proposal-complete files, release files, or evidence fixtures.

## Stop

Send SIGINT or SIGTERM to each maintained process and allow its shutdown handler to run. In a terminal, `Ctrl+C` is the normal coordinator/broker stop action. Do not use a proof-runner stop/release file.

If a process dies unexpectedly, do not manually repeat a provider mutation. Restart the relevant service and inspect the durable state and authoritative C1 state first.

## Inspect

The read-only local inspection command is:

```powershell
npm run breakglass:inspect
```

It loads and verifies HMAC-protected policy, retirement, receipt, and job records and prints operational identifiers and states. It does not create incidents, read mutable GitHub branch HEAD, mint provider credentials, or issue DELETE.

Authoritative incident state belongs to operator-side T3N `get-incident`. The effect broker does not call that operator-only endpoint. When local state and remote state disagree, remote C1 safety state wins; if it cannot be read or is contradictory, stop automatic provider work and treat the job as `STATE_CONFLICT`.

## Normal event path

For a new delivery, the coordinator:

1. authenticates the raw request body and exact delivery identity;
2. checks the durable receipt before doing source reads;
3. selects a validated active policy from the registry;
4. reads exact BEFORE and AFTER commits at the exact bound path with the GitHub App `contents:read` permission;
5. verifies the existing causal transition;
6. atomically binds the qualifying event to the one-shot policy;
7. persists the exact HMAC-protected C1 create request;
8. creates the one incident and reserves it through the remediation principal;
9. performs operator-side remote inspection and creates a MAC-protected broker handoff.

The broker then uses only broker-authorized C1 lifecycle calls: claim, confirm claim, begin effect, confirm effect-start, finalize, or reconcile. It requests temporary GitHub App authority only after confirmed effect-start, checks the fixed target, makes at most one DELETE attempt, verifies independently, revokes temporary authority, and records the result.

## Recovery matrix

| Remote C1 state | Maintained action | Provider mutation |
| --- | --- | --- |
| `ACTIVE` | Broker does nothing. Coordinator may resume the remediation reservation using the remediation principal. | None |
| `RESERVED` | Operator creates a normal broker handoff. Broker claims and confirms ownership through C1. | Only after confirmed effect-start |
| `READY_RETRY` | Start normal broker claim processing if the existing C1 semantics allow it. C1 decides whether the claim wins. | Only after confirmed effect-start |
| `EFFECT_CLAIMED` | Pass the exact remote claim ID/version. Broker confirms that exact claim before continuing. | None until the exact claim is confirmed and effect-start is confirmed |
| `EFFECT_STARTED` | Enter effect recovery. Use exact claim/effect-start identities for read-only verification and allowed reconciliation. | No new DELETE |
| `RECONCILE_REQUIRED` | Run read-only provider verification and existing `reconcile-effect` semantics. | No DELETE |
| `FAILED` | Follow existing C1 reconciliation rules only. Do not infer that a provider action did not happen. | No new DELETE |
| `CLOSED` | Do not launch a broker. The coordinator may retire the exact policy only after `CLOSED / VERIFIED_ABSENT`. | None |
| `EXPIRED` | Fail closed and require operator review according to the incident state. | None |
| `STATE_CONFLICT` | Stop automatic work. Re-read remote state with the operator principal and investigate MAC-protected local state. | None |
| `LEASE_OWNER_AMBIGUOUS` | Do not reclaim automatically. Require operator review or a later safe resolution. | None |

The broker receives an operator-side snapshot as routing input, not provider authority. A stale snapshot cannot unlock the provider: the broker must still win the live C1 claim/confirmation/effect-start sequence.

## Critical effect-start rule

> After persisted effect-start, never manually retry the provider DELETE.

This remains true after crashes immediately before token mint, after token mint, before request transmission, after request transmission with no response, after a DELETE response, during verification, before finalization, or during reconciliation. Treat the provider outcome as potentially attempted. Use read-only verification and the existing C1 reconciliation path. The runtime's claim is zero *additional automated destructive attempts after persisted effect-start*, not atomic exactly-once provider execution.

## Replay and policy retirement

An accepted receipt is the frozen event-to-authority decision. It is schema v3, HMAC-protected, and contains the exact C1 create request. An exact duplicate verifies that receipt and reuses the stored request with zero source reads, zero current-policy selection, and zero authority rederivation. Retirement does not delete receipts.

The policy state machine is:

```text
ACTIVE -> BOUND_TO_EVENT -> RETIRED
```

Binding happens only after immutable source verification has classified the event as the existing causal transition. Once bound, a distinct event cannot use that policy, even if the retirement tombstone has not yet been written. Automatic retirement requires an operator-authorized remote read confirming the exact incident is `CLOSED` with `VERIFIED_ABSENT`. Retirement is idempotent and automatic backward transitions do not exist.

## State storage

With `BREAKGLASS_DATA_DIRECTORY=<root>`, the runtime uses:

| Directory | Contents | Handling |
| --- | --- | --- |
| `policies/` | HMAC-protected registry records and server-generated activation metadata | durable authority; back up |
| `bindings/` | exclusive one-shot policy/event bindings | durable authority; back up |
| `retirements/` | irreversible retirement tombstones | durable authority; back up |
| `receipts/` | schema v3 delivery reservations, decisions, and accepted exact C1 requests | durable replay authority; back up |
| `jobs/` | HMAC-protected runtime jobs, remote-state observations, handoff IDs, claims, leases, and recovery metadata | durable recovery state; back up |
| `results/` | broker result/diagnostic files | useful audit output; back up if audit retention requires it |

Directories are created with restrictive permissions where the platform supports them. Corrupt or legacy records fail closed. The runtime refuses repository, filesystem-root, and operating-system temporary-directory data roots.

This is intentionally a single-instance filesystem deployment. The files are not a distributed lock service and the product does not claim horizontal scaling, multi-region failover, or global mutual exclusion.

## Backups

Back up `policies/`, `bindings/`, `retirements/`, `receipts/`, and `jobs/` together, preserving file ownership and permissions. Retain `results/` if operational audit needs it. Back up the state-integrity key and GitHub App private key through the organization's secret-management process, separately from runtime state. Do not put either secret in Git or in a backup that is readable as ordinary application data.

Restoring only part of the state tree can create an integrity or recovery conflict. Restore the complete consistent snapshot, then run doctor and inspect before resuming services.

## Credential rotation

- T3N operator, remediation, and broker credentials: rotate independently, update only the role that uses each credential, and verify the DID still matches the configured principal.
- `C2_WEBHOOK_SECRET`: rotate at the GitHub webhook and coordinator together during a controlled maintenance window. A mismatch rejects deliveries.
- GitHub App private key: rotate as a standing root credential, update the coordinator/broker secret path as required, and verify the installation and fixed repository binding. Installation tokens remain temporary and are revoked.
- State-integrity key: set a new current `BREAKGLASS_STATE_INTEGRITY_KEY_ID` and key file. During a controlled transition, configure old `key_id=path` entries in `BREAKGLASS_STATE_INTEGRITY_VERIFY_KEYS` as verify-only. New records use the current key; old keys cannot authenticate new state. There is no automatic legacy receipt migration. Remove the old verify-only key after an explicitly reviewed migration/retention decision.

Never log, copy into a broker child environment, or serialize any of these secrets into a receipt, job, result, or error payload.

## Failure escalation

Stop automatic processing and require operator review when:

- doctor reports missing, malformed, or mixed-role configuration;
- a receipt, policy, binding, retirement, or job MAC fails;
- state is legacy, corrupt, contradictory, or cannot be read;
- remote C1 state is unavailable or does not match the frozen incident authority;
- a lease is expired but its owner PID is alive or ambiguous;
- C1 reports `EFFECT_STARTED`, `RECONCILE_REQUIRED`, or an ambiguous provider outcome;
- the exact remote terminal incident cannot be confirmed before retirement;
- the GitHub verifier cannot establish the target's absence.

In these cases, use operator-side remote inspection and read-only verification. Do not create a replacement incident, rebind a policy, change the target, or retry DELETE manually.

## Command reference

| Command | Environment | State/action | Safe classification |
| --- | --- | --- | --- |
| `npm run winner:build` | none | builds the winner C1 contract | offline build; no runtime/provider effect |
| `npm run winner:test` | test fixtures | runs maintained offline W1 suites | offline; no external effect |
| `npm run breakglass:doctor` | `.env.winner.coordinator` | validates configuration and storage | non-destructive/read-only |
| `npm run breakglass:policy:create -- <input> <evidence>` | `.env.winner.coordinator` | creates active registry policy | local mutation; can enable later provider action |
| `npm run breakglass:start` | `.env.winner.coordinator` | runs webhook coordinator | operational; can eventually lead to provider action |
| `npm run breakglass:broker` | `.env.winner.broker` | runs production broker worker | operational; can eventually lead to provider action |
| `npm run breakglass:inspect` | `.env.winner.coordinator` | reads HMAC-protected local state | read-only |
| `npm run breakglass:policy:retire -- <id> <version> <incident>` | `.env.winner.coordinator` | writes retirement tombstone after remote check | local mutation; no provider DELETE |

The old root `demo`, bootstrap, setup, incident, and agent commands are historical/legacy tools. Do not use them as the maintained winner start path.
