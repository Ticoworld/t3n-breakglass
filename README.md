# BreakGlass

BreakGlass gives an agent one incident-bound emergency action instead of an administrator credential.

Today the maintained runtime supports one bounded action only: revoking one exact GitHub deploy key after a qualifying, authenticated GitHub push. The runtime is a single-instance, file-backed enterprise remediation service built around Terminal 3 (T3N) contract authority.

## Why

Emergency automation is often given a broad standing credential because responders need to act quickly. That makes the agent, its process, and every failure path a high-value administrator boundary.

BreakGlass narrows that boundary. A trusted operator creates a policy for one exact repository/ref/path transition and one exact deploy-key target. When the authenticated event and immutable source reads qualify, BreakGlass creates one bounded T3N incident. The remediation service can reserve it, but only a confirmed effect broker can obtain temporary GitHub provider authority, and only after the effect has been durably started in T3N.

The agent never receives a GitHub administrator credential, cannot choose another target, and cannot increase the effect budget.

## What T3N enforces

T3N is the remote authority boundary, not just an API wrapper. The C1 contract enforces the principal separation and lifecycle used by the runtime:

- the operator creates and inspects the incident;
- the remediation principal reserves the bounded incident;
- the broker principal claims and confirms effect ownership;
- effect-start must be confirmed before provider authority is released;
- the target and action remain bound to the accepted C1 request;
- terminal closure and reconciliation are recorded remotely.

T3N and GitHub are not one atomic transaction. If the provider outcome becomes ambiguous after effect-start, the runtime uses read-only verification and existing reconciliation semantics. It does not blindly retry the provider mutation.

## The safety boundary

```text
authenticated GitHub event
  -> pre-existing one-shot policy
  -> exact immutable BEFORE/AFTER source reads
  -> causal transition verification
  -> bounded C1 incident
  -> remediation reservation
  -> broker ownership
  -> persisted effect-start
  -> temporary GitHub App permission
  -> exact deploy-key revocation
  -> independent verification
  -> CLOSED / VERIFIED_ABSENT
  -> policy retirement
```

The provider effect has an attempt budget of one. After persisted effect-start, a restart performs no new destructive provider attempt. This is a recovery safety rule, not a claim of exactly-once provider execution.

## Current scope

The maintained runtime is deliberately narrow:

- source: GitHub push delivery with raw-body HMAC authentication;
- repository: `Ticoworld/t3n-breakglass-sandbox`;
- ref: `refs/heads/c2-breakglass-demo`;
- source path: `.breakglass-c2/exposed-deploy-key`;
- causal transition: the exact immutable path changes from the configured BEFORE state to the configured AFTER private-material digest;
- action: `revoke_github_deploy_key`;
- provider target: one policy-bound GitHub deploy-key ID and expected title;
- deployment model: one maintained runtime instance with file-backed state.

There is no generic provider layer, arbitrary GitHub action, second remediation action, dashboard, or horizontally scaled state service.

## What has been proven

Historical live work recorded real GitHub ingress, exact immutable source observations, bounded C1 authority, a confirmed broker, provider-backed deploy-key removal, independent absence verification, terminal closure, and replay observations. Those are claim-level observations from historical artifacts, not a claim that every historical run was a full pass. The final maintained runtime was then hardened through offline adversarial tests for receipts, policy races, crashes, ACL routing, credential separation, leases, and destructive-retry prevention.

## Architecture

```text
GitHub webhook
      |
      v
Coordinator / operator principal
      |
      +--> immutable GitHub App source reader
      +--> policy registry and HMAC receipt store
      +--> T3N create/get-incident
      +--> remediation reservation
      +--> MAC-protected runtime job / broker handoff
                         |
                         v
                   Effect broker
                         |
                         +--> claim / confirm
                         +--> begin-effect / confirm-effect-start
                         +--> JIT GitHub App installation token
                         +--> one DELETE attempt
                         +--> independent verification
                         +--> finalize or reconcile
```

The roles are intentionally distinct:

- Coordinator: authenticates the webhook, consumes validated policy state, reads immutable source content, creates incidents, inspects authoritative C1 state, and retires policies after remote terminal confirmation. It never performs the provider DELETE.
- Remediation agent: an automated bounded service using the remediation DID. It reserves the incident and hands work toward the broker. An LLM is not required for the demonstrated decision.
- Effect broker: uses the broker DID for effect lifecycle calls. It confirms ownership and effect-start before requesting a temporary GitHub App installation token. It never calls operator-only `get-incident`.
- GitHub source reader: uses the GitHub App with `contents:read` for the fixed repository and exact immutable commit/path reads. It revokes its temporary installation token and surfaces cleanup failure.
- Provider verifier: performs same-session and independent read-only checks of the exact deploy-key target.
- T3N C1 contract: remains the remote authority for principal ACLs, ownership, effect-start, terminal state, and reconciliation.

BreakGlass is legitimately an agent product as an automated remediation service. An AI system could choose when to request a bounded remediation, but deterministic policy and contract boundaries own the dangerous target and action. The agent never receives administrator/provider authority and cannot substitute a different target.

## Quick start

### 1. Install and prepare role-specific configuration

Use Node.js 20 or newer and the repository's pinned dependencies:

```powershell
npm install
Copy-Item winner-runtime-coordinator.env.example .env.winner.coordinator
Copy-Item winner-runtime-broker.env.example .env.winner.broker
```

Fill the two copied files with real values locally. Never commit them. Keep them in separate service contexts:

- [`winner-runtime-coordinator.env.example`](winner-runtime-coordinator.env.example) is for the coordinator/operator side.
- [`winner-runtime-broker.env.example`](winner-runtime-broker.env.example) is for the broker side.

Both templates use a process-owned data directory outside the repository and an external state-integrity key file. The coordinator template contains the webhook secret, operator T3N key, and remediation T3N key. The broker supervisor template contains the broker T3N key, provider configuration, and state-integrity key needed to verify MAC-protected local jobs; that key is not passed into the provider-effect child. The GitHub App private key is a standing root credential and must be protected and rotated as an operational secret; temporary installation tokens are minted only downstream of confirmed effect-start.

The fixed GitHub App settings must resolve to `Ticoworld/t3n-breakglass-sandbox`. Do not configure a PAT: the maintained runtime refuses `GITHUB_PAT`.

### 2. Validate without creating state or provider authority

```powershell
npm run breakglass:doctor
```

Doctor loads `.env.winner.coordinator`, checks runtime/configuration shape, distinct DIDs, contract identity/version, fixed source bindings, storage, registry integrity, GitHub App shape, forbidden PAT/proof-barrier settings, and key configuration. It does not create a policy or incident, mint a provider token, mutate GitHub, or call DELETE.

### 3. Create one policy

Create a bounded policy input containing the exact target and principal bindings. The registry supplies activation metadata, registry identity, content hash, and its server-generated provenance record; caller-supplied provenance fields are not trusted. The second argument is an operator-reviewed evidence file whose identity is recorded by the registry.

```powershell
npm run breakglass:policy:create -- .\policy-input.json .\trusted-policy-evidence.json
```

The input file is bounded to the following shape; replace every illustrative value with the operator-reviewed target facts:

```json
{
  "policy_id": "deploy-key-revocation-2026-01",
  "policy_version": 1,
  "action": "revoke_github_deploy_key",
  "deploy_key_id": 123456,
  "expected_deploy_key_title": "breakglass-managed-key",
  "expected_read_only": true,
  "expected_public_key_fingerprint": "SHA256:replace-with-fingerprint",
  "expected_private_material_sha256": "replace-with-64-hex-digit-digest",
  "remediation_agent_did": "did:t3n:replace-with-remediation-did",
  "effect_broker_did": "did:t3n:replace-with-broker-did",
  "ttl_secs": 300
}
```

The input must match the frozen shape, including `policy_id`, `policy_version`, `action`, `deploy_key_id`, `expected_deploy_key_title`, `expected_read_only: true`, the expected public-key fingerprint, the expected private-material SHA-256, the remediation and broker DIDs, and a bounded `ttl_secs` value. Use an operator-reviewed evidence file: the command records its path/hash as registry evidence, but that file alone is not a new proof that the policy predates an original GitHub event timestamp. The command mutates local policy state and enables a future provider action; it does not itself call GitHub DELETE.

### 4. Start the maintained services

Start the coordinator with `.env.winner.coordinator`:

```powershell
npm run breakglass:start
```

It listens on the configured exact webhook route, normally `/c2-b0/github-push`. Start the broker in a separate service context with `.env.winner.broker`:

```powershell
npm run breakglass:broker
```

Both commands are operational and can eventually lead to the bounded provider action, but only after all authentication, immutable source, C1, ownership, effect-start, token, target, and verification gates pass. The broker does not require proof barriers or the historical race harness.

Configure GitHub to deliver the authenticated event to the coordinator route. The maintained runtime does not create GitHub pushes, redeliver webhooks, or generate deploy keys.

### 5. Inspect and retire

Use the coordinator environment for a read-only local summary:

```powershell
npm run breakglass:inspect
```

After the operator-side C1 read confirms the exact bound incident is `CLOSED / VERIFIED_ABSENT`, retire that exact policy/version/incident binding:

```powershell
npm run breakglass:policy:retire -- <policy_id> <policy_version> <incident_id>
```

Retirement mutates the local registry but does not perform a provider action. It is idempotent and does not delete accepted receipts, so an exact accepted duplicate can still replay its frozen C1 request without source reads or current-policy lookup.

## Policy lifecycle and replay

Policies are file-backed, HMAC-protected records. The maintained lifecycle is:

```text
ACTIVE
  | qualifying authenticated event + immutable causal verification
  v
BOUND_TO_EVENT
  | remote C1 CLOSED / VERIFIED_ABSENT
  v
RETIRED
```

A repository/ref match alone does not consume a policy. A nonqualifying source transition leaves it available. Once an eligible event binds the policy, another distinct event cannot obtain authority from it, including during the close-to-retire window. A crash cannot revert `BOUND_TO_EVENT` to `ACTIVE`.

Accepted delivery receipts use schema v3 and HMAC domain separation. They bind the exact delivery ID as a string, raw-body digest, event identity, policy/version and registry commitment, event binding, exact C1 create request, target, principals, action, and incident identity. Accepted authority is immutable. Legacy unkeyed receipts fail closed.

For an exact authenticated duplicate, the runtime verifies the receipt and returns the stored C1 request. It performs zero source reads, zero current-policy selection, and zero authority rederivation. A conflicting payload digest is refused.

## Recovery rules

The coordinator owns authoritative C1 inspection using the operator principal. Local jobs are MAC-protected operational state; remote C1 state dominates when the two disagree. On restart, the coordinator uses the exact accepted request and incident identity rather than rebuilding authority from current policy.

The important rule is:

> After persisted effect-start, never manually retry the provider DELETE.

Use `npm run breakglass:inspect`, operator-side remote inspection, and read-only verification/reconciliation. Do not infer that a provider action did not happen merely because a local result file is missing. If C1 is ambiguous or contradictory, stop automatic provider mutation and require operator review.

The full recovery matrix and stop/escalation procedure is in [`winner/HANDOVER.md`](winner/HANDOVER.md).

## Credential boundaries

| Process | Receives | Must not receive |
| --- | --- | --- |
| Coordinator | operator T3N key, remediation T3N key, webhook secret, state-integrity key, GitHub App source-read configuration | broker T3N key; provider DELETE capability |
| Remediation service | remediation T3N key and bounded incident input | operator key, GitHub App private key, provider token, target/action substitution |
| Broker supervisor | broker T3N key, provider configuration, state-integrity key for HMAC-protected local job access | operator T3N key, remediation key, webhook secret, PAT |
| Broker effect child | explicit broker/provider allowlist and fixed identifiers | operator/remediation keys, webhook secret, state-integrity key, PAT, proof barriers, evidence paths, unrelated parent secrets |

`C1_OPERATOR_DID` in broker configuration is an identifier used to derive the contract name, not an authentication credential. The GitHub App private key remains a standing root credential; the installation token is temporary and revoked. There are standing credentials in the deployment, but the dangerous provider capability is released only after the C1 effect-start boundary.

## Evidence: live proof versus offline hardening

Historical evidence is preserved under [`winner/evidence/`](winner/evidence/). It supports individual observed claims, including authenticated ingress, immutable source transition, bounded C1 request shape, provider-backed deploy-key removal, independent absence verification, terminal closure, and replay observations.

The historical classifications remain failures where recorded:

- [`C2-E2E-R2-FAILURE.json`](winner/evidence/C2-E2E-R2-FAILURE.json) remains `C2_E2E_R2_FAIL_BROKER_OWNER_EVIDENCE_ADJUDICATION`.
- [`C2-E2E-R2A-HISTORICAL-ADJUDICATION.json`](winner/evidence/C2-E2E-R2A-HISTORICAL-ADJUDICATION.json) records the adjudication and does not promote R2 to a pass.
- [`C2-E2E-R2B-R2-FAILURE.json`](winner/evidence/C2-E2E-R2B-R2-FAILURE.json) remains historical failure evidence.
- [`C2-E2E-R2B-R3-CLOSED-REPLAY.json`](winner/evidence/C2-E2E-R2B-R3-CLOSED-REPLAY.json) does not turn the historical R3 run into a full pass.

The maintained runtime was subsequently hardened offline. The offline work covers HMAC authority receipts, one-shot policy binding, crash/restart handling, remote-state dominance, faithful C1 ACL routing, broker environment isolation, heartbeat leases, and production-path adversarial tests. It must not be described as if the historical live R2 or R3 run executed this final runtime unchanged. There is no new live proof classification here.

Evidence navigation:

| Claim | Evidence type | Artifact |
| --- | --- | --- |
| authenticated GitHub ingress | historical live artifact | [C2-B0 live ingress delivery](winner/evidence/C2-B0-LIVE-INGRESS-DELIVERY.json) |
| exact immutable BEFORE/AFTER source observations | historical source-freeze artifact | [C2-A-R2 push source freeze](winner/evidence/C2-A-R2-PUSH-SOURCE-FREEZE.json) |
| provider-backed deploy-key effect and independent absence | historical live C1/provider artifact | [C1-R6B-R4E-R1 provider proof](winner/evidence/C1-R6B-R4E-R1-PROVIDER-PROOF.json) |
| duplicate and closed-replay observations | historical failure artifacts supporting individual claims only | [C2-E2E-R2B-R3 closed replay](winner/evidence/C2-E2E-R2B-R3-CLOSED-REPLAY.json) |
| maintained-runtime receipt, policy, recovery, broker, and source-reader hardening | offline production-path tests | [`winner/tests/w1-*.test.ts`](winner/tests) |

Read each artifact's own claims and limitations. The R2/R3 classifications above remain failures.

## Tests and build

The maintained offline gates are:

```powershell
npm run winner:test
npm test
node --import tsx --test --test-concurrency=1 winner/tests/c2-push-ingress.test.ts
cargo test --manifest-path winner/contract/Cargo.toml --offline
npm run winner:build
```

They cover authority tampering, canonical state, one-shot policy races, nonqualifying events, duplicate replay, crash/restart recovery, broker contention, C1 ACL boundaries, provider-token gating, effect-start ambiguity, lease safety, and destructive-retry prevention. They do not contact live GitHub/T3N providers.

`winner:build` builds the maintained Rust/WASM C1 contract. The contract remains version `2.0.4`; the W2 documentation change does not alter or redeploy it.

## Maintainer handoff

Start with [`winner/HANDOVER.md`](winner/HANDOVER.md). It describes boot, stop, inspection, recovery, backups, rotation, storage, escalation, and the single-instance boundary. Known limitations and resolved historical defects are in [`winner/BUGS.md`](winner/BUGS.md).

The frozen runtime is at commit `d26934f52d5fdf84fd0ec5b0d9176dcf54407b96` on `winner-v2-core`. The repository, role-specific environment templates, runtime commands, MAC-protected state model, recovery rules, offline suites, historical evidence, and limitations are the handover surface. The developer is willing to continue maintaining BreakGlass after the challenge while keeping that surface transferable to Terminal 3 or another maintainer; this is not a promise of indefinite unpaid support.

## Historical proof and legacy tooling

The root also contains earlier Phase2E/bootstrap/agent scripts. They are retained as historical or legacy tooling and are not the maintained winner workflow. In particular, do not use these as the runtime quick start:

```text
npm run demo
npm run setup-github
npm run bootstrap
npm run incident:create
npm run agent
npm run agent:execute
```

Some legacy/setup commands can create or mutate external resources. They are not required for the maintained W1 runtime and are intentionally not hidden behind the winner command surface.

## Remit / Sluice

BreakGlass closes the operational job at the narrowest useful boundary: one documented, runnable, recoverable GitHub deploy-key remediation path with incident-bound authority. It does not expand into a dashboard, generic SDK, distributed queue, second provider, or feature catalogue.
