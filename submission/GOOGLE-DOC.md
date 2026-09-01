# BreakGlass

## One-sentence pitch

BreakGlass gives an AI agent incident-bound authority to perform one exact emergency operation without giving the agent the underlying administrative credential.

## Problem

An incident may require a dangerous administrative action immediately, but giving an AI agent a standing GitHub administrator credential makes target substitution, replay, credential theft, and prompt injection much more damaging. A human approval step alone does not create a machine-enforced, one-use authority with a frozen target.

## What BreakGlass does

A trusted operator creates a private Incident Authority containing the authorized agent, one fixed action, one exact GitHub deploy-key target, a short expiry, and `max_uses = 1`. The agent receives only the incident ID. Terminal 3 resolves the private authority, checks caller identity and time, uses a sealed GitHub PAT inside the Rust/WASM contract, performs the exact revocation, verifies the key is absent, consumes the authority, and refuses replay.

The only destructive action in this submission is `revoke_github_deploy_key`.

## Why Terminal 3

Terminal 3 supplies the separate agent DID, organization ownership, scoped egress, private incident state, trusted time, sealed credential, Rust/WASM execution, external HTTP call, authoritative verification, and durable one-use state. The agent does not hold the PAT, target, action, expiry, or max-uses policy.

## Live proof

Canonical Phase 2E run:

```text
Agent:    did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019
Incident: INC-PHASE2E-LIVE-1788249253449
Target:   Ticoworld/t3n-breakglass-sandbox#161921323
```

The real live sequence was:

```text
GitHub before: independent GET 200; target present and read-only
Authority: ACTIVE, 0/1
Agent request: incident_id only
T3N result: DELETE 204, exactly once
T3N result: authoritative verification GET 404
GitHub after: independent GET 404; target absent
Authority: CONSUMED, 1/1
Replay: REPLAY_REFUSED; destructive calls 0
```

The DELETE and internal verification statuses are explicitly classified as T3N-contract-reported external HTTP results. The before and after reads are independent GitHub verification. The complete sanitized artifact is `evidence/phase2e/phase2e-live-proof.json`.

## Architecture

```text
Trusted Operator
  -> private Incident Authority
  -> separate organization-owned Agent
  -> execute-incident Rust/WASM contract
  -> sealed GitHub PAT
  -> api.github.com DELETE
  -> authoritative GET
  -> CONSUMED
```

## Security and adversarial tests

The agent surface accepts only `incident_id`, rejects extra target/action fields, exposes no operator creation tool, and cannot widen the authority. Rust tests cover nonexistent incidents, wrong agents, expiry, replay, ambiguous outcomes, reconciliation, state transitions, and authority-loaded targets. Product tests pass 6/6 and Rust tests pass 11/11. A repository-wide audit found no credential values or private-key markers in tracked or untracked non-ignored files.

## How to run

The repository requires Node.js, Rust/WASI tooling, a Terminal 3 testnet operator credential, a funded organization-owned replacement agent, and a restricted GitHub PAT. Copy `.env.example` to the ignored operator environment and configure the separately ignored replacement-agent environment. Keep the exact `@terminal3/t3n-sdk@5.2.0` pin.

```powershell
npm install
npm run doctor
npm test
npm run build
npm run incident:create -- INC-1043 Ticoworld t3n-breakglass-sandbox 123456 300
npm run agent
npm run demo
```

The demo is live and destructive to its disposable target. Newly provisioned agents may require Terminal 3 test credits.

## Maintainability and handover

I’m happy to continue developing BreakGlass after the challenge. The current implementation is deliberately limited to one proven emergency action, and the repository includes a handover guide for Terminal 3 or another maintainer if ownership needs to transfer.

A future action should have a separate schema, fixed least-privileged egress, sealed secret, independent verification, one-use state transition, reconciliation behavior, adversarial tests, and fresh disposable live evidence. It should not widen the agent input.

## Bugs and developer feedback

- SDK 5.3.0 rejects the same live trust manifest accepted by 5.2.0 because `rtmr1_allowlist` is missing. This is preserved as a reproducible local compatibility finding; `unsafe_trust_server` was not used.
- The original `createAgent(..., { defaultCard: false })` path produced the no-card ownership pitfall. This is classified as documentation/API ambiguity, not a confirmed platform bug.
- New organization-owned agents initially had zero usable credits. This is an observed testnet limitation requiring Terminal 3 funding.
- Captured T3N log entries lacked useful span IDs. This is an observed diagnostic limitation for the inspected logs.

## Public links

- Public GitHub repository: https://github.com/Ticoworld/t3n-breakglass
- Public Google Doc: `[PUBLIC_GOOGLE_DOC_URL]`
- Contact/social: `[CONTACT_OR_SOCIAL_LINK]`

## Screenshots

- `[SCREENSHOT_1_README_HERO]`
- `[SCREENSHOT_2_AUTHORITY_PREVIEW]`
- `[SCREENSHOT_3_EXECUTION]`
- `[SCREENSHOT_4_GITHUB_VERIFICATION]`
- `[SCREENSHOT_5_REPLAY]`
- `[SCREENSHOT_6_T3N_AGENT]`
