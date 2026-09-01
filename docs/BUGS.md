# BreakGlass Bug Package

These findings come from the live Phase 0 and Phase 1 work. They are classified conservatively and remain separate from the product proof. No unsafe trust bypass was used.

## Finding 1 — SDK 5.3.0 trust-manifest compatibility regression

Classification: **LOCAL COMPATIBILITY FINDING / REPRODUCIBLE SDK COMPATIBILITY ISSUE**

Environment: Terminal 3 testnet, endpoint `https://cn-api.sg.testnet.t3n.terminal3.io/api/trust-manifest`.

The same live HTTP `200` manifest was accepted by exact `@terminal3/t3n-sdk@5.2.0` and rejected by `@terminal3/t3n-sdk@5.3.0`. The observed manifest contained `cluster`, `version`, `peer_ids`, `rtmr3_allowlist`, `signed_at`, and `signature`, but not `rtmr1_allowlist`.

The exact 5.3.0 error was:

```text
Trust manifest at https://cn-api.sg.testnet.t3n.terminal3.io/api/trust-manifest is malformed.
```

Minimal reproduction:

```ts
import { fetchTrustedManifest, setEnvironment } from "@terminal3/t3n-sdk";

setEnvironment("testnet");
await fetchTrustedManifest("testnet");
```

Observed behavior:

```text
5.2.0: accepted; trusted preflight succeeded
5.3.0: rejected; rtmr1_allowlist reported missing
```

The workaround is the exact `5.2.0` pin retained in `package.json` and `package-lock.json`. `unsafe_trust_server` was not used because it disables the attestation check and would invalidate the trust-boundary evidence.

Evidence: `evidence/sdk-5.3.0-state.json`, `evidence/sdk-5.3.0-bug-note.json`, and `evidence/t3n-bootstrap-blocker.json`.

## Finding 2 — `createAgent` / `defaultCard` ownership pitfall

Classification: **DOCUMENTATION / API AMBIGUITY**

The original call was:

```text
createAgent(existingOrganisationDid, name, { defaultCard: false })
```

SDK source inspection showed that explicitly passing `defaultCard: false` selects the no-card wire path. The old agent then appeared outside the organization roster, had no private card, returned `whoami.owner = null`, and could not receive organization egress (`NotAnOrgOwnedAgent`).

The canonical replacement path omitted the option:

```text
createAgent(existingOrganisationDid, "BreakGlass Agent")
```

That replacement became organization-owned, had a readable private card, was funded, and received the exact `api.github.com` egress grant. The evidence also showed an inconsistency between SDK comments about registry persistence for no-card agents. The record therefore does not call this an independent platform bug: the first call explicitly selected the no-card behavior, and the remaining issue is API/documentation ambiguity.

Evidence: `evidence/phase1-agent-provisioning-mismatch.json`, `evidence/phase1-agent-provisioning.json`, `evidence/phase1-replacement-agent-ownership.json`, and `evidence/phase1-replacement-agent-safe-preflight.json`.

## Finding 3 — New organization-owned agents start with zero usable credits

Classification: **OBSERVED TESTNET LIMITATION**

The replacement-agent preflight initially returned `InsufficientCredit` with zero available base units. Terminal 3 then funded the replacement agent. The same safe probe subsequently reached the contract and returned a normal contract-level denial.

This is an observed testnet provisioning limitation, not a claim about an undocumented platform guarantee. New agents should be funded and checked before a metered invocation.

Evidence: `evidence/phase1-replacement-agent-credit-preflight.json` and the preserved earlier blocked credit artifact.

## Finding 4 — Log entries lacked useful span IDs

Classification: **OBSERVED DIAGNOSTIC LIMITATION**

The captured contract log entries reported `span_id_present: false`. The evidence supports that observation for the inspected logs; it does not establish a universal platform defect or prove that no other correlation mechanism exists.

Evidence: `evidence/phase1-logs.json`.

## Reporting standard

The evidence package distinguishes platform behavior, SDK compatibility, API ambiguity, and local observations. No finding is upgraded to a platform bug without a reproducible artifact.
