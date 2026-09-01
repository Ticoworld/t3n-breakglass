# BreakGlass Bug Package

These findings are preserved from the live Phase 0/Phase 1 work. They are not replaced by unit tests or hidden by the Phase 2 product layer.

## BUG 1 — SDK 5.3.0 trust-manifest regression

The same live testnet trust manifest was accepted by exact SDK 5.2.0 and rejected by SDK 5.3.0. The manifest returned HTTP 200 but contained `cluster`, `version`, `peer_ids`, `rtmr3_allowlist`, `signed_at`, and `signature`; 5.3.0 newly required `rtmr1_allowlist` and failed with a malformed-manifest error.

The project remains pinned to `@terminal3/t3n-sdk@5.2.0`. `unsafe_trust_server` was not used because bypassing attestation would invalidate the trust-boundary proof.

Evidence: `evidence/sdk-5.3.0-state.json`, `evidence/sdk-5.3.0-bug-note.json`, and `evidence/t3n-bootstrap-blocker.json`.

## BUG 2 — `createAgent` no-card / organization-ownership pitfall

Observed behavior and interpretation:

- The original call explicitly used `createAgent(existingOrganisationDid, name, { defaultCard: false })`.
- SDK source inspection showed that the explicit false option selects the no-card wire path.
- The resulting old agent was absent from the organization roster, had no private card, returned `whoami.owner=null`, and could not receive organization egress (`NotAnOrgOwnedAgent`).
- This is primarily API misuse or documentation ambiguity, not proof of an independent platform defect.
- The repair used exactly one replacement through the default-card path with no options. The replacement DID is organization-owned, has a readable private card, is funded, and has the exact egress grant.

Evidence: `evidence/phase1-agent-provisioning-mismatch.json`, `evidence/phase1-agent-provisioning.json`, `evidence/phase1-replacement-agent-ownership.json`, and `evidence/phase1-replacement-agent-safe-preflight.json`.

## BUG 3 — New organization-owned agents begin with zero usable credits

The initial replacement-agent credit preflight returned `InsufficientCredit` with zero available base units. Terminal 3 funding was required before a metered stateless invoke could proceed. After funding, the same preflight reached HTTP 200 and returned a contract-level denial.

This is recorded as an observed platform limitation unless Terminal 3 documentation explicitly guarantees initial agent funding.

Evidence: `evidence/phase1-replacement-agent-credit-preflight.json` and the earlier blocked artifact retained in the evidence directory.

## Additional observed limitations

- Current T3N contract log entries do not carry span IDs, although the Phase 1 log messages were sanitized and contained no likely secret pattern.
- The operator wrapper requires a configured GitHub deploy-key ID for a safe target check; when it is absent, doctor reports a warning instead of guessing.
