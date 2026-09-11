# BreakGlass bugs and limitations

This is an honest maintenance record for the frozen winner runtime. Historical defects remain useful evidence of why the current boundaries exist; they are not silently rewritten into successes.

## Historical provider-boundary weakness

**Symptom:** Earlier experiments could demonstrate a provider effect without the complete C1 ownership/effect-start boundary needed to make concurrent remediation safe.

**Root cause:** Provider authority was not always downstream of a contract-confirmed owner and persisted effect-start.

**Impact:** A concurrent or crashed runner could not be evaluated using the strong boundary now required for a maintained dangerous action.

**Discovered by:** Review of the early concurrent provider/effect proof path before the C1 ownership model was frozen.

**Current status:** The C1 contract and maintained broker require claim confirmation and confirmed effect-start before temporary GitHub authority. The effect attempt budget remains one, and post-effect-start recovery is read-only. Historical evidence remains historical.

## GitHub delivery ID precision

**Symptom:** Treating a GitHub delivery ID as a JavaScript number can lose digits and merge distinct deliveries.

**Root cause:** JavaScript numeric coercion is not safe for arbitrary long delivery identifiers.

**Impact:** Dedupe identity and replay decisions could be applied to the wrong delivery.

**Discovered by:** Lossless-delivery review and regression tests around historical C2 webhook identities.

**Current status:** The maintained ingress preserves the delivery ID as an exact string, binds it to the raw-body digest, and stores it in HMAC-protected receipt/binding state. Do not coerce it to a number in new tooling.

## Historical broker evidence adjudication

**Symptom:** The old broker evidence adjudicator required loser confirmation in a way that did not match the intended early-loss contract evidence.

**Root cause:** Proof-harness adjudication overreached beyond the contract observation required for the race.

**Impact:** The historical R2 run remains a failure classification even though individual artifacts can support narrower observed claims.

**Discovered by:** Independent adjudication of the historical R2 broker evidence.

**Current status:** The maintained runtime does not use that adjudicator as production orchestration. The historical artifact [`C2-E2E-R2A-HISTORICAL-ADJUDICATION.json`](evidence/C2-E2E-R2A-HISTORICAL-ADJUDICATION.json) is preserved and must not be relabeled as a full R2 pass.

## Historical duplicate/redelivery behavior

**Symptom:** Earlier C2/redelivery paths did not provide the final maintained receipt semantics for every duplicate and conflicting payload case.

**Root cause:** Durable delivery identity and authority persistence evolved across the proof runs.

**Impact:** A redelivery could not always be described as a safe, authority-free replay of the accepted decision.

**Discovered by:** Historical C2 R2/R2B replay analysis and duplicate-delivery tests.

**Current status:** The maintained runtime authenticates raw bytes before processing, uses exact string delivery identity, HMAC-protects schema-v3 receipts, refuses conflicting digests, and replays an accepted receipt without source reads or authority rederivation. This hardening was tested offline; it does not rewrite old live evidence.

## W1 accepted-receipt tampering defect

**Symptom:** An accepted local receipt could be structurally valid while its authority-bearing fields were changed after acceptance.

**Root cause:** Structural JSON validation alone did not authenticate the accepted authority record.

**Impact:** A process with the ability to edit local state could change the stored C1 request unless an external integrity boundary detected it.

**Discovered by:** W1 independent verification through direct accepted-receipt field tampering.

**Current status:** W1-R2 added canonical HMAC envelopes with `breakglass.receipt.v3`, exact C1 request binding, strict legacy refusal, and fail-closed tamper detection. This protects the stated local state-integrity threat model, not a full host/root compromise where the key and runtime can both be replaced.

## W1 close-to-retire race

**Symptom:** A policy could remain locally active between successful C1 closure and persistence of its retirement record.

**Root cause:** Retirement was initially the only durable signal preventing reuse.

**Impact:** A second distinct qualifying event could have selected the policy in that window.

**Discovered by:** W1-R1 close-to-retire race analysis between remote C1 closure and local retirement persistence.

**Current status:** The maintained lifecycle binds a policy atomically to the first event only after immutable causal verification: `ACTIVE -> BOUND_TO_EVENT -> RETIRED`. `BOUND_TO_EVENT` blocks distinct events even before the remote-terminal retirement tombstone is written. Retirement additionally requires operator-side remote `CLOSED / VERIFIED_ABSENT`.

## W1 broker/operator ACL mismatch

**Symptom:** A first maintained broker path attempted operator-only `get-incident` using the broker principal.

**Root cause:** Local recovery orchestration was incorrectly placed inside the effect broker.

**Impact:** The real C1 ACL correctly denied the broker, so normal production completion was impossible under faithful permissions.

**Discovered by:** W1-R2-FIX faithful ACL testing with operator `get-incident` allowed and broker `get-incident` denied.

**Current status:** The coordinator/recovery controller performs operator-side remote inspection. The broker receives a bounded handoff and uses only broker-authorized lifecycle calls. The broker never requires `get-incident`; stale handoffs are still checked by live C1 transitions.

## Single-instance filesystem state

**Symptom:** Policies, receipts, jobs, leases, and results live in one process-owned filesystem tree.

**Root cause:** The product boundary is deliberately a maintained single-instance runtime rather than a distributed platform.

**Impact:** This is not a horizontally scalable or multi-region deployment. Filesystem availability, permissions, complete backups, and host recovery matter.

**Discovered by:** W0 operability audit and W1 restart/lease design review.

**Current status:** Atomic exclusive creation, HMAC integrity, heartbeat leases, fail-closed corruption handling, and remote C1 dominance are implemented for the single-host/single-instance scope. Do not add a second instance or shared filesystem and assume it is safe without a separately reviewed distributed design.

## Ambiguous provider outcomes are not atomically resolved

**Symptom:** T3N effect-start and a GitHub DELETE cannot be one atomic transaction across two systems.

**Root cause:** The provider call and C1 state transition are separate external operations.

**Impact:** A crash or lost response can leave the provider outcome unknown.

**Discovered by:** C1 effect-start crash and provider ambiguity analysis.

**Current status:** Persisted effect-start prevents a new automated DELETE attempt. Recovery verifies the provider read-only and uses C1 reconciliation. The runtime does not claim exactly-once provider execution or atomic T3N/GitHub commit.

## GitHub App private key is a standing root

**Symptom:** The GitHub App private key must remain available to the source reader and broker so they can mint scoped installation tokens.

**Root cause:** Token minting requires the App's signing credential; it cannot be treated as an ephemeral credential created by the runtime.

**Impact:** The private key remains a high-value standing secret and requires normal host/secret-management protection.

**Discovered by:** W1 configuration and child-process credential-boundary audit.

**Current status:** The key is configured by protected file path, never logged or persisted in runtime records, and is used to mint narrower temporary installation tokens. The broker child environment is explicitly allowlisted and excludes operator/remediation/webhook/state-integrity secrets.

## Native Windows WASI toolchain availability

**Symptom:** A Windows checkout may not have the Rust `wasm32-wasip2` target or a usable WSL toolchain installed.

**Root cause:** The contract build depends on the local Rust/WASM toolchain rather than shipping a platform-specific compiled artifact.

**Impact:** `npm run winner:build` can fail during environment setup even though the TypeScript runtime and offline tests are available.

**Discovered by:** Windows `winner:build` execution when the native `wasm32-wasip2` target was unavailable.

**Current status:** Install the required Rust target and, on Windows, the supported WSL fallback described by the build script. This is a maintainer environment limitation, not a change to C1 contract semantics.

## Deliberate out-of-scope limitations

The maintained product does not include a dashboard, generic provider/action framework, second provider, second remediation action, queue platform, Kubernetes deployment, multi-region failover, or horizontal scaling. These are scope decisions that preserve a deep, inspectable emergency-authority boundary rather than unresolved promises.

## Evidence integrity

`winner/evidence/` contains historical live and offline artifacts from several phases. In particular, `C2-E2E-R2-FAILURE.json` remains the R2 failure artifact and `C2-E2E-R3-R2-FAIL_CLOSED_REPLAY_LOST_NOT_ACCEPTED` remains the historical R3 classification represented by the repository's evidence. W1/W1-R2/W1-R2-FIX hardening was offline and must not be presented as an uninterrupted live run of the final runtime.
