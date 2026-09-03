# C1-R6A failed-run closure and effect-start repair

This document is descriptive evidence for the local R6A repair. It does not
represent a live pass, a registration, or a provider result.

## Checkpoint and historical boundary

- Starting branch: `winner-v2-core`
- Starting SHA: `64a7f5fc73d761e1b1b471c4d2e85c839aeaaec9`
- `origin/winner-v2-core` at start: `64a7f5fc73d761e1b1b471c4d2e85c839aeaaec9`
- `origin/main`: `4a077035474337b7a1ad16204820e68ed3020477`
- Historical incident: `C1-1788441029399`
- Historical target: `Ticoworld/t3n-breakglass-sandbox`, deploy key `162181065`

The historical R6 failure remains preserved in `C1-R6-LIVE-FAILURE.json`.
Its final operator read showed `EFFECT_CLAIMED`, `effect_attempts = 0`,
`effect_claim_version = 2`, and no final classification. The target is
independently absent, but the exact responsible DELETE path is not
reconstructible from the retained R6 process evidence.

No historical incident transition was performed by R6A.

## Forensic evidence boundary

The retained host activity proves that calls with the listed functions were
accepted by the host under the relevant principals. Host activity does not
bind request bodies to the incident and does not contain the discarded child
result documents. Therefore host activity alone cannot identify the broker
winner, loser, token count, DELETE acknowledgement, or replay result.

| Timeline item | Classification | Evidence boundary |
|---|---|---|
| create-incident | PROVEN | Historical final authority and host activity show the authority existed; host entry seq 183570 is recorded. |
| wrong-role broker reserve | CODE-REACHABLE | Current runner contains the check before reservation; exact historical child result was not retained. |
| wrong-role remediation claim | CODE-REACHABLE | Current runner contains the check before reservation; exact historical child result was not retained. |
| remediation reserve | PROVEN | Host activity seq 183593 and the retained successful reservation path. |
| broker claim invocation A | CODE-REACHABLE | Two claim calls are in host activity (seq 183600 and 183603), but body-to-contender binding is unavailable. |
| broker claim invocation B | CODE-REACHABLE | Same boundary as the preceding row. |
| release-not-attempted | PROVEN as host activity / NOT RECONSTRUCTIBLE as child result | Host seq 183609 exists; its relation to a particular discarded child is not proven. |
| finalize-effect | PROVEN as host activity / NOT RECONSTRUCTIBLE as child result | Host seq 183613 exists; final authority was not terminal afterward. |
| replay claim activity | PROVEN as host activity / NOT RECONSTRUCTIBLE as result | Host seq 183619 exists; the returned replay result is absent. |
| final get-incident | PROVEN | Operator read returned the preserved non-terminal authority; host seq 183623 is recorded. |
| final provider observation | PROVEN only as independent absence | Exact GET was 404 and list was valid/absent; responsible DELETE path/count is not reconstructible. |

The prior runner order was mechanically `race -> replay -> final get-incident`.
This was a proven ordering defect. The repair is
`race -> durable child results -> final CLOSED readback -> replay -> final
readback`.

## Contract surface and state model

The candidate contract version is `2.0.3`; it is not registered in R6A. The
state-only contract has no provider imports or HTTP implementation. Its map
key is `z:<runtime tenant DID>:winner-incidents`; it is read/written through
the C1 contract map interface only.

Functions and caller authority:

| Function | Caller | State effect |
|---|---|---|
| `create-incident` | exact runtime tenant/operator DID | absent key -> `ACTIVE`; fixed action/owner/repository, cluster timestamps, one-effect budget |
| `get-incident` | exact runtime tenant/operator DID | read and validate only |
| `reserve-incident` | remediation DID | `ACTIVE` -> `RESERVED` |
| `claim-effect` | broker DID | `RESERVED` or `READY_RETRY` plus matching expected generation -> `EFFECT_CLAIMED`; generation increments |
| `release-not-attempted` | broker DID | `EFFECT_CLAIMED` with attempts 0 -> `READY_RETRY`; generation is retained |
| `begin-effect` | broker DID | matching `EFFECT_CLAIMED` -> `EFFECT_STARTED`, attempts 0 -> 1 |
| `finalize-effect` | broker DID | only `EFFECT_STARTED`, attempts already 1; closes or enters bounded recovery state |
| `reconcile-effect` | broker DID | `EFFECT_STARTED`, `RECONCILE_REQUIRED`, or `FAILED`; never restores attempts to 0 |

Every request is strict serde input with unknown fields rejected. The create
request accepts only incident ID, remediation DID, broker DID, deploy-key ID,
and TTL. Owner, repository, action, timestamps, budget, state, reservation,
claim, and final classification are contract-derived or contract-managed.

Reachable state transitions in the candidate model are:

- `ACTIVE -> RESERVED` on the remediation reservation; an expired active
  authority becomes `EXPIRED` on a permitted pre-effect transition.
- `RESERVED -> EFFECT_CLAIMED` on a broker claim with the current generation;
  competing or wrong-generation claims lose, and expiry denies.
- `EFFECT_CLAIMED -> READY_RETRY` on a matching broker
  `release-not-attempted`; `EFFECT_CLAIMED -> EFFECT_STARTED` on matching
  `begin-effect`.
- `EFFECT_STARTED -> CLOSED` for verified absence;
  `EFFECT_STARTED -> RECONCILE_REQUIRED` for acknowledged, unknown, or
  present outcomes through finalize/reconcile; the existing bounded model may
  represent verified-present finalization as `FAILED` before reconciliation.
- `RECONCILE_REQUIRED -> CLOSED` only for verified absence; present/unknown
  remain reconciliation-required. `FAILED -> CLOSED` is possible only after a
  verified-absence reconciliation with the same claim.
- `CLOSED`, `EXPIRED`, and unrecoverable terminal states do not regain effect
  authority. No transition from an attempts-1 state returns to attempts 0.

The OCC conflict is at the transaction read/write of the same incident map
entry. R6A assumes only the previously demonstrated C0R property: competing
transactions can conflict/retry so one committed state winner is selected. It
does not assume global serialization, CAS, exactly-once invocation, external
effect transactionality, or a durable outbox.

## Effect-start boundary

Before repair, the broker could reach provider DELETE while the authority was
still `EFFECT_CLAIMED` with `effect_attempts = 0`; `finalize-effect` performed
the first budget increment. This was `EFFECT_START_NOT_COMMITTED = PROVEN`.

After repair:

1. claim returns a committed winner;
2. the broker validates the target and temporary provider authority and runs
   provider pre-effect reads;
3. pre-effect failure may call `release-not-attempted` only before the
   `begin-effect` request is sent;
4. `begin-effect` commits `EFFECT_STARTED` and `effect_attempts = 1`;
5. only after the committed `EFFECT_STARTED` response may provider DELETE be
   entered;
6. finalization accepts only `EFFECT_STARTED` with the same claim and does
   not increment the budget.

An ambiguous begin-effect transport result is conservative: the broker does
not release the claim and does not enter provider DELETE. A crash after a
committed begin leaves the consumed one-effect budget and requires read-only
reconciliation; it cannot authorize a second automatic effect.

## Broker entry and target/credential origins

The parent live runner generates one fresh incident ID and receives the
disposable target metadata from the target-setup child. It sends the incident
ID and target ID to the operator `create-incident` call. The contract, rather
than the parent or model, constructs and stores the action, owner, repository,
cluster timestamps, budget, and state. The remediation child receives only
the incident ID. Broker children receive the incident ID plus the expected
claim-generation value; they do not receive owner, repository, action, or
deploy-key target fields as authority input.

The broker target used for provider work is loaded from the committed claim
detail after `CLAIM_WON`. The broker rejects any mismatch with its fixed
`Ticoworld/t3n-breakglass-sandbox` configuration. The GitHub App private key is
accessed only in the winner path, when the broker calls `appJwt`; the
repository-selected installation token is minted only after that claim and
installation validation. Provider prechecks are exact-key GET plus list GET.
The only DELETE entry is after a committed `begin-effect`; it is marked
ambiguous at the request boundary and is never retried blindly. The temporary
installation token is revoked in the winner cleanup path, and the same token
is probed after revocation. Finalization occurs only after provider observation
and token cleanup. A pre-begin failure can use `release-not-attempted` only
when the begin request was never sent; post-begin errors remain consumed and
require reconciliation.

The broker entry surface is `winner/broker/run.ts`, invoked as an independent
process by `winner/scripts/c1-live.ts`. The live parent now requires durable
broker result files before constructing effect evidence. It does not use
stdout as the authoritative child result.

## Generation fence and stale contender

The old claim API accepted both `RESERVED` and `READY_RETRY` without an
expected generation. Therefore this interleaving is code-reachable (but was
not proven to have occurred in R6): A claims generation 1, A releases, and a
stale B that still carries the old generation is retried against `READY_RETRY`
and could claim again.

The candidate claim request includes `expected_claim_version`. A claim is
allowed only when it equals the stored generation. A successful claim bumps
the generation; release retains the bumped value. Thus stale B with generation
0 loses after A's release, while an explicitly refreshed retry with generation
1 may claim. This is orchestration metadata, not a model-supplied target.

## Replay and durability

Replay is defined only as a fresh broker invocation after an independent
operator read proves exactly `CLOSED`, `effect_attempts = 1`, and
`VERIFIED_ABSENT`. The runner now refuses to start replay before that gate and
performs a post-replay operator read as well.

Each broker process receives a unique per-run `C1_RESULT_FILE`. It writes its
sanitized result through write-to-temporary-file followed by rename before
normal exit and on caught process failure. The parent reads `broker-a`,
`broker-b`, and replay result files, not stdout, for the effect proof. A
parent-level failure artifact records any available persisted child documents.
Result documents contain claim identity/outcome, effect-start result, token
boolean, provider-before/after metadata, DELETE status/count, revocation,
same-token probe, release/finalize outcomes, and timestamps; they contain no
credential material. The same-token probe is accepted only when an observed
HTTP 401 or 403 is recorded; a transport exception is not treated as refusal.

## Crash matrix

| Crash point | Durable state / safe classification |
|---|---|
| before claim | no claim; SAFE_RETRY only if no state-changing request was sent |
| claim request sent, result unknown | claim status must be read; do not assume loss or mint provider authority |
| claim committed, before App JWT | `EFFECT_CLAIMED`; SAFE_RECONCILE or NOT_ATTEMPTED release only when begin was never sent and that fact is locally proven |
| App JWT minted, before installation token | claim still pre-begin; revoke token, then release only if begin was never sent |
| installation token minted, before provider GET | revoke token; release only while begin request was never sent |
| provider GET failed before begin | revoke token; NOT_ATTEMPTED release is bounded to the proven pre-begin path |
| immediately before DELETE | `EFFECT_STARTED`; no release or automatic retry |
| DELETE request outcome unknown | `EFFECT_STARTED`; read-only reconciliation only, no blind second DELETE |
| DELETE acknowledged, before verification | `EFFECT_STARTED`; read-only verification/reconciliation |
| verified absent, before revoke | `EFFECT_STARTED`; revoke then finalize |
| revoke succeeds, before finalize | `EFFECT_STARTED`; no second effect; finalize/reconcile |
| finalize request ambiguous | read final authority; do not repeat destructive work |
| CLOSED response received, process dies | terminal readback can be used; replay is allowed only after independent CLOSED verification |

`EFFECT_STARTED` recovery accepts verified absence to `CLOSED`, and accepts
present/unknown outcomes only into bounded reconciliation. It never returns to
`READY_RETRY` or attempts 0.

## Local verification boundary

- Rust generated state sequences: 4,000 sequences × 80 operations.
- Rust model/unit tests: 26 passed; doc tests: 1 passed.
- Separate-process local race: 32 iterations; one winner and one loser per
  iteration, persisted result files consumed, winner begin marker before
  provider DELETE marker.
- TypeScript winner/C1 tests: 52 passed, including child durability, replay
  ordering, and stale-generation regressions.
- Root product tests: 7 passed.
- Candidate WASM build used the supported `wasm32-wasip2` path after a clean
  rebuild.

These are local/code claims only. They do not prove live T3N registration,
live OCC, or a provider-side exactly-once property.

## Claim boundary and next gate

Allowed now: local source/model repair, local ordering and durability claims,
and the candidate component hash/export claim.

Forbidden now: registration of 2.0.3, ACL/delegation changes, any live
incident, provider operation, C1 re-proof, provider-side exactly-once claim,
or C2 work. The next gate is state-only registration and live fencing proof;
the historical 2.0.2 incident remains untouched.

The GitHub App private key remains a standing trust root.
