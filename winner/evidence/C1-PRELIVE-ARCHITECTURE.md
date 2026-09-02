# C1 pre-live architecture map

This is a descriptive source reconstruction of `winner-v2-core` at the
pre-live audit checkpoint. It is not a C1 proof and contains no live result.

## Boundary and principals

The remediation-facing input is one JSON object, `{ "incident_id": "..." }`.
The Rust request structs use `serde(deny_unknown_fields)`. The broker CLI also
takes the incident ID as its sole positional argument. Synchronization files
and fixed configuration are process environment, not model/agent input.

The intended principals are:

| Principal | Source of authentication | Authorized C1 functions |
|---|---|---|
| remediation agent | `AGENT_T3N_API_KEY` plus exact `AGENT_DID` | `reserve-incident` only |
| dedicated effect broker | `EFFECT_BROKER_T3N_API_KEY` plus exact `EFFECT_BROKER_DID` | `claim-effect`, `release-not-attempted`, `finalize-effect`, `reconcile-effect` |
| operator | operator credential used by provisioning/configuration scripts | no lifecycle authority in the Rust model |
| user-created valid DID | its own `DID` + `T3N_API_KEY` pair | no broker authority; it is not a fallback |
| any other DID | its own authenticated identity, if any | no C1 lifecycle authority |

The Rust authorization check is the caller DID returned by
`tenant_context::calling_user_did()`, compared to the DID stored in the
authority. Authentication success is not authorization success.

## Contract storage and entry surface

The five WIT exports are:

1. `reserve-incident`
2. `claim-effect`
3. `release-not-attempted`
4. `finalize-effect`
5. `reconcile-effect`

Every export dispatches through `winner/contract/src/lib.rs`. The dispatch
function derives exactly one map name from the tenant context:

`z:<lowercase tenant DID>:winner-incidents`

It reads the incident ID as the KV key, deserializes `IncidentAuthority`,
checks that the stored incident ID and full state shape are valid, obtains the
calling DID and cluster timestamp, then invokes the pure model transition.
Only a `WON` transition is written, except that an expiry transition is also
persisted so an unclaimed live authority can become `EXPIRED`. Expected
denials are JSON results (`DENIED` or `LOST`); malformed requests and storage
infrastructure failures return an error before a state write.

The exact OCC boundary is the transaction's read of
`winner-incidents[incident_id]` followed by its write of that same
map/key. For competing claims, both transactions may read `RESERVED`, but
only one conflicting read/write transaction can commit under the C0R-proven
host OCC behavior. The stale transaction is re-evaluated against the committed
state and returns `LOST`. C1 assumes no stronger platform property.

## Authority fields and origins

| Field | Origin | Can the agent/model supply it? |
|---|---|---|
| `incident_id` | operator seed environment, then contract KV key | yes, as the only input, subject to validation |
| `remediation_agent_did` | recorded replacement-agent evidence/configuration | no |
| `effect_broker_did` | broker provisioning evidence/configuration | no |
| `action` | committed `ACTION` constant | no |
| `github_owner`, `github_repo` | committed target constants during current seed path | no; mismatching env overrides are rejected |
| `deploy_key_id` | operator target setup result, committed in the incident authority | no |
| reservation/claim IDs and versions | Rust state transitions | no |
| timestamps and effect budget | operator seed plus Rust checks; budget must equal one | no |

The broker accepts only `incident_id` from its invocation surface. After a
successful claim it parses the authority-loaded detail, rejects incomplete or
wrong-action claims, and rejects an owner/repository mismatch with the fixed
GitHub App configuration before minting any provider credential.

## State and transition map

The reachable states are `ACTIVE`, `RESERVED`, `EFFECT_CLAIMED`, `READY_RETRY`,
`CLOSED`, `EXPIRED`, `RECONCILE_REQUIRED`, and `FAILED`. `valid_shape` is
checked before every model operation; terminal fields and effect-attempt
counts are now constrained rather than trusted from comments.

`NOT_ATTEMPTED` is a broker/provider classification, not a Rust stored state;
the normal release path returns the authority to `READY_RETRY`.

Notation: `A` is the remediation agent, `B` the dedicated broker, and `N`
means operator, user-created DID, random DID, absent caller, or any other
caller. `W` means `WON`; `L` means normal `LOST`; `D` means normal `DENIED`.
Expiry at the cluster timestamp is a `D` and marks only an unclaimed
`ACTIVE`/`RESERVED`/`READY_RETRY` record as `EXPIRED`. No expired transition
clears a claim.

| Stored state | reserve(A) | reserve(N) | claim(B) | claim(N) | release(B/N, matching) | finalize(B/N, matching) | reconcile(B/N, matching) |
|---|---|---|---|---|---|---|---|
| ACTIVE | W → RESERVED | D | L | D | D/D | D/D | D/D |
| RESERVED | L | D | W → EFFECT_CLAIMED | D | D/D | D/D | D/D |
| EFFECT_CLAIMED | L | D | L | D | W → READY_RETRY if unexpired / D | W → CLOSED/RECONCILE_REQUIRED/FAILED / D | D/D |
| READY_RETRY | L | D | W → EFFECT_CLAIMED | D | D/D | D/D | D/D |
| CLOSED | D (budget) | D | L (budget) | D | D/D | D/D | D/D |
| EXPIRED | D, remains EXPIRED | D | D, remains EXPIRED | D | D/D | D/D | D/D |
| RECONCILE_REQUIRED | D (budget) | D | L (budget) | D | D/D | D/D | W → CLOSED or remains RECONCILE_REQUIRED / D |
| FAILED | D (budget) | D | L (budget) | D | D/D | D/D | W → CLOSED or RECONCILE_REQUIRED / D |

`finalize` accepts `VERIFIED_ABSENT` and closes; it accepts
`PROVIDER_ACKNOWLEDGED`, `ATTEMPTED_OUTCOME_UNKNOWN`, and `VERIFIED_PRESENT`
and consumes the one attempt. The latter two ambiguous/present outcomes enter
reconciliation; `VERIFIED_PRESENT` enters `FAILED` first. `reconcile` accepts
`VERIFIED_ABSENT` to close and accepts the two unresolved classifications to
remain or return to `RECONCILE_REQUIRED`; other classifications are denied.

The `N` rows are not a privilege merge: the model checks the required stored
DID before state handling. The exact five-DID authorization matrix is exercised
by the contract caller tests and the offline principal audit; the operator,
user-created DID (`did:t3n:325ddf60d58d5054d3107cbc051ffa544d162e92`), and random
DID are all non-authorized for broker functions.

## Broker effect sequence

`winner/broker/run.ts` is the lifecycle entry point:

1. refuse `GITHUB_PAT`, authenticate only the dedicated broker key, and write
   a sanitized ready record;
2. wait for the common barrier;
3. call `claim-effect` with only `{ incident_id }`;
4. on `CLAIM_LOST`, emit zero token/provider counts and exit;
5. on `CLAIM_WON`, validate the authority-loaded action/target and compare the
   target to the fixed App repository;
6. mint an App JWT from the private key path, validate the exact installation,
   mint a repository-selected installation token with administration write,
   verify the exact private repository, and perform exact-key/list prechecks;
7. on any broker-controlled failure before DELETE, attempt
   `release-not-attempted`; that transition requires an unexpired
   `EFFECT_CLAIMED` record with zero attempts;
8. immediately before entering `deleteKey`, set the local
   `deleteMayHaveBeenInitiated` boundary. From that point onward no release is
   attempted; the broker performs at most one DELETE and then reads exact key
   and list state;
9. classify the provider outcome. `VERIFIED_ABSENT` requires exact GET 404,
   list HTTP 200, a well-formed list body, and no target in that list. Any
   ambiguity is not a destructive retry;
10. revoke the installation token in `finally` when one was minted, then call
    `finalize-effect` only for a recorded post-provider classification.

App JWT and installation-token values are held in memory only. They are never
written to evidence. The private key path is external to the repository and is
standing authority; the code has no PAT fallback. Token revocation failure is
recorded as a cleanup failure and does not trigger another DELETE.

`prepare-target.ts` is a separate operator setup helper. It creates the
disposable read-only deploy key and later removes only its local temporary SSH
material; a remote create ambiguity can require manual provider cleanup. It is
not part of the claim-before-effect lifecycle and was not run in this phase.

## Replay and evidence

The intended live runner creates/seeds one incident, reserves it with the
remediation agent, starts two separate broker processes at one common barrier,
collects their raw sanitized observations, reads final authority/activity, and
then runs a replay broker. The live proof writer now refuses to write
`C1-live-proof.json` unless both race outcomes, one token, one DELETE, final
`CLOSED`, and replay `CLAIM_LOST`/zero-token/zero-delete criteria all pass.
No offline harness writes that live artifact or labels itself live.
