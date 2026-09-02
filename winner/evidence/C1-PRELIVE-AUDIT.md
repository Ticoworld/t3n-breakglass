# C1 pre-live brutal offline audit

## Verdict

`PRELIVE_REPAIR_PASS_WAITING_ONLY_ON_CREDIT`

The source/local attack found and repaired concrete defects. The remaining
proof obligation is live T3N OCC plus funded broker execution and independent
GitHub observation. This phase performed no live call.

Base commit audited: `07b6e890bed4951bc40591f32ba346a74c6fc9aa`.

## Scope and freeze

The working tree was clean at the freeze check, the branch was
`winner-v2-core`, and the starting local and remote winner refs were
`07b6e890bed4951bc40591f32ba346a74c6fc9aa`. `origin/main` was
`4a077035474337b7a1ad16204820e68ed3020477`.

No metered T3N function, control-plane mutation, `submitUserInput`, agent
creation, delegation update, provider call, GitHub API call, GitHub token mint,
deploy-key operation, C2 work, or submission work was performed.

## Substantive findings and repairs

| Finding | Before evidence | Repair and regression |
|---|---|---|
| malformed terminal combinations were accepted by `valid_shape` | a `CLOSED` record with zero attempts was accepted | terminal field/attempt invariants are explicit; Rust malformed-state test |
| reconciliation could mutate a `CLOSED` record | `reconcile` did not require a reconciliation state | only `RECONCILE_REQUIRED`/`FAILED` enter reconcile; duplicate reconcile test |
| expiry could reopen a claimed record through release | release had no cluster-time check | release requires live incident; expiry regression test |
| reserve expiry could overwrite `EFFECT_CLAIMED` with a claim still attached | generated sequence 35 produced invalid reachable shape | expiry marks only unclaimed states; regression test for reserve-after-claim |
| exact 404 plus failed/malformed list could look absent | classifier lacked list status/body validity | requires HTTP 200 and well-formed list; fake ambiguity matrix |
| committed authority target was not compared with broker fixed target | broker used fixed config owner/repo but did not reject authority mismatch | `CLAIM_TARGET_MISMATCH` before provider credentials; target test |
| seed env could widen owner/repository | arbitrary safe segments were accepted | seed uses committed target constants and rejects overrides |
| delegation env overrides could redirect grants | operator environment could select another valid DID | overrides must match recorded principals; all three DIDs must differ |
| pre-DELETE exceptions could strand a zero-attempt claim | only explicit precheck failure released | guarded `releaseClaim` covers broker-controlled pre-DELETE failures; source regression guard |
| live replay was not a pass criterion and proof was written before all checks | replay errors/values could be recorded while pass checks ran later | require replay barrier/result/zero-effect and write live proof only after criteria |
| App config accepted a repository-local private-key path | the standing key location was only an operational convention | reject paths inside the repository; App authority regression test |
| live runner created the disposable provider target before validating registered identities/configuration | target setup preceded the delegation-evidence check | validate operator/registration/delegation before target setup; source-order regression |
| error redaction covered only opaque T3N keys and could expose JWT/GitHub bearer-shaped values | redaction regex omitted JWT and GitHub token forms | redact Authorization/Bearer, JWT, GitHub token, and T3N token forms; regression test |

The first four state defects were also attacked by the generated state-machine
test. The provider list defect was found by the ambiguity harness: a 200 body
that was not an array is not evidence of absence. No repair weakens the
one-effect architecture or grants a broader principal.

## State-machine exhaustion

The complete state/caller/function table is in
`C1-PRELIVE-ARCHITECTURE.md`. The pure Rust model now passes 16 unit tests,
including expiry, wrong caller, wrong claim, replay, terminal-shape, and
generated-sequence tests. The generated property run covered 4,000 sequences ×
80 operations = 320,000 operations, with reserve/claim/release/finalize/
reconcile/replay and agent/broker/random caller permutations.

The invariant held for every generated sequence:

> with `max_effects=1`, no second independent claim wins without a successful
> `NOT_ATTEMPTED` release; after any possible effect attempt, no claim wins.

Expected denial paths return normal `DENIED`/`LOST` values and do not depend on
an `Err` write surviving. Storage/serialization failures remain infrastructure
errors. Expiry persistence is intentional only for an unclaimed authority.

## Principal and authority attack

The remediation DID can reserve only; the dedicated broker DID can run the
broker lifecycle only. Operator, user-created valid DID
`did:t3n:325ddf60d58d5054d3107cbc051ffa544d162e92`, and random DID do not
inherit broker authority from authentication validity. The runtime selects
`EFFECT_BROKER_T3N_API_KEY` and verifies its exact DID; it does not fall back to
`T3N_API_KEY`, `AGENT_T3N_API_KEY`, or the user-created pair.

## Target-injection attack

The model-facing tool boundary and Rust requests reject unknown fields. The
broker has no action/owner/repository/deploy-key CLI parameters and records only
the incident ID as invocation input. It consumes target fields only from the
committed claim detail, then compares owner/repository to the fixed App
configuration. Environment target overrides in the seed path are rejected.
Prototype-pollution/spread-style widening is not used at the trust boundary.

## Claim-before-effect ordering

The source ordering is mechanically tested as:

`CLAIM_REQUEST → CLAIM_COMMITTED_WON → APP_JWT_MINT → INSTALLATION_TOKEN_MINT → PROVIDER_GET → PROVIDER_DELETE`.

The loser branch exits with zero token and destructive counts. There is no
`Promise.all` in the broker lifecycle. App JWT/private-key access is after the
committed winner branch. The DELETE boundary is explicit and is followed by
verification, revocation, and non-destructive finalization.

## Two-process local race

`winner/tests/local-race.test.ts` launches two independent Node processes per
iteration, waits for both ready files, releases a common barrier, and uses a
file-lock-backed committed-state adapter that re-reads after contention. It
ran 32 iterations. Every iteration produced exactly one `CLAIM_WON` and one
`CLAIM_LOST`, one winner token event, one winner DELETE event, zero loser token
events, and zero loser DELETE events. Child PIDs and raw per-contender result
files are checked. This is only a broker-behavior simulation given the C0R-live
OCC assumption; it is not evidence of live T3N OCC.

## Crash, release, and provider ambiguity

The complete crash matrix is in `C1-PRELIVE-CRASH-MATRIX.md`. The safety rule is
conservative at the DELETE-entry boundary: uncertain send means no release and
no automatic destructive retry. The fake provider matrix covers all requested
drop/status/verification inconsistencies. Independent absence requires exact
404 plus valid HTTP-200 list absence. Reconciliation emits reads only.

The release transition still has an explicit, unavoidable trust assumption:
the contract cannot observe GitHub, so an authorized but dishonest broker could
lie about whether DELETE was entered. The normal broker's local control flow
uses the boundary flag to ensure it does not make that assertion after a
possible send.

## GitHub App authority audit

`winner/broker/github-app.ts` has no PAT path. It requires numeric App and
installation IDs, enforces an external private-key path, and requires exactly
`Ticoworld/t3n-breakglass-sandbox`. The installation token request selects only
that repository and requests only `administration: write`; the broker also
requires a private repository response and exact target presence. JWTs,
installation tokens, Authorization headers, and private key bytes are excluded
from evidence. Tokens are held in memory and revoked in post-mint `finally`
paths where the process remains alive. A standing private key remains a
standing authority and is documented as such. Fake HTTP lifecycle tests verify
the request body, bearer use, and one revoke call.

## Evidence trust and live-proof boundary

Evidence classifications are kept separate: `LOCAL_MODEL`, `CODE_PROVEN`,
`LIVE_T3N`, `LIVE_GITHUB`, `INDEPENDENT_PROVIDER_READ`, and `HOST_ACTIVITY`.
The offline harness writes no live proof. The live runner now checks raw broker
observations, final `CLOSED`, and a successful replay loser before writing
`C1-live-proof.json`; its `C1_PASS` output is unreachable from the offline
tests.

## OCC, KV, version, and ACL boundary

C1 relies only on the C0R result that two transactions reading/writing the same
reservation state can conflict and leave one committed winner after retry. It
does not assume global serial execution, CAS, exactly-once invocation,
external-effect transactionality, a durable outbox, or a mid-function commit.

The V2 contract is `z:adb9365ee986cc6d0cb4006580782fe6fc7a431f:breakglass-winner-c1`,
version `2.0.0`, numeric contract ID `842`, with private map ACL readers and
writers set to contract ID 842 in the registration evidence. Registration
derives the map and ACL from the newly returned registration ID and updates
the map explicitly; it does not rely on V1 migration. No live ACL call was
made in this audit. The checked-in delegation evidence is not present, so live
principal provisioning/delegation remains a pre-proof setup obligation and is
not represented as completed here.

KV keys are the tenant-scoped `winner-incidents` map plus validated incident
IDs (1–128 bytes at the contract boundary). The C1 namespace/tail is distinct
from V1. Rust rejects empty/overlong IDs, unsafe target segments, invalid DIDs,
bad action, non-one budget, malformed state, and unknown request fields. No
claim ID is accepted unless it matches the stored current claim exactly.

## Local test status

| Suite | Result |
|---|---|
| root product tests | 7 passed |
| broker/pre-live tests | 15 passed |
| two-process race | 32/32 iterations passed |
| Rust contract unit tests | 16 passed |
| Rust doc tests | 1 passed |

The broker/pre-live count includes the original broker tests and new pre-live
tests; the race is separately reported because its iterations are the useful
quality measure. WASM build and final secret audit are recorded in the result
JSON after execution.

## Claims allowed and forbidden

Allowed after this phase: source-level ordering, authorization, state-machine,
local race, ambiguity, and evidence-boundary claims listed above.

Forbidden: C1_PASS, live T3N OCC proof, funded broker proof, GitHub provider
mutation proof, exactly-once external effect, durable outbox, or any claim that
the current external credit blocker was resolved.
