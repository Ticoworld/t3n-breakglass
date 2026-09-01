# C-0R — Missed-thread closure

Research-only closure pass. Date: 2026-09-01. Branch: `c-0r-closure`, based
on the published verification package at `a0fde302dec02a6af585cf52dcea261e938e709b`.
The product baseline remains public commit
`4a077035474337b7a1ad16204820e68ed3020477`. No BreakGlass behavior, public
main, or submission material was changed.

This report does not authorize C0 and does not freeze a V2 architecture. It
records what the missed experiments establish and where the ceiling remains
blocked.

## 1. Completeness correction

The original C-0 reported `COMPLETE`. C-0V rejected exhaustion because decisive
experiments were deferred; durable outbox was omitted; OCC reservation
semantics were not tested; audit, App-token, and webhook feasibility were not
closed; and AgentGate was underweighted as an elite benchmark. This is a
historical correction, not a rewrite of the original findings.

## 1a. Inherited AgentProof evidence

The C-0R package retains the old submission autopsy rather than inventing judge
feedback. Direct source: [Ticoworld/agentproof-t3n](https://github.com/Ticoworld/agentproof-t3n),
checked at `e710ddf`; the inspected artifacts were `README.md`,
`docs/BUGS.md`, `docs/FEEDBACK.md`, `docs/WALKTHROUGH.md`, and the contract and
test artifacts listed in `research/C-0-AGENTPROOF-AUTOPSY.md` and
`research/C-0-SOURCE-LEDGER.md`.

**FACT — CODE/LIVE evidence:** the old submission had a partial flight
fulfillment path and did not demonstrate a complete real-money loop in the
retained artifacts. Its own artifacts distinguish what was mocked, what was
testnet, and what was not completed.

**INFERENCE — competitive explanation:** a platform-mechanics proof without a
judge-visible complete enterprise job likely weakened its competitiveness.
That is an inference from the artifact gap and the Remit/PactAgent lesson, not
judge feedback. No unavailable judge opinion is presented as fact.

## 2. Evidence standard

This report uses the following classifications exactly:

* **SOURCE-PROVEN** — official documentation or a primary interface/source
  states the behavior.
* **CODE-PROVEN** — inspected code/WIT/type declarations implement or expose
  the stated behavior.
* **LIVE-EVIDENCE-PROVEN** — a safe testnet or disposable live experiment
  returned the stated result.
* **INFERRED** — a constrained consequence of proven source and live facts;
  it is labeled as inference rather than upgraded to fact.
* **UNKNOWN** — not permitted for a material final register row. C-0R closes
  each material row as proven, unavailable, non-material, or the explicit
  external-account block.

Exact evidence paths are indexed in `C-0R-VERIFICATION-INDEX.md` and the
source trail is in `C-0R-SOURCE-LEDGER.md`.

## 3. R1 — Durable outbox

### Design semantics

**SOURCE-PROVEN / CODE-PROVEN.** The official Host API labels `host:outbox` as
Coming soon and describes enqueue-after-commit, at-most-once delivery using
idempotency-key dedupe and a single leader. The vendored
`host:outbox@1.0.0` WIT in the call-centre reference gives the exact typed
surface: `enqueue(idk, request)`, `status(idk)`, host upstream allowlisting,
pending/committed/failed statuses, and committed metadata containing
`at-seq`, `upstream-ref`, and `response-digest`. Same IDK plus the same request
is accepted idempotently; a same IDK with a different request digest is an
IDK collision. `status` is leader-only in the WIT.

The WIT is a platform interface definition, not proof that a challenge tenant
can execute it. The call-centre contract vendors it but does not import it.
The flight contract and AgentGate also vendor it without importing it.

Sources: [Host API](https://docs.terminal3.io/t3n/how-t3n-works/host-api),
[ADK reference](https://docs.terminal3.io/developers/adk/reference),
call-centre commit `bf08f0ba0fb1ce585696e78b7162a0785afab97f`,
`contract/wit/deps/host-outbox-1.0.0/package.wit`; see the source ledger.

### Live public testnet probe

**LIVE-EVIDENCE-PROVEN.** The research component in
`research/C-0R-outbox-probe/` imported `host:outbox/outbox@1.0.0`, compiled
under WSL Rust 1.97.1 for `wasm32-wasip2`, and was registered on testnet. The
probe used no secret and attempted only `GET https://example.com/`.

* registration `z:adb9365ee986cc6d0cb4006580782fe6fc7a431f:c0r-outbox-probe`,
  contract ID 836, succeeded;
* a second version registration, contract ID 837, also succeeded;
* invocation of the registered component returned JSON-RPC `-32603 Internal
  error`, request UUID `a9f9edbf-d244-4b8c-b2d9-c6a7330422d4`, with no detail;
* contract logs were empty; no outbox ack, `status`, `at-seq`, upstream
  reference, or response digest was returned.

To falsify the alternative explanation that this was only an upstream-host or
connector rejection, a second registered version imported the same outbox WIT
but invoked a `link-probe` function that never called outbox. Registration
again succeeded as contract ID 840; invocation still returned `-32603` with
request UUID `e0bcd4b5-8184-4a4b-be35-9ac32cca8e0a`. See
`research/C-0R-outbox-link-result.json` and its source runner. This closes the
link-versus-connector ambiguity while leaving the node's private internal
linker/host error unexposed.

This proves the registration layer accepts the component but the current
public testnet tenant-z execution path cannot execute the imported outbox
interface. The node did not expose the lower-level linker reason, so the
private internal cause is not claimed. The exact sanitized result is
`research/C-0R-outbox-result.json`.

Final classification for `OUTBOX-AVAILABLE-TO-Z-WORLD`: **PROVEN IMPOSSIBLE /
UNAVAILABLE**, scoped to the current public participant/testnet tenant-z path.
This is stronger than “the docs say Coming soon” and narrower than “the whole
Terminal 3 platform cannot do it.”

### Connector and receipt closure

**PROVEN IMPOSSIBLE / UNAVAILABLE for the current public challenge path.** No
public SDK method, tenant map operation, WIT import, reference contract, or
documented tenant configuration surface was found for defining an outbox
connector, selecting its idempotency contract, or reading outbox status/ack
metadata. The WIT contains operator-style allowlist/connector concepts, but
does not provide a tenant registration API in the inspected public surfaces.

No indirectly exposed system contract, public beta tenant allowlist, or
reference-agent path that successfully invokes outbox was found. The absence
is bounded to the searched public surfaces; the testnet error does not reveal
whether a private allowlist exists behind the node.

Direct `api.github.com` DELETE cannot be treated as qualifying for outbox IDK
semantics: GitHub's deploy-key REST documentation does not promise an
idempotency-key or atomic conditional-delete contract. An idempotent remediation
connector in front of GitHub could theoretically qualify, but no such
connector is configurable or executable for this tenant today. That is a
platform-design possibility, not a bounty-live capability.

The requested short question for Ian / Terminal 3 is:

> Can `host:outbox/outbox@1.0.0` be enabled for a challenge tenant today? If
> yes, which public or beta z-contract import and upstream/connector allowlist
> are required? Is `outbox.status` available to challenge participants, and
> can its `at-seq` ack be checked through the documented audit/Merkle proof
> path? Our public testnet probe registered successfully but invocation
> returned JSON-RPC `-32603 Internal error` with no detail.

## 4. R2 — Current KV/OCC reservation

**LIVE-EVIDENCE-PROVEN: one committed winner.** The probe in
`research/C-0R-occ-probe/` registered contract 839 and used a fresh map/key.
Two separate SDK child processes were released by a common barrier:

* contender A ready at `1788264281316`, contender B at `1788264282609`;
* common release `1788264282638`;
* both invocation starts were `1788264282649` (same millisecond);
* both initially read the reservation as null in contract logs;
* B committed `WON` with `contender-b`;
* A was host-retried, reread `contender-b`, and returned `LOST`;
* final map readback and repeated readback both returned `contender-b`;
* activity entries for both calls were successful host records at sequence
  numbers 173796 and 173797.

The exact child inputs, timestamps, outputs, logs, activity, final readbacks,
and errors are in `research/C-0R-occ-result.json`. No HTTP, secrets, provider,
or BreakGlass state was involved.

The correct semantic conclusion is that ordinary `kv_store::get` enters the
transaction's OCC read set for this mutation path; a conflicting stale
transaction does not overwrite the committed reservation. The host retries
the losing call transparently, and guest code sees the winner on retry. This
is **not** an explicit CAS method and it is **not** a mid-function commit.

The latter distinction controls the ceiling: a reservation function can
commit before a later provider call if the workflow is split into phases, but
the current synchronous BreakGlass invocation still performs its external
HTTP operation before its one transaction commits. OCC alone therefore does
not fence the current call's side effect.

An external reservation database is **not necessary** for one-winner T3N
reservation semantics. It remains necessary only if a future bounty path needs
an external/provider fence or durable worker state that current T3N interfaces
do not supply. OCC does not by itself make a GitHub DELETE idempotent or create
an independently verifiable provider receipt.

## 5. R3 — Outbox × OCC

**INFERRED platform composition; unavailable bounty implementation.** The
proven pieces compose conceptually as:

`transactional OCC reservation/state`
`→ post-commit outbox (if enabled)`
`→ idempotent connector/provider operation`
`→ committed ack/activity/proof`.

That composition is an evidence-derived platform ceiling characterization,
not a new architecture proposal or authorization to build it. OCC closes the
reservation race. The outbox WIT is designed to move the external delivery
after the T3N commit and record an ack. A provider/connector still owns effect
idempotency and actual outcome. Today the testnet path lacks executable
outbox, tenant connector configuration, and public ack/proof retrieval, so the
bounty-buildable ceiling remains below this composition.

## 6. R4 — Activity/audit receipt binding

**LIVE-EVIDENCE-PROVEN, with a bounded negative.** After a safe `reserve`
invocation, `research/c0r-audit-live.ts` retrieved activity through SDK 5.2.0.
The host returned:

* sequence `173816`;
* hash `c44555c54d2d715b9b866ad0666b9e72d11e65b4f329f36a83ec0e5eb04dedb7`;
* host timestamp `1788264333269`;
* caller/actor/on-behalf-of DID;
* organization DID;
* exact contract and function `reserve`;
* outcome `success`.

The same artifact shows the contract's `tenant_context::seq_no()` was 173812,
not 173816. These are not silently equated: activity sequence is a host audit
record for the dispatch, while the guest context sequence is a separate
context value. `getAuditEvents` returned an empty batch because this probe did
not emit a host audit event. Contract logs were retrievable but had null span
IDs.

Therefore the answer to “can current public/testnet capabilities produce a
receipt stronger than guest-generated JSON?” is **YES**. Host activity supplies
metadata the guest cannot truthfully self-assign. The answer to “did C-0R prove
a complete causal, independently verified Merkle receipt?” is **NO**: the
retrieved activity did not bind the target or request body to the provider
response, no public SDK Merkle-proof method was found, and no proof endpoint was
successfully fetched. This bounded negative is recorded as unavailable for the
current public BreakGlass deployment, not as a claim about private Terminal 3
admin APIs.

## 7. R5 — GitHub App JIT provider authority

**LIVE-EVIDENCE-PROVEN.** The live runner in `research/c0r-app-jit-live.ts`
used the configured App private key only in memory, minted an RS256 App JWT,
validated installation `158227303`, and exchanged it for a repository-selected
installation token. The token response reported only
`Ticoworld/t3n-breakglass-sandbox`, `administration: write`, and mandatory
`metadata: read`, with an expiry one hour later. The exact sanitized artifact
is `research/C-0R-app-jit-live-result.json`.

The runner generated a fresh read-only deploy key ID `161952517`, proved exact
GET `200` and list `200` before action, issued exactly one DELETE using the
installation token, received `204`, then independently proved exact GET `404`
and list `200` with the target absent. It explicitly revoked the same token
with `204`; a subsequent repository GET using that same token returned `401`.
No PAT fallback occurred and no credential material was written to evidence.

This proves JIT installation-token authority for this disposable repository,
not zero-standing provider authority. The GitHub App private key remains a
standing trust root, and this result does not prove provider-side exactly once,
atomic GitHub/T3N state, outbox availability, or a complete causal/Merkle
receipt.

## 8. R6 — Webhook authenticity and delivery dedupe

**LIVE-EVIDENCE-PROVEN for the gateway protocol; real GitHub ingress not
claimed.** `research/c0r-webhook-gateway.ts` verifies HMAC-SHA256 over exact raw
bytes before parsing the event and stores a delivery ID/body digest exactly
once. The fixture tested: valid delivery, exact replay, altered body with old
signature, wrong signature, and same delivery ID with a different valid body.
Only one record was accepted; the result is in
`research/C-0R-webhook-result.json`.

The GitHub docs prove the header contract and delivery identifier. A real
webhook delivery was not run because it requires a reachable HTTPS endpoint
and owner/UI configuration: create a repository/org webhook, set
`application/json`, configure a secret, subscribe to the disposable
`deploy_key` event, and send the disposable event. This is an external setup
prerequisite, not an unresolved algorithmic question. The current BreakGlass
contract still has no ingress or in-contract HMAC path.

## 9. R7 — Post-effect ambiguity

**LIVE-EVIDENCE-PROVEN.** A disposable local connector intentionally dropped
responses before and after mutating an in-memory target. The fixture
distinguished `NOT_ATTEMPTED`, `ATTEMPTED_OUTCOME_UNKNOWN`,
`PROVIDER_ACKNOWLEDGED`, `VERIFIED_ABSENT`, and `VERIFIED_PRESENT`. The
after-effect drop produced a client `TypeError` while the fixture observed the
mutation; verification was unavailable, and retry count remained zero. The
before-effect drop verified presence. See `research/C-0R-ambiguity-result.json`.

Current BreakGlass is safe against blind destructive retry: its source at
`contract/src/lib.rs` handles DELETE errors/successes with verification and
moves ambiguous cases to reconciliation/failure. It cannot know from a
transport error whether GitHub received the request. “Destructive call
attempted” is a contract-side fact, not an independently observed provider
ack. The baseline gap remains.

## 10. R8 — Official reference race

**CODE-PROVEN ordering; LIVE-EVIDENCE-PROVEN host premise; provider effect not
proven.** The call-centre reference at commit
`bf08f0ba0fb1ce585696e78b7162a0785afab97f` implements:

`ledger::is_idempotency_key_used` (`contract/src/ledger.rs:127-139`)
`→ relay_client::call_pay` (`contract/src/relay_client.rs:47-84`)
`→ mark_idempotency_key_used` (`contract/src/pay.rs:107-133`).

The payment relay requires an IDK in the request, but the inspected `/pay`
route does not maintain a server-side dedupe map; mock mode returns a canned
response and real mode invokes the Circle CLI. The contract world does not
import outbox.

The safe local fixture in `research/c0r-reference-race.ts` synchronized two
calls after the marker read and before relay release. Both modeled calls read
unused, generated relay requests, and then wrote the marker; the result records
two relay requests and no external payment. This is not a live attack on the
reference and does not prove Circle executed duplicate money movement.

The live C-0/R2 T3N evidence proves the host premise that separate ordinary
calls can overlap before the transaction conflict/retry resolution. Combined
with the source ordering, the outbound relay-request race class is proven. A
provider-side duplicate payment remains unproven and must not be advertised.
The durable outbox design would remove this T3N-side ordering window only if
the interface is actually linked and the downstream connector is itself
idempotent.

## 11. R9 — AgentGate field position

AgentGate is an elite benchmark regardless of whether it is a formal challenge
submission. Inspected HEAD is
`d76f3570fb9bd41247dc1b8b63df74e3d183c4ec` at
[github.com/Anshv784/agentgate](https://github.com/Anshv784/agentgate).

**CODE-PROVEN:** its z contract has endpoint/path/marker policy, KV-backed
credential reads, HTTP-with-placeholders, response projection, an application
audit ledger, endpoint listing, and an MCP server with list/call/audit tools.
Its world does not import outbox. Important files are
`contract/src/gateway.rs`, `contract/wit/world.wit`, `mcp/server.ts`, and
`scripts/deploy.ts`.

**README-CLAIMED ONLY:** the README says the current testnet flow produced four
denials and a real Resend email, all under an org-minted agent. That live flow
was not independently reproduced during C-0R. **MOCK/DIAGNOSTIC:** the repo's
contract-probe and public echo diagnostics are not proof of the production
email path. No claim is made beyond the source/README distinction.

Against a current BreakGlass candidate, an elite AgentGate-style rival beats
it on maintainability, generic MCP integration, policy breadth, and 60-second
judge comprehension. It also has a stronger visible platform-bug contribution
story through its documented bug probes, though each bug's status must be
checked at source/live evidence level. Current BreakGlass is harder to follow
on its narrow vertical: an independently demonstrated destructive GitHub
action, exact target binding, private authority, and reconciliation behavior.
That edge is not enough by itself; AgentGate could add the vertical while
keeping its generic gateway/product loop.

## 12. Updated material register

The reopened register is appended to `research/C-0-MATERIAL-UNCERTAINTIES.md`.
It contains the required rows: outbox availability, connector config, outbox
ack, OCC reservation, activity binding, App JIT, webhook auth/dedupe,
post-effect ambiguity, and the official reference race. It also records the
bounded Merkle/public-proof and direct-GitHub-IDK negatives.

Final statuses are limited to the allowed vocabulary. The appended C-0R rows
contain no `UNKNOWN`; six are `PROVEN` and five are `PROVEN IMPOSSIBLE /
UNAVAILABLE`. There is no remaining
`BLOCKED_ON_EXTERNAL_ACCOUNT_CONFIGURATION` row. The
pre-existing C-0 rows remain historical evidence and are not silently edited
to pretend the old conclusion was different.

## 13. Original conclusions that changed

1. “No explicit CAS” no longer supports “no reservation.” Live ordinary KV
   OCC proves one committed winner, so an external reservation database is not
   required for that narrower property.
2. The receipt conclusion changes from “only guest/application JSON” to “YES,
   host activity is stronger than guest JSON,” while complete causal/Merkle
   binding remains unproven/unavailable in the current public path.
3. Durable outbox changes the platform-design ceiling materially, but not the
   current bounty-buildable ceiling: registration succeeded, execution did
   not, and no connector/ack/proof path is public to this tenant.
4. The provider ambiguity finding is sharper: current code avoids blind retry,
   but cannot establish provider receipt after a dropped response.
5. AgentGate's field weight increases from “adjacent/unconfirmed” to “elite
   benchmark with code-proven MCP/policy/product depth and separately labeled
   live claims.”

## 14. Ceiling candidates affected

The existing candidate documents remain historical and are not rewritten into
a new design. Their evidence status changes as follows:

* **Candidate 1 — Causal Remediation Broker:** strengthened because T3N OCC
  can supply a one-winner reservation; weakened because the current public
  path cannot prove outbox, JIT App exchange, provider fence, or causal
  receipt. It is not selected or frozen.
* **Candidate 2 — Agent Action Receipt / Authority Ledger:** activity metadata
  is now live, so its kill condition is narrower, but the causal target/action/
  provider binding is still absent and AgentGate/Aegis/AgentVault collision is
  real.
* **Candidate 3 — Autonomous Security Incident Loop:** webhook protocol is
  locally proven, but real GitHub ingress and App JIT remain externally gated;
  it remains a product-depth direction, not an authorized build.
* Any candidate whose differentiator requires current testnet outbox is dead
  for the bounty unless Terminal 3 enables it. Any candidate requiring an
  external reservation DB solely for one-winner selection is unnecessarily
  heavy after R2; a provider/effect fence is still a separate requirement.

## 15. Deepest evidence-derived architecture characterization

No new architecture is proposed or frozen. The deepest composition now
supported by evidence is only a ceiling characterization:

`verified cause`
`→ committed T3N authority/reservation`
`→ post-commit outbox if tenant-enabled`
`→ idempotent remediation connector`
`→ provider action`
`→ ack/activity/proof`

The **platform-design ceiling** is higher than C-0 knew because ordinary OCC
reservation and a typed durable outbox exist as distinct capabilities. The
**bounty-buildable ceiling** today is lower because outbox execution, tenant
connector setup, and public Merkle proof remain unavailable. App JIT is now
live-proven, but its standing private-key root and provider ambiguity limits
remain. This statement is not a V2 recommendation.

## 16. C-0R verdict and authorization gate

**C-0R verdict: COMPLETE.** The missed material threads are now proven,
disproven, or bounded unavailable by evidence; no material thread remains
parked behind a generic future-testing placeholder.
The GitHub App JIT provider sequence is live-proven; its standing private-key
root is preserved in the conclusion.

**C0 may begin: NO.** No product implementation, V2, public-main mutation, or
submission work is authorized by this report.
