# C-0 Code-Level Attack

Audit date: 2026-09-01. Repository commit audited: `4a077035474337b7a1ad16204820e68ed3020477`.

## Attack matrix

| Question | Result | Evidence / status |
|---|---|---|
| Can two callers both see ACTIVE? | Yes in the live platform path. Both simultaneous invocations returned `previous_status: EXECUTING`, `CONSUMED`, and a DELETE 204. | `research/C-0-race-result.json`; fresh private `Ticoworld/t3n-breakglass-sandbox` key 161935325; LIVE-EVIDENCE-PROVEN |
| Does KV expose CAS/version conditions to this component? | No. The current world imports only `kv-store 2.1.0`; visible WIT exposes get/put/delete/scan and no compare-and-swap or conditional put. The SDK tenant `entrySet` also returns void. | `contract/wit/world.wit`; `contract/wit/deps/host-interfaces-2.1.0/package.wit`; local `node_modules/@terminal3/t3n-sdk/dist/index.d.ts:5874`; CODE-PROVEN |
| Does T3N serialize entire invocations? | No such safety property can be claimed; the live race disproves serialization sufficient to protect the external effect. | Live race artifact; LIVE-EVIDENCE-PROVEN |
| Is reconciliation DID-authorized? | No. The status branch at `lib.rs:85-90` calls `reconcile` before `calling_user_did` is read or compared. | `contract/src/lib.rs:85-90,291-354`; CODE-PROVEN |
| Did a wrong DID actually reach reconciliation? | Yes. Operator DID invoked an existing RECONCILE_REQUIRED incident, caused provider GET, and got a persisted reconciliation result. | `research/C-0-wrong-reconcile-result.json`; LIVE-EVIDENCE-PROVEN |
| Could wrong reconciliation DELETE? | Not through the current reconciliation function: it calls GET only. The authorization flaw is still material because it grants unauthorized provider-read and state-mutation authority, and it can affect lifecycle decisions. No claim of wrong-DID DELETE is made. | `contract/src/lib.rs:291-354`; CODE-PROVEN |
| Can precheck failure strand an authority? | Yes. `begin_execution` writes EXECUTING before the precheck. Any transport error, non-200, or malformed body returns PRECHECK_FAILED without restoring ACTIVE. | `contract/src/lib.rs:112-155`; CODE-PROVEN |
| Is duplicate target authority prevented? | No. Incident uniqueness is by map key/ID only; the authority schema has no target index or reservation. INC-A and INC-B can encode the same owner/repo/key. | `contract/src/authority.rs:22-71`; `scripts/incident-create.ts:151-163`; CODE-PROVEN |
| Is there provider-side conditional delete? | No. DELETE has no ETag/If-Match or equivalent version condition. | `contract/src/lib.rs:414-435`; CODE-PROVEN |

## Concurrency trace

The intended serial trace is:

`GET ACTIVE -> validate -> PUT EXECUTING -> GET provider -> DELETE -> GET provider -> PUT CONSUMED`.

The live trace shows the actual safety boundary is weaker:

`A: GET ACTIVE / B: GET ACTIVE -> A: PUT EXECUTING / B: PUT EXECUTING -> A: DELETE / B: DELETE -> both GET 404 -> both report CONSUMED`.

The final map has `uses: 1`, but that ledger value is not a reservation on the provider call. Both requests were issued before either caller could rely on the final state. GitHub returned 204 to both calls; because DELETE is idempotent, the final absence does not tell us whether GitHub applied one or two independent effects. The important claim is narrower and proven: at-most-one destructive request is false.

The disposable test was destructive only to a newly created read-only deploy key in a private sandbox repository. Before/after evidence is in `evidence/phase2-incident-inc-c0-race-1788258001834.json` and the invocation result is in `research/C-0-race-result.json`; no secret value was printed.

## State ordering and liveness

Persisting EXECUTING before the external precheck is a safety-minded ordering, but it creates a stranded state if the precheck fails before any DELETE. The contract returns `PRECHECK_FAILED`, while a later invocation enters reconciliation because the persisted status is EXECUTING. Reconciliation can only GET; if the provider is still unavailable, the state remains RECONCILE_REQUIRED. This is safe against blind DELETE retry, but not an acceptable emergency completion guarantee.

The right deeper abstraction is not “move the write later.” It is a durable reservation with an effect budget, an explicit `NOT_ATTEMPTED` versus `UNKNOWN_EFFECT` distinction, and a recovery authority that is separately authorized and observable. Current KV/API surfaces do not provide that reservation primitive.

## Authorization partition failure

There are three authorities in the code but only two are separated:

1. destructive authority: normal ACTIVE branch, DID/time/action checked;
2. read/reconciliation authority: `reconcile`, no DID/time check;
3. state mutation authority: both branches persist the incident.

The code treats (2) as safe because it does not issue DELETE. That is incorrect: it is still provider-read authority and trusted-state mutation authority. The live wrong-DID test demonstrates the path is invocable under the current deployment grant.

## Other attack surfaces

- Prompt-injected agent: fixed tool schema prevents target/action substitution, but a compromised agent can race/repeat calls; serial replay protection is insufficient.
- Tool-result poisoning: current contract has no untrusted event/tool-result input, so this particular path is not exposed; future event ingestion must verify raw payloads before creating authority.
- Cross-tenant action: tenant-derived map key and T3N tenant boundary constrain normal contract access. This is a surviving invariant, not proof against a compromised tenant owner.
- Scope widening: authority shape is fixed, but the PAT's provider permissions are wider than one incident and are not made JIT.
- TOCTOU: operator and contract prechecks are snapshots. The provider can change between GET and DELETE; no conditional version is supplied.
- Audit forgery: contract proof fields are guest-generated output. They can describe what the code believes happened but do not independently prove raw request delivery, provider identity, or a unique transaction receipt.

## Code-level verdict

The current state machine is a useful fail-closed attempt around one provider action. It is not a concurrency-safe one-use capability, not a caller-complete reconciliation protocol, and not an evidence-bound authority system. These are CODE-PROVEN or LIVE-EVIDENCE-PROVEN failures, not test backlog items.
