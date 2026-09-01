# C-0R platform-impossibility proof packs

Research date: 2026-09-01. These are bounded claims about the current public
BreakGlass contract world and the public testnet tenant-z execution path. They
are not claims that Terminal 3 can never add or privately enable a capability.
The distinction matters: a vendored WIT interface, an SDK declaration, and a
registered tenant-world import are different evidence levels.

## Common search trail

| Search layer | Exact material inspected | Result |
|---|---|---|
| SDK | `@terminal3/t3n-sdk 5.2.0`, `node_modules/@terminal3/t3n-sdk/dist/index.d.ts`; searches for `outbox`, `enqueue`, `conditional`, `compare`, `CAS`, `lease`, `lock`, `proof`, `getActivityLog`, `getAuditEvents` | Public client exposes activity/audit reads and map/contract operations, but no tenant outbox client, KV CAS method, lease/lock method, or Merkle-proof client method. |
| WIT | BreakGlass `contract/wit/world.wit`; pinned `host-interfaces@2.1.0`, `host-tenant@1.0.0`; vendored `host-outbox@1.0.0` | Current BreakGlass imports tenant context, logging, KV, and HTTP only. Broader packages contain signing, clock, contracts-call, audit, and outbox definitions, but those imports are not in the BreakGlass world. |
| Reference contracts | `Terminal-3/adk-circle-call-centre-agent-demo` at `bf08f0ba0fb1ce585696e78b7162a0785afab97f`; `Terminal-3/z-tenant-flight` at `1226b396ac909379df0814308c5c9ea055e703f`; `Anshv784/agentgate` at `d76f3570fb9bd41247dc1b8b63df74e3d183c4ec` | All three vendor the outbox WIT; none imports it in the tenant world inspected. The call-centre README/world explicitly says the real ABI definition is not linked into tenant-z worlds yet. |
| Official docs | Host API, ADK reference, consensus, KV-map tips, GitHub webhook/App/deploy-key docs; URLs in `C-0R-SOURCE-LEDGER.md` | Outbox is documented as Coming soon; ordinary KV writes are transactional; activity/audit surfaces are public SDK surfaces; GitHub App/token and webhook rules are documented. |
| Live testnet | `C-0R-outbox-result.json`, `C-0R-outbox-link-result.json`, `C-0R-occ-result.json`, `C-0R-audit-result.json` | Outbox component registration was accepted, but both an enqueue call and a no-op function in a component importing outbox failed with JSON-RPC `-32603 Internal error` and no contract logs. Ordinary KV OCC reservation committed one winner. Activity metadata was retrievable. |

## Claim-by-claim closure

### 1. Explicit CAS / conditional KV write

* Search: SDK `TenantMapsNamespace.entrySet` and map mutation types; WIT
  `host:interfaces/kv-store` `get`, `put`, `delete`; all three reference worlds.
* Result: no explicit `compare-and-swap`, version precondition, or conditional
  write is exposed to this guest world. The visible map `entrySet` is a
  control-plane mutation and has no conditional argument.
* Correct classification: **PROVEN IMPOSSIBLE / UNAVAILABLE for an explicit
  CAS method in the current contract world**.
* Important correction: this does **not** mean reservation is unavailable.
  Live R2 proves ordinary transactional `get` + `put` uses OCC read/write
  conflict detection and yields one committed winner. The former C-0 claim
  that no explicit CAS implied no reservation has been superseded by the
  live result, not by assumption.

### 2. Leases / locks

* Search: current BreakGlass WIT, pinned host WIT names and functions, SDK
  declarations, reference worlds, and host API capability table.
* Result: no tenant-importable lease, lock, fencing-token, or lock-renewal
  operation was found. `EXECUTING` is a BreakGlass KV state, not a host lease.
* Correct classification: **PROVEN IMPOSSIBLE / UNAVAILABLE for a tenant
  lease/lock primitive in the current public contract world**. No conclusion
  is made about private/system-only services.

### 3. Webhook ingress inside current BreakGlass

* Search: BreakGlass scripts/WIT, SDK HTTP/contract surfaces, current public
  docs and reference worlds.
* Result: no inbound HTTP listener, webhook delivery receiver, or contract
  function that accepts a GitHub raw webhook exists. The current app creates
  incidents by an operator-side map write.
* Correct classification: **PROVEN IMPOSSIBLE / UNAVAILABLE in the current
  BreakGlass contract/application boundary**. This does not say Terminal 3 has
  no external ingress product; it says no such ingress is present or
  tenant-importable here.

### 4. In-contract HMAC verification

* Search: BreakGlass `world.wit`; current host WIT imports; SDK crypto/signing
  declarations; current reference worlds.
* Result: the current BreakGlass component has no crypto or signing import and
  no raw inbound bytes to verify. The broader `host-interfaces@2.1.0` package
  contains a signing interface, but it is not in this world and is not proof of
  a tenant-callable HMAC verifier.
* Correct classification: **PROVEN IMPOSSIBLE / UNAVAILABLE in the current
  BreakGlass contract world**. R6 separately proves that a gateway can perform
  the exact raw-body HMAC/delivery-ID protocol outside the contract.

### 5. Provider-token minting

* Search: BreakGlass WIT/source, SDK declarations, current reference worlds,
  host API capability table, and GitHub App official API docs.
* Result: T3N HTTP can send a credential already available to the component;
  current BreakGlass has no GitHub App JWT signer, installation-token exchange,
  token revoke call, or provider-token broker. GitHub itself documents the
  exchange and revoke APIs, but that is an external provider capability.
* Correct classification: **PROVEN IMPOSSIBLE / UNAVAILABLE in the current
  BreakGlass contract world**. A GitHub App private key plus a broker could
  make the external sequence possible, but R5 is blocked on account setup and
  does not claim it was live-proven.

### 6. Host audit import / independently verifiable proof

* Search: BreakGlass WIT; `host:interfaces@2.1.0` audit interface; SDK
  `getAuditEvents`, `getActivityLog`, contract logs; public docs.
* Result: BreakGlass does not import host audit. The SDK can retrieve activity
  entries with host sequence/hash/timestamp/actor/org/contract/function/outcome.
  R4 retrieved those fields after a live invocation. No public SDK method for
  a Merkle proof was available, and no proof was retrieved.
* Correct classification: **PROVEN IMPOSSIBLE / UNAVAILABLE for host-audit
  import and Merkle-proof retrieval in the current BreakGlass deployment and
  public SDK surface**. The stronger activity receipt is nevertheless
  **PROVEN** as a separate live capability.

### 7. Provider-side atomic DELETE fencing

* Search: GitHub deploy-key REST documentation, GitHub webhook/event docs,
  current BreakGlass HTTP client, outbox WIT, and reference relay code.
* Result: GitHub documents deploy-key DELETE and status responses but no
  idempotency-key or conditional-fence contract for DELETE. Current BreakGlass
  uses a sealed long-lived PAT and synchronous DELETE. The outbox WIT would
  add T3N-side at-most-once delivery only if an allowed connector exists; its
  connector is not available on the public testnet tenant path.
* Correct classification: **PROVEN IMPOSSIBLE / UNAVAILABLE for a
  provider-side atomic fence in the current BreakGlass/GitHub path**. It is
  not a claim that a purpose-built idempotent remediation connector could not
  supply one.

### 8. Documented deploy-key deletion webhook

* Search: current GitHub `deploy_key` webhook event documentation and event
  payload index, retrieved 2026-09-01.
* Result: the documented deploy-key event action is `created`; no documented
  `deleted` action was found. REST deletion remains observable by an explicit
  read, not by a claimed deletion webhook receipt.
* Correct classification: **PROVEN IMPOSSIBLE / UNAVAILABLE as a documented
  GitHub deploy-key deletion event dependency**. This is intentionally limited
  to the public documented event schema.

## Why these are not merely “not found”

The unavailable classifications combine: (1) exact negative searches across
the installed SDK and guest WIT, (2) inspection of the current public reference
worlds, and, for outbox, (3) a registered component plus a testnet invocation
that reached the node and failed before guest logs with `-32603`. A no-op link
probe also failed before guest output, so the result is not explained only by
the downstream connector or upstream-host allowlist. Where the
evidence is only an SDK/WIT negative, the scope says “current public contract
world” rather than “entire Terminal 3 platform.” Where a related capability is
actually live (ordinary OCC and activity), the register records it as proven
instead of preserving the old negative inference.
