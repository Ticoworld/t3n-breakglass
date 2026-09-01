# C-0 Failure Patterns and Why They Matter

Audit date: 2026-09-01. This file converts the Remit/Sluice lessons plus code and field evidence into adversarial criteria.

## Shared warning

“The core works” is a fallback signal. Remit stopped at bounded execution and lost to PactAgent's complete agreement-to-payout loop. Sluice proved a real liquidity flow and then pushed its deepest protocol/economic ideas into future work while a rival closed provider discovery, pricing, rent, proof, and refund. BreakGlass currently risks the same failure: a credible T3N primitive is being mistaken for a winning product.

## Failure-pattern table

| Pattern | Current BreakGlass | Stronger physical control | Executable proof |
|---|---|---|---|
| Prompt injection | Agent cannot change target/action fields, but can invoke the fixed incident and race repeated requests. | Contract-side nonce/reservation and effect budget; model output never chooses target. | Hostile agent calls tool concurrently/repeatedly; current race already demonstrates failure. |
| Poisoned tool result | Current flow has no external event/tool-result input. | Verify source signature/raw payload before evidence is eligible; bind digest, delivery ID, and source identity. | Feed altered webhook body/signature and require no authority creation. |
| Malicious event payload | No event path, so no current exposure; also no verified-event capability. | HMAC + schema + source/repository installation binding + replay dedupe before T3N commit. | Invalid HMAC, valid HMAC wrong repository, duplicate delivery. |
| Credential exfiltration | Normal agent process does not see PAT; contract guest does. | Host-resolved short-lived App token or token broker; never return credential to guest/output. | Inspect process/output and deliberately attempt secret-return paths. |
| Tool-argument substitution | Strongly reduced by `{incident_id}` only and `deny_unknown_fields`. | Retain capability handle, make target/action immutable and non-model-readable where possible. | Fuzz extra fields, path segments, Unicode, JSON duplicates. |
| Confused deputy | Fixed target reduces deputy risk; wrong DID can invoke reconciliation and mutate trusted state. | Separate destructive, read, and lifecycle authorities, each caller-bound. | Wrong agent/operator invokes each state and compare provider calls/state writes. |
| Cross-tenant action | T3N tenant map isolation is a real control. | Keep tenant-bound capability and verify target belongs to evidence tenant. | Attempt foreign map/incident and inspect no provider request. |
| Scope widening | Application action is fixed; provider PAT scope is wider than target. | GitHub App token constrained to exact repository and Administration permission; broker policy rejects widening. | Attempt token use against second repository and wrong endpoint. |
| Replay | Serial consumed replay is refused. Concurrent replay is not effect-safe; webhook replay has no delivery ledger. | Atomic reservation/nonce or provider-side idempotency key plus dedupe. | Two simultaneous calls and duplicate webhook delivery. |
| Stale authorization | Contract cluster-time check exists in ACTIVE path; operator clock equivalence is not proven. | Host-issued validity window/receipt, bounded skew, and state expiry independently enforced. | Boundary timestamps, delayed queue, clock skew simulation. |
| TOCTOU | GET precheck then DELETE; no ETag/If-Match. | Provider conditional request or re-fetch under a broker lock; explicit changed-target outcome. | Change key between precheck and delete in disposable repo. |
| External-action ambiguity | No DELETE retry; GET reconciliation. | Distinguish not-attempted, sent/unknown, provider-acknowledged, and verified; manual/automated recovery policy. | Drop response after provider effect and after no effect. |
| Audit forgery | Guest JSON says what happened; weak app reference. | Host-stamped activity/audit entry plus provider delivery/request IDs and signed digest. | Compare receipt to node activity and provider response under tampered output. |
| Approval spoofing | Trusted operator map write; no signed human intent/evidence relationship. | Human approval is a signed policy decision over an immutable evidence digest and exact target. | Alter target/evidence after approval and require denial. |
| Operator compromise | Explicitly out of scope in current threat model, but operator can create arbitrary incidents and control the PAT map. | Split event verifier, policy approver, and executor; use narrow provider credentials. | Compromised operator fixture attempts invented incident. |

## Complete-system failure test

The judge-visible loop must include cause/detection, policy, authority issuance, execution, provider verification, expiry/reconciliation, and a receipt. A one-action MCP tool with docs/tests is still one shallow capability. The current baseline fails this test even where its individual primitive is sound.

## Material conclusion

The most important failure is not that a model can be tricked into selecting a bad string. The important failure is that the system grants an external destructive capability without an atomic effect reservation, without a verified causal trigger, and with a provider credential whose standing scope exceeds one incident.
