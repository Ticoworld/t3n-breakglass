# C-0 Ceiling Candidates

Research date: 2026-09-01. These are evidence-derived directions after the current thesis attack, not implementation authorization or feature requests.

## Candidate 1 — Causal Remediation Broker

**Short thesis:** A verified GitHub security signal becomes a private, policy-bound, one-action remediation capability whose provider authority is minted just in time and whose final receipt is independently verifiable.

**Causal derivation:** T3N already supplies agent identity, private state, TEE, egress, and activity surfaces. Current BreakGlass shows the value of target-frozen remediation but fails at event authenticity, concurrency, standing PAT, and receipt. GitHub supplies HMAC delivery identity and scoped, expiring App installation tokens. The missing composition is a causal broker across those boundaries.

**What BreakGlass becomes:** The remediation executor is the last stage of a detector -> evidence -> policy -> capability -> provider action -> verification -> receipt loop.

**New mechanism:** An external GitHub delivery gateway verifies raw HMAC and dedupes `X-GitHub-Delivery`; it commits a canonical evidence digest/installation/repository/key record. A T3N authority references that digest and a signed policy decision. An action broker mints a repository/permission-scoped installation token only after eligibility and explicitly revokes it after verification. A reservation/nonce service fences concurrent execution before DELETE.

**Why T3N is load-bearing:** Private evidence and authority state, agent DID/grants, TEE policy kernel, egress restriction, and a host activity/audit receipt. A plain web app can imitate the flow but not the same T3N boundary if the receipt is real.

**Enterprise job / agent / human:** Detect unauthorized deploy key or security event; automatically remediate under policy. Agent evaluates bounded evidence and calls only the opaque action capability. Human defines policy, approves high-risk classes, and handles ambiguity/escalation rather than approving every routine delete.

**Standing authority:** GitHub App installation/configuration, App private key or broker identity, webhook secret, T3N tenant owner/policy, and reservation/evidence service. **JIT:** installation token, exact incident capability, provider action budget. **Single-use/revocable:** reservation nonce/capability and installation token; App private key remains standing and must be rotated.

**External systems / live demo:** GitHub webhook -> T3N evidence -> hostile agent -> GitHub App token -> disposable deploy-key delete -> exact GET/list -> revoke token -> host/provider receipt. Hostile demo races calls, replays delivery, changes target, and attempts credential exfiltration.

**Concurrency/failure/receipt:** One reservation winner before outbound call; no DELETE on losers. Provider timeout becomes UNKNOWN_EFFECT/RECONCILE with separate authorized recovery. Receipt contains delivery ID/HMAC-verified digest, evidence hash, policy/intent, actor DID, reservation, provider token scope hash, request/result IDs, final GET, and T3N activity sequence/hash.

**Competitor collision:** Aegis/AgentVault collide on delegation/audit; Release Sentinel on event-driven policy gate. They do not trivially provide GitHub-specific provider token/effect verification, but this is a claim to prove, not a marketing moat.

**2–3x rival:** A rival would add multi-provider provider-token brokerage, approval/escalation, incident timeline, rollback/recovery, and independently signed receipts while preserving one narrow action demo.

**Feasibility/time/ceiling:** Medium-high if external gateway/broker is allowed; high if pure T3N contract is required because current WIT lacks event/crypto/audit/CAS. Rough bounty scope: 1–2 weeks for a narrow GitHub proof, longer for truly platform-native receipt/reservation. High win ceiling because it closes a recognizable security job and visibly attacks the current race. **Kill condition:** cannot prove reservation before DELETE, cannot independently anchor receipt, or App private key handling creates more standing authority than the PAT removes.

## Candidate 2 — Agent Action Receipt / Authority Ledger

**Short thesis:** T3N becomes the verifiable control plane for high-risk agent actions: every action is an attenuated, time-bounded capability with a causal receipt, regardless of provider.

**Derivation and mechanism:** AgentVault/Aegis/Proofly show demand for scoped delegation and signed proof; T3N already has identity, private state, TEE, and activity declarations. BreakGlass supplies an adversarial external-effect case. The new mechanism is a provider-neutral receipt/nonce protocol, with one GitHub adapter as proof rather than a multi-provider wrapper.

**Enterprise job:** Security, finance, or operations teams can ask “which agent, under what human/policy/evidence, touched which external resource, with what exact scope and result?” Agent executes a capability; human sets policy and reviews exceptions.

**Standing/JIT:** Trust root, policy, provider installation, and broker remain; action capability and provider session are JIT. Revocation/expiry and receipt are first-class.

**Demo/security:** GitHub deploy-key remediation with a hostile agent; show the same receipt schema rejecting target substitution, replay, wrong DID, and malformed evidence. External systems GitHub + T3N + gateway.

**Receipt/failure:** Causal receipt is the product; provider ambiguity remains explicit. Concurrency needs nonce/reservation, not KV state alone.

**Collision/2–3x rival:** Aegis and AgentVault are direct collisions. A rival can win by supporting multiple real provider effects, an approval/incident UX, and independently verified host receipts. The candidate dies if T3N activity/audit cannot be retrieved and linked by a judge.

**Feasibility/time/ceiling:** Medium; more general but harder to make memorable. High mechanism ceiling, weaker 60-second comprehension than Candidate 1. Kill condition: becomes another signed JSON/application audit library.

## Candidate 3 — Autonomous Security Incident Loop

**Short thesis:** A T3N-native incident runbook closes detection, policy, action, recovery, and post-incident evidence for a specific GitHub class of compromise, with humans governing policy rather than manually operating each incident.

**Derivation:** SOAR/Incident Manager proves enterprise value comes from complete lifecycle; current BreakGlass starts at operator selection. Add verified webhook/detection, policy escalation, monitoring, recovery, and evidence while retaining T3N private authority.

**Mechanism/role:** Event gateway creates a deduped evidence record; agent triages; policy creates or denies a capability; broker executes; verifier closes/escalates. Human sets thresholds and resolves ambiguous provider state. Standing roots and App key remain; incident action/token are JIT.

**Demo:** Create a suspicious deploy key, deliver a signed event, show auto-triage, run hostile agent, delete/verify/revoke, replay event and call concurrently, show one receipt and one escalation path.

**Collision:** Release Sentinel, AWS Incident Manager, Aegis, and SOAR products compete on lifecycle. The differentiation is T3N-backed confidential action authority and provider receipt.

**Feasibility/time/ceiling:** Medium; highest product/judge value if kept to one incident class. Kill condition: monitor/agent is decorative and no provider credential/effect proof exists.

## Comparative conclusion

Candidate 1 has the strongest combination of novelty, judge comprehension, and concrete depth, but only if reservation and receipt can be proven. Candidate 2 is the deepest reusable mechanism but collides with generic delegation/audit projects. Candidate 3 has the strongest complete-loop story but can collapse into SOAR plus a T3N wrapper. No candidate is authorized for C0 implementation by this archaeology report.
