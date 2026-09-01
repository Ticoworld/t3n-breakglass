# C-0 Coverage and Exhaustion Check

Research/retrieval date: 2026-09-01. This is a record of search surfaces, not a claim that the entire internet was searched.

## Coverage table

| Area | Searched | Important findings | No-finding areas | Remaining question / final status |
|---|---|---|---|---|
| Official Terminal 3 docs | [docs index](https://docs.terminal3.io/llms.txt), architecture, consensus, TEE, host API, z namespace, ADK, agent auth, maps, placeholders, reference, changelog links. | TEE/capability host, tenant context, egress, private maps, org agents, grants, placeholders, ledger/audit/activity concepts. | No public turnkey incident/JIT/provider-token primitive found in the reviewed index. | Current design cannot claim a host-native incident capability; PROVEN IMPOSSIBLE / UNAVAILABLE for current world. |
| Terminal-3 GitHub | Official org repos, `t3-claw`, `z-tenant-flight`, getting-started, call-centre demo, hedera plugin. | T3Claw claims sandbox/capability/credential/prompt-injection defenses and cron/event routines; flight contract uses private credential + placeholder HTTP; official reference agents close business workflows. | No public BreakGlass-equivalent event-to-remediation contract or public host CAS implementation found. | T3N owns much of the substrate, so wrappers have low novelty; missing cross-boundary mechanism remains. |
| Current SDK/version surfaces | `@terminal3/t3n-sdk` local `5.2.0` declarations, package metadata, contract WIT `2.1.0`, tenant WIT `1.0.0`, repo package lock. | Wider declarations include grants/windows, org policy, audit/activity, workload auth, contracts-call, mutation responses. Current world imports only four packages. | Official source repository for the installed package was not publicly accessible from the inspected GitHub URL. | SDK declarations are code-proven locally; deployability/live use of unused surfaces is PROVEN IMPOSSIBLE / UNAVAILABLE. |
| Current reference agents/products | Official T3Claw, z-tenant-flight, T3 use-case delegate-access page, ADK product page. | T3 itself describes sensitive credentials in T3N, agent preparation/approval, outbound ERP/payment, and audit. | No official reference with verified event-bound one-use provider remediation found. | Current thesis must be above identity/secret/egress/audit. |
| Public T3N competitors | Terminal 3 GitHub topic (15 public repos observed), direct repos for Aegis, Release Sentinel, AgentVault, Proofly, MediPass, Conviction Agent, Credora, Ethereum-Agentic, ClearanceFlow, ProcureMind, SameDayDesk. | Field has complete workflows, signed delegation, red-team claims, compliance proofs, CI/CD gates, financial/medical use cases. | Exact current repository named “T3N Sentinel” absent; “AgentGate” only adjacent/unconfirmed as a T3N submission. | Field-relative current BreakGlass is NOT COMPETITIVE ENOUGH; repo claims vs live evidence are separated. |
| Superteam challenge | [T3N Agent Build Challenge](https://superteam.fun/earn/listing/t3n-agent-build-challenge). | 55 submissions observed; usefulness, quality, maintainability, docs, bugs are explicit judging pressures; 290 USDC pool. | No public full submission archive/API surfaced in reviewed page. | Complete loop and maintainability matter as much as primitive correctness. |
| GitHub security docs | Deploy keys REST, webhook events/headers, validation, best practices, failed deliveries, App JWT, installation tokens, App private keys, token revocation, Actions OIDC. | HMAC/delivery dedupe, App scoped one-hour token, non-expiring private key, 204/404 delete semantics, no documented deploy-key delete event. | GitHub docs do not expose transactional idempotency/CAS for deploy-key DELETE. | Provider effect fence cannot be delegated to documented API; PROVEN IMPOSSIBLE / UNAVAILABLE. |
| PAM/JIT/PIM | Azure PIM, Teleport, BeyondTrust, CyberArk ZSP. | Eligible/active role, approvals, TTL, session/audit, zero-standing patterns, escalation. | No adjacent product solves T3N KV + GitHub effect transaction. | Borrow approval/TTL/audit semantics, not UI; effect seam remains. |
| Cloud/workload identity | AWS STS, Google WIF, SPIFFE/SPIRE, RFC 8693. | Short-lived exchange, audience/scope, workload identity, actor/subject delegation; expiry is not revocation/one-use. | No token exchange makes arbitrary GitHub DELETE atomic. | JIT provider credential is feasible but standing trust root persists. |
| Capability security | Macaroons, UCAN, object-capability research. | Attenuation, caveats, delegation, references, confused-deputy avoidance. | No capability format alone guarantees single-use external effects. | Use opaque attenuated handle plus receiver-side reservation. |
| SOAR/incident systems | AWS Incident Manager and event-sourcing pattern. | Detection -> response plan -> engagement/escalation -> findings/postmortem; append-only event/projection model. | No SOAR product makes T3N the provider-effect receipt by default. | Complete operational loop is a product layer; current loop starts too late. |
| Agent-security research | InjecAgent, AgentDojo, OWASP LLM/MCP, Invariant Labs tool poisoning. | Prompt/tool output attacks and excessive agency are practical; code-side authority limits are necessary. | No source directly tests BreakGlass. | Current fixed arguments help, but race/wrong-reconcile are product-specific proven failures. |
| Own repository roadmap | `rg` over `README.md`, `docs`, `scripts`, `contract`, `tests`, `review` for future/later/TODO/roadmap/not implemented/out of scope/limitation/follow-up/optional/next. | Existing docs explicitly defer emergency action instructions, richer actions, independent evidence/receipt, and note SDK/log limitations; threat model excludes operator compromise. | No hidden implementation of CAS, event ingress, App token minting, or audit host call found. | Deferred items include winner-level mechanisms; they cannot be treated as low-value polish. |

## Unresolved-question disposition

The search areas above have no material C-0 question left open without a status. The items that would otherwise be “unresolved” are closed as follows:

- Can current T3N KV fence a concurrent provider effect? No: current surface lacks CAS/lease, and the live race disproved the existing fence.
- Can current BreakGlass authenticate an evidence event? No: it has no event ingress/HMAC path; GitHub HMAC is feasible only in a new gateway.
- Can current BreakGlass mint a provider token? No: the component has no token/signing import; GitHub App minting is an external composition with a standing App key.
- Can current BreakGlass emit an independent receipt? No: current WIT does not use audit/activity; SDK declarations make a later experiment feasible but do not prove current deployment binding.
- Which next candidate should be built? This is a product decision, not an archaeological unknown. Candidate 1/2/3 are documented with kill conditions in `C-0-CEILING-CANDIDATES.md`.

Every item is therefore PROVEN, DISPROVEN, PROVEN IMPOSSIBLE / UNAVAILABLE, or NON-MATERIAL. Material `UNKNOWN` count is zero.

## Repository evidence inventory

- Public code: `contract/src/lib.rs`, `contract/src/authority.rs`, `contract/wit/world.wit`, `scripts/incident-create.ts`, `scripts/create-incident.ts`, `scripts/lib.ts`, `scripts/product.ts`, `scripts/agent-tool.ts`.
- Existing live evidence: `evidence/phase1-wrong-agent.json`, `evidence/phase1-invocation-reconcile-stuck-execution.json`, `evidence/phase2e/phase2e-live-proof.json`.
- C-0 live evidence: `research/C-0-race-result.json`, `research/C-0-wrong-reconcile-result.json`, `evidence/phase2-incident-inc-c0-race-1788258001834.json`.
- Public HEAD remained unchanged at `4a077035474337b7a1ad16204820e68ed3020477`.

## Exhaustion conclusion

The material archaeology needed to classify the current baseline and kill its current thesis is complete. The next decision is not blocked by an unlabelled fact: it is a design choice constrained by proven platform gaps and live failures. C0 implementation is still **NO** because the current product thesis is falsified and Candidate 1/2/3 require an explicit ceiling selection and validation gate before construction.
