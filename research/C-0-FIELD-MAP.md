# C-0 Current T3N Bounty Field Map

Research/retrieval date: 2026-09-01. The public field was re-searched through the [Terminal 3 GitHub topic](https://github.com/topics/terminal3), current public repositories, and the [T3N Agent Build Challenge listing](https://superteam.fun/earn/listing/t3n-agent-build-challenge). The listing showed 55 submissions, a 290 USDC pool, and judging emphasis on quality/usefulness, maintainability, documentation, and bugs. Those counts are time-sensitive and were observed on the retrieval date.

## Evidence-ranked field

The ranking below is relative to BreakGlass's current complete-loop depth, not a claim about judges' final decisions. README statements are labeled as repository claims; live status is not upgraded without a reproducible artifact.

| Project | Problem / complete loop | T3N/security/depth evidence | What a judge sees in 60 seconds | Why it beats current BreakGlass | Collision / limitation |
|---|---|---|---|---|---|
| **Aegis** — `Risingtell/aegis`, latest observed `e6437e3` | Healthcare claims/reimbursements: patient delegation -> agent request -> policy/limits -> live/mock executor -> audit. | Repo claims patient and agent signatures, request hash, nonce, validity, revocation, function scope, payee/cap, disclosure; claims red-team 7/7 including payout redirect, overspend, PHI exfiltration, MITM, replay, revocation, wrong key. Source: [repo](https://github.com/Risingtell/aegis), retrieved 2026-09-01. Treat live depth as repo-claimed, not independently proven here. | A high-stakes payment/PHI scenario and a visible hostile-agent harness. | More complete enterprise job, stronger cryptographic delegation, explicit adversarial proof, money and privacy stakes. | It also uses the familiar TEE/agent-signature/audit substrate; current public evidence does not establish all claimed live executions. |
| **Release Sentinel** — `WNZhao/t3n-release-sentinel`, latest observed `bd63e43` | Private CI/CD release gate: event/change context -> policy evaluation -> approved/blocked decision -> release/rollback evidence. | Repo claims contract 777 v0.1.4, private policy, TEE, 8 decision reasons, live sandbox, 2 TS + 5 Rust tests + strict typecheck. Raw linked live proof was unavailable during this audit. Source: [repo](https://github.com/WNZhao/t3n-release-sentinel), retrieved 2026-09-01. | A recognizable enterprise gate with immediate approved/blocked outcome and tests. | Closes a useful workflow and makes policy outcomes visible; more maintainable/product-shaped than one destructive action. | No demonstrated provider-side JIT credential/effect fencing was found; live claim remains repository evidence. |
| **AgentVault** — `Samfresh-ai/agentvault`, latest observed commit `59db923` | Scoped, time-limited, revocable credentials to sub-agents with immutable signed audit. | 14 public commits and README thesis; implementation/live depth not independently replayed. Source: [repo](https://github.com/Samfresh-ai/agentvault), retrieved 2026-09-01. | “Issue/revoke/audit a sub-agent credential” maps directly to the sponsor problem. | Competes at the generic authority layer and claims the capability BreakGlass currently lacks. | Similar claims may be application-level; provider-side effect semantics are not established from public evidence. |
| **Proofly** — `edycutjong/proofly`, updated 2026-08-22 | Compliance proof in TEE: one verify function -> SD-JWT/OID4VP signed yes/no -> no PII -> live demo. | 32 commits/11 PRs observed; repo points to auth, agent, contract, and live verification code. Source: [repo](https://github.com/edycutjong/proofly), retrieved 2026-09-01. | One decision, small privacy-preserving output, visible live proof. | Stronger independent verifiability and a crisp end-to-end decision loop. | Not an emergency remediation competitor; less relevant external side-effect depth. |
| **MediPass** — `uvindev/medipass` | Cross-border medical identity, selective disclosure, portal/coverage/hooks/scripts/tests. | 40 commits observed; README claims real T3N testnet and a four-tool chain. Source: [repo](https://github.com/uvindev/medipass), retrieved 2026-09-01. | Full user workflow around identity/coverage rather than a primitive. | Product completeness, privacy, and multiple integrated steps. | Live claims were not independently reproduced; not directly competing on emergency privilege. |
| **Conviction Agent** — `ryonzhang/t3-conviction-agent` | Delegated trading mandate -> calibrated signals -> bounded brokerage execution. | README claims hardware-sealed brokerage credentials, allowed symbols, conviction, max size, daily loss, one commit observed. Source: [repo](https://github.com/ryonzhang/t3-conviction-agent), retrieved 2026-09-01. | Agent acts under visible financial limits. | Stronger autonomy and explicit economic constraints. | Evidence depth is shallow/one-commit; provider effect and red-team proof not established. |
| **Ethereum-Agentic** — `Chibey-max/Ethereum-Agentic` | Autonomous Ethereum wallet operations with on-chain policy and T3N identity. | Public topic listing showed updated 2026-07-08; details not independently replayed. Source: [topic](https://github.com/topics/terminal3), retrieved 2026-09-01. | Money-moving agent with an on-chain policy boundary. | Higher perceived autonomy and user value if live. | Implementation depth and adversarial proof not established. |
| **Credora** — `ayush00git/Credora` | Autonomous escrow agent for international trade finance. | Topic listing showed updated 2026-06-20; public README-level evidence. | Complete economic job is immediately legible. | Escrow lifecycle is closer to PactAgent's complete-loop lesson. | No independently verified T3N mechanism depth found in this audit. |

## Exact requested names

- “AgentGate” does not resolve to one current T3N bounty project in the topic field. Two relevant public adjacent projects exist: `zihan001/agentgate` (tool-call policy proxy) and `selfradiance/agentgate` (collateralized execution/bonds/slashing). They are evidence of collision, not confirmed bounty submissions. Sources: [policy AgentGate](https://github.com/zihan001/agentgate), [collateral AgentGate](https://github.com/selfradiance/agentgate), retrieved 2026-09-01.
- “T3N Sentinel” was not found as an exact current repository; `t3n-release-sentinel` is the relevant match.
- “Aegis” and “MediPass” map to the repositories above.

## Strongest three threats

1. Aegis can beat current BreakGlass on complete high-stakes workflow, cryptographic delegation, red-team proof, and visible hostile-agent failure handling.
2. Release Sentinel can beat it on immediate enterprise comprehension, policy-driven workflow completion, maintainability, tests, and judge-visible decision output.
3. AgentVault can beat it on the generic sponsor thesis—scoped, time-boxed, revocable sub-agent authority with signed audit—unless BreakGlass adds provider-side effect semantics that AgentVault cannot trivially reproduce.

Proofly/MediPass can also beat current BreakGlass on privacy/product completeness. Current BreakGlass's defensible edge is a concrete destructive external action with a T3N private authority and reconciliation model; the race and weak receipt currently undermine that edge.

## What rivals cannot easily follow

A rival that only has an application-level policy engine may not easily reproduce: T3N-native tenant isolation, agent DID/grant enforcement, secret confinement, host egress, and a real GitHub App token/effect receipt bound into the T3N ledger. Those are potential moat mechanisms, not current BreakGlass proof. A rival can imitate the UI and JSON proof easily; it cannot imitate a platform-enforced receipt unless T3N surfaces are actually used and independently demonstrated.

## C-0R benchmark correction — AgentGate

The formal challenge-submission status remains unconfirmed; that status is not
the benchmark question. At HEAD
`d76f3570fb9bd41247dc1b8b63df74e3d183c4ec`,
[Anshv784/agentgate](https://github.com/Anshv784/agentgate) is a material elite
benchmark. Source inspection proves a T3N contract with endpoint/path/marker
policy, placeholder HTTP, KV credential reads, response projection, an
application audit ledger, and an MCP list/call/audit surface. The README's
testnet/real-email claims are kept as README claims, not independently
reproduced evidence. Against current BreakGlass it wins the maintainability,
generic MCP, policy breadth, and 60-second comprehension comparisons; current
BreakGlass's independently evidenced GitHub destructive vertical remains the
narrower edge. See `research/C-0R-MISSED-THREADS.md` R9 and
`research/C-0R-SOURCE-LEDGER.md`.
