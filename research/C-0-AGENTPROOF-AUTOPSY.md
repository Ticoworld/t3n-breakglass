# C-0 AgentProof Autopsy

Audit date: 2026-09-01. Repository: `Ticoworld/agentproof-t3n`, latest public commit inspected `e710ddf` (2026-08-08). Primary artifacts: [README at e710ddf](https://raw.githubusercontent.com/Ticoworld/agentproof-t3n/e710ddf/README.md), [`docs/BUGS.md`](https://raw.githubusercontent.com/Ticoworld/agentproof-t3n/e710ddf/docs/BUGS.md), [`docs/WALKTHROUGH.md`](https://raw.githubusercontent.com/Ticoworld/agentproof-t3n/e710ddf/docs/WALKTHROUGH.md). Retrieval date: 2026-09-01.

## What AgentProof actually demonstrated

| Surface | Evidence-backed finding |
|---|---|
| Onboarding | Signup/Quickstart authentication and testnet identity flow were exercised. SOURCE-PROVEN by its walkthrough. |
| TEE build | A component was built and registered, including contract ID 557. SOURCE-PROVEN repo artifact. |
| Reference product | A flight contract was partially exercised, but the successful external fulfillment path required a Duffel credential/egress configuration that was not completed. SOURCE-PROVEN repo docs; complete flight loop DISPROVEN. |
| Approval policy | Contract ID 558 had positive and negative policy cases. This proves a confidential decision/check primitive, not a full authorization lifecycle. SOURCE-PROVEN repo docs. |
| Engineering quality | Seven Rust tests and a documented set of SDK/trust-manifest defects were present. CODE-PROVEN/repo artifact. |
| External outcome | No real money movement or successfully completed external flight booking was demonstrated. SOURCE-PROVEN by walkthrough; do not infer more. |
| Adversarial depth | No agent prompt-injection/tool-poisoning harness, replay/effect race proof, independent receipt, or end-to-end incident lifecycle was shown. NON-MATERIAL to AgentProof's narrower onboarding objective, but material to BreakGlass. |

## What it was not

AgentProof was not evidence that T3N automatically supplies a complete enterprise agent product. It tested onboarding and a policy primitive. The missing credential/egress completion is exactly the kind of boundary that a winning submission must close. A functioning contract registration is not a complete system.

## Lessons for BreakGlass

1. Reference-agent demos make platform mechanics legible but do not establish external business value.
2. A positive/negative authorization policy test is weaker than a hostile-agent test that attempts the full action through every boundary.
3. Integration credentials and egress are part of the product loop, not setup trivia.
4. Defects such as trust-manifest incompatibility, `TenantClient.me()` mismatch, and balance parsing failures are evidence that SDK version claims must be pinned to live artifacts.
5. T3N-native novelty must be demonstrated at the seam between confidential authority and external effect; otherwise a judge can view the submission as another platform tutorial.

## Classification

AgentProof is a platform-mechanics proof and a warning against stopping at a working primitive. It is not a strong competing complete product and does not rescue the current BreakGlass thesis.
