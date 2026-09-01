# C-0 BreakGlass Archaeology

Audit date: 2026-09-01. Code baseline: public HEAD `4a077035474337b7a1ad16204820e68ed3020477`.

## Research verdict in one sentence

BreakGlass owns a bounded, target-frozen GitHub action running inside T3N, but its “one-use evidence-bound privilege” thesis does not survive code and live attack: authority creation is operator-invented, the provider credential is standing, reconciliation is under-authorized, and concurrent calls can duplicate the destructive request.

## Exact authority flow

`operator preflight -> private map write ACTIVE -> agent sends incident_id -> contract reads record -> (EXECUTING/RECONCILE_REQUIRED branch) OR (caller DID + cluster-time checks) -> persist EXECUTING -> GitHub GET -> GitHub DELETE -> GitHub GET -> CONSUMED / FAILED / RECONCILE_REQUIRED`.

The status branch is before caller authentication. The precheck is after EXECUTING is committed. This ordering explains both live failures.

## What is genuinely strong

- The agent-facing argument surface is tiny and deny-unknown-fields.
- The target and action are not selected by model-generated tool arguments.
- The ordinary agent process does not hold the GitHub PAT.
- The provider host is fixed and T3N egress is configured explicitly.
- The code distinguishes clear success, clear failure, and ambiguous provider outcomes, and refuses blind destructive retry.
- The deployed phase-2 proof used a private sandbox key, exact GET/list verification, and serial replay refusal.

These are meaningful controls. They are bounded primitive depth, not a complete emergency-operations product.

## What the code actually owns

Application code owns the incident schema, target/path validation, caller DID comparison, TTL gate, state transitions, precheck, DELETE/GET protocol, and output proof. T3N owns the execution boundary, identity context, tenant map access, egress enforcement, and underlying ledger/runtime. GitHub owns provider authentication and target state. No layer currently owns an atomic transaction spanning T3N state and GitHub side effects.

## Assumptions versus invariants

The public architecture treats a trusted operator, long-lived PAT, and clean network ambiguity as environmental facts. They are assumptions. The actual invariants are only the normal ACTIVE-branch checks, fixed target/action/host, private tenant storage, and serial state-based replay check. See `C-0-CURRENT-BASELINE.md` for the complete list.

## Liveness archaeology

The system favors “do not retry an uncertain DELETE” over emergency completion. That is defensible for safety, but the implementation also puts an authority into EXECUTING before it knows whether the provider was reachable. A GitHub GET timeout, 500, malformed response, or T3N outbound failure can strand an authority with no attempted destructive action. The documented recovery is manual reconciliation, and the reconciliation path is itself not caller-authorized.

## Product archaeology

The public materials present a working loop, but the actual loop begins after an operator has already selected and inspected the target. It has no detector, verified event source, incident dedupe, policy escalation, human approval state, credential mint, provider-side revoke, autonomous monitoring, or independent receipt. A UI around this same flow would not close those gaps.

## T3N fit

T3N is load-bearing for confidential tenant state, agent identity, TEE execution, egress limits, and the host ledger/activity plane. It already markets identity, secrets isolation, outbound wrapping, and audit as platform capabilities. Therefore the winning novelty cannot be “an agent with a secret in T3N.” It must be a new cross-boundary mechanism: causal evidence, temporary provider authority, effect-safe execution, and durable independent proof.

## Current thesis attack

“Evidence-bound JIT privilege for AI agents” is not implemented by current BreakGlass. It is also not fully attainable inside the current contract alone: there is no verified event ingress, no current CAS, no current host audit import, and no provider-token minting primitive in the component world. A stronger architecture can combine an authenticated external gateway, T3N private state/TEE, and GitHub App installation tokens, but the standing App private key/broker boundary and provider non-transactionality remain explicit.

## Archaeological conclusion

The baseline should be preserved as a locked fallback and used as an adversarial test oracle. It should not be extended by adding providers, wrappers, or UI before the next design proves a stronger authority/receipt mechanism and closes a complete enterprise job.
