# C-0 BreakGlass Depth Ladder

The levels below are semantic depth: each level removes a class of authority, failure, or proof ambiguity. More screens, providers, SDK wrappers, and prose do not advance a level by themselves.

| Level | Meaning | Why it is real depth | Current position |
|---|---|---|---|
| L0 | Fixed provider action in TEE | Establishes a bounded target/action and credential boundary. | Current BreakGlass reaches this. |
| L1 | Complete incident job | Detection/creation, triage/policy, execution, verification, expiry, escalation, and closure form one user loop. | Missing detection/escalation/closure. |
| L2 | Caller-complete authority partition | Destructive, read, lifecycle, and evidence mutations each require the intended principal. | Normal ACTIVE is partial; reconciliation fails. |
| L3 | Effect-safe reservation | A replaying/racing agent cannot produce more than the allowed provider effect before the external call. | Disproved by live race; current KV offers no CAS surface. |
| L4 | Provider-side JIT authority | Provider credential is minted for exact installation/repository/permission and expires/revokes after the job. | Current long-lived PAT; missing. |
| L5 | Verified causal trigger | Authority can be created only from authenticated, deduped external evidence plus policy/intent, not an operator-invented label. | Missing; current incidents are direct map writes. |
| L6 | Attenuated intent capability | Agent gets an opaque capability binding actor, cause, target, action, audience, validity, and budget; model cannot widen it. | Current ID is target-bound application data, not an independently signed/effect-budgeted capability. |
| L7 | Ambiguity-aware recovery | System distinguishes pre-effect failure, sent/unknown, provider-acknowledged, and verified outcome, with authorized reconciliation and no unsafe retry. | Partial protocol; wrong DID and precheck liveness defects. |
| L8 | Independent causal receipt | Host/provider evidence binds event digest -> policy/intent -> caller -> authority version -> outbound request -> provider result -> final state. | Current guest JSON/weak reference only. |
| L9 | Autonomous operations loop | Monitor/detect -> decide/escalate -> execute -> verify -> expire/reconcile -> learn, with humans setting policy and handling exceptions. | Missing. |
| L10 | Adversarially demonstrated product | Hostile agent, spoofed events, concurrency, credential misuse, cross-tenant, and provider ambiguity are live tests with judge-readable proof. | Current baseline has only partial adversarial evidence. |

The highest ceiling is not “L0 plus a UI.” It is an L5–L10 composition in one narrow vertical, with L3/L7/L8 as the hard moat. L4/L5/L8 are dependent on capabilities T3N does not currently expose in the BreakGlass world, so architecture must state the external gateway/broker boundary honestly.
