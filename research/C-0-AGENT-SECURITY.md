# C-0 Agent-Security Archaeology

Research/retrieval date: 2026-09-01. Primary research sources: [InjecAgent](https://arxiv.org/abs/2403.02691), [AgentDojo](https://arxiv.org/abs/2406.13352), [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/), [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/), and [MCP tool poisoning disclosure](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks). These sources establish contemporary attack classes; they do not prove a specific BreakGlass exploit without the code/live tests below.

## Relevant failure classes

| Failure | Current prevention | Physical impossibility available in stronger design | Current status |
|---|---|---|---|
| Prompt injection | Model cannot choose arbitrary target/action because MCP accepts only incident ID. | Opaque capability handle, contract-side target/action, one-use reservation, no model authority to mint incidents. | Partial control CODE-PROVEN; repeated-call race LIVE-EVIDENCE-PROVEN. |
| Poisoned tool result | No external result is fed back into authority creation in current flow. | Verify provenance/signature/raw digest before any state transition. | Current path not exposed; future event boundary is PROVEN IMPOSSIBLE / UNAVAILABLE. |
| Malicious event payload | No event ingestion. | HMAC verification, schema binding, installation/repository binding, delivery dedupe, source digest. | Not implemented; current thesis event authenticity DISPROVEN. |
| Credential exfiltration | Agent process does not receive PAT; contract reads it. | Host-side secret reference or JIT provider token; contract cannot return secret and output scrub is defense-in-depth. | Agent-process separation CODE-PROVEN; guest plaintext access CODE-PROVEN. |
| Confused deputy | Fixed action/target and egress reduce arbitrary deputy use. | Capability must name exact target and action; every state mutation has caller-specific authority. | Reconciliation authority bypass DISPROVEN/code + live. |
| Cross-tenant action | Tenant map namespace and T3N isolation. | Evidence capability includes tenant and provider-installation subject; reject mismatches before egress. | Current normal path mitigated; no cross-tenant break demonstrated. |
| Scope widening | Authority shape and URL validation reject application-level widening. | Provider token itself limited to exact repository/permission and action broker rejects alternate audience. | PAT provider scope remains wider; current JIT claim DISPROVEN. |
| Replay | Consumed state blocks serial ACTIVE replay. | Nonce/reservation ledger plus provider idempotency key or effect budget. | Serial pass LIVE-EVIDENCE-PROVEN; concurrent one-use DISPROVEN. |
| Stale authorization/TOCTOU | Cluster-time check and two GET checks. | Provider conditional version/ETag, bounded validity, target hash, explicit changed-state outcome. | Time-source equality unavailable; no conditional delete. |
| Audit forgery | Sanitization avoids returning obvious secrets. | Host-stamped receipt binds request hash, actor, authority version, provider IDs, result and sequence. | Independent receipt DISPROVEN. |
| Operator compromise | Current threat model excludes it. | Split event verifier/policy approver/executor and narrow provider root; signed intent. | Material gap: operator can invent incident and controls PAT map. |

## What the research says for this product

InjecAgent's 1,054 test cases and AgentDojo's tool-output hijacking tasks show that a model's instruction-following is not a reliable authorization boundary. The relevant response is to make bad authority unavailable: the model should hold only an opaque incident capability, while target, scope, credential, nonce, and effect budget are checked by code/host. That is already partly true in BreakGlass, but the live race demonstrates that a capability can be syntactically narrow and still be physically replayable.

MCP tool poisoning matters mainly to a future detector/agent tool layer. If an external description or result can influence incident creation, the input must be treated as untrusted data and bound to a verified source. Current BreakGlass avoids this by having an operator create the incident; it does not solve the problem.

## Hostile-agent demo requirement

A credible next demo should run an agent that receives a prompt telling it to: alter the repository, choose another repository, call the same incident repeatedly, leak the provider credential, accept a poisoned event, and invoke reconciliation under a wrong identity. The expected proof is a hard denial/no request/no secret for each disallowed action, plus a successful exact remediation for the one allowed action. Current baseline can demonstrate only some of these; it fails repeated concurrent execution and wrong-DID reconciliation.
