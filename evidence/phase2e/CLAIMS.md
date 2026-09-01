# Phase 2E Claim Classification

Run: `INC-PHASE2E-LIVE-1788249253449`

The classifications below distinguish what was directly observed, what the T3N contract reported, what GitHub independently returned, and what remains an inference. The original Phase 2 evidence was not modified.

| Claim | Classification | Evidence and boundary |
| --- | --- | --- |
| Target existed before execution | INDEPENDENTLY VERIFIED | `target-before.json`: exact GitHub key GET 200, list GET 200, target present, list count 1, read-only true; one POST 201 was captured for this run |
| Trusted T3N time source | DIRECTLY OBSERVED | `trusted-time.json`: T3N trust-manifest HTTP 200, raw Date header, parsed seconds equal `created_at`, expiry equals parsed seconds plus TTL |
| Authority was ACTIVE before execution | DIRECTLY OBSERVED | `incident-before.json`: private incidents-map read shows ACTIVE, uses 0, max_uses 1 and exact target/agent |
| Agent request contained only `incident_id` | DIRECTLY OBSERVED | `agent-request.json` and `t3n-execution.json`: request fields contain only incident_id; target fields false |
| DELETE occurred once | CONTRACT-REPORTED | `t3n-execution.json` result reports `destructive_call.attempted=true` and `count=1`; no independent request observer exists |
| DELETE returned 204 | CONTRACT-REPORTED | `t3n-execution.json` result reports method DELETE and HTTP 204; classification is `T3N-CONTRACT-REPORTED EXTERNAL HTTP RESULT` |
| Contract verification GET returned 404 | CONTRACT-REPORTED | `t3n-execution.json` result reports authoritative verification HTTP 404 and absent true |
| GitHub independently reported 404 after execution | INDEPENDENTLY VERIFIED | `github-independent-after.json`: exact key GET 404, list GET 200, target absent, list count 0 |
| Authority became CONSUMED | DIRECTLY OBSERVED | `incident-after.json` private map read shows CONSUMED; contract result also reports CONSUMED |
| Uses became 1/1 | DIRECTLY OBSERVED | `incident-after.json` shows uses 1 and max_uses 1; exact target, action, and agent DID unchanged |
| Replay was refused | CONTRACT-REPORTED | `replay.json` result reports REPLAY_REFUSED with before/after CONSUMED |
| Replay sent zero DELETEs | CONTRACT-REPORTED | `replay.json` result reports attempted false, method NONE, count 0; no independent HTTP observer exists |
| GitHub remained absent after replay | INDEPENDENTLY VERIFIED | `github-after-replay.json`: exact key GET 404, list GET 200, target absent, list count 0 |
| Complete ACTIVE → EXECUTING transition was externally observed as two events | NOT PROVEN | The evidence shows ACTIVE before and `state.before=EXECUTING` in the execution result; no separate externally observable transition event was invented |
| An independent raw observer captured the DELETE request/response | NOT PROVEN | The 204 is intentionally classified as T3N-contract-reported, not independent GitHub trace |

## Proven chain

Independent GitHub-before GET 200 → T3N contract reports DELETE 204 → T3N contract reports authoritative GET 404 → independent GitHub-after GET 404 → private authority read shows CONSUMED and uses 1/1 → replay reports REPLAY_REFUSED with zero DELETEs → independent GitHub-after-replay GET 404.
