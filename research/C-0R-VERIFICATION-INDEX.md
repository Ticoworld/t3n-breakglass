# C-0R verification index

This is the shortest path from each missed-thread conclusion to its evidence.
The JSON files contain sanitized inputs/results only; no credential-bearing
raw environment or HTTP dump is included.

| Conclusion | Smallest supporting chain |
|---|---|
| Durable outbox exists as a typed platform design but is unavailable to the current public tenant-z path | `C-0R-MISSED-THREADS.md` R1 -> `C-0R-outbox-probe/wit/world.wit` -> copied `host-outbox` WIT -> `c0r-outbox-live.ts` -> `C-0R-outbox-result.json` (registration success, enqueue invocation `-32603`, empty logs) -> `c0r-outbox-link-live.ts` -> `C-0R-outbox-link-result.json` (registration success, no-op invocation `-32603`) -> call-centre `contract/wit/world.wit` at commit `bf08f0ba0fb1ce585696e78b7162a0785afab97f` |
| Outbox connector/ack/Merkle proof cannot be used by current challenge tenant | R1 and `C-0R-PLATFORM-PROOF-PACKS.md` claims 1/6/7 -> `host-outbox` WIT `enqueue/status`, `committed-ack`, `at-seq` -> SDK 5.2.0 negative search -> live invocation failure |
| One T3N OCC reservation winner is proven | `C-0R-occ-probe/src/lib.rs` -> `c0r-occ-live.ts` barrier/child launch -> `C-0R-occ-result.json` exact ready/start timestamps, both initial log reads null, one final `contender-b`, one retry LOST, activity seq 173796/173797 |
| External reservation DB is not required for winner selection | R2 above -> compare `final_reservation` and repeated readback -> distinction in R2: OCC reservation is not provider effect fencing |
| T3N activity receipt is stronger than guest JSON but not a causal/Merkle receipt | `c0r-audit-live.ts` -> `C-0R-audit-result.json` invocation + activity fields -> `node_modules/@terminal3/t3n-sdk/dist/index.d.ts` `ActivityEntry/getActivityLog` -> empty `audit_events` and no public proof method |
| Webhook HMAC/delivery dedupe algorithm accepts exactly one record | `c0r-webhook-gateway.ts` -> `C-0R-webhook-result.json` five cases -> accepted count 1; GitHub docs links in source ledger establish provider header semantics |
| Real GitHub ingress is a manual setup prerequisite, not silently claimed live | R6 in main report -> GitHub webhook docs -> `C-0R-webhook-result.json` explicitly says local fixture and no real ingress -> setup requirement in report |
| Provider outcome ambiguity is real and no blind retry is safe | `c0r-ambiguity-live.ts` -> `C-0R-ambiguity-result.json` dropped-after-effect and dropped-before-effect cases -> `contract/src/lib.rs` error/success branches show current no-blind-retry |
| Official call-centre reference has same outbound read-before-effect race class | call-centre `pay.rs:107-133`, `ledger.rs:127-139`, `relay_client.rs:47-84` at `bf08f0ba0fb1ce585696e78b7162a0785afab97f` -> `C-0R-reference-race-result.json` local synchronized model -> live OCC artifact proves the host overlap premise; no provider duplicate effect claimed |
| GitHub App JIT path is not closed because account setup is absent | GitHub official App/JWT/token/revoke docs -> `C-0R-app-jit-result.json` exact owner/setup prerequisite -> report R5; standing private key caveat |
| AgentGate is an elite benchmark even without formal challenge-status confirmation | `C-0R-MISSED-THREADS.md` R9 -> AgentGate URL/HEAD `d76f3570fb9bd41247dc1b8b63df74e3d183c4ec` -> README claims separated from source-proven contract/MCP/KV audit -> comparison table |
| No material uncertainty remains parked as UNKNOWN except the allowed external setup block | appended `C-0-MATERIAL-UNCERTAINTIES.md` C-0R register -> `C-0R-MISSED-THREADS.md` R10 -> count command in final audit |
