# BreakGlass Evidence Index

This index points a reviewer from each major claim to the smallest useful artifact. The canonical live run is the Phase 2E bundle; earlier Phase 0, Phase 1, and Phase 2 evidence remains preserved separately.

Canonical proof: [`evidence/phase2e/phase2e-live-proof.json`](../evidence/phase2e/phase2e-live-proof.json)

The canonical Phase 2E artifact records the product boundary suite as 6/6 at that checkpoint. The current post-hardening suite is 7/7; the original raw artifact is intentionally unchanged.

Canonical run:

```text
Incident: INC-PHASE2E-LIVE-1788249253449
Agent:    did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019
Target:   Ticoworld/t3n-breakglass-sandbox#161921323
```

| Claim | Evidence | Classification |
| --- | --- | --- |
| Target existed before execution | [`target-before.json`](../evidence/phase2e/target-before.json) | Independently verified: exact key GET 200, list GET 200, present, read-only, count 1 |
| Trusted time was used | [`trusted-time.json`](../evidence/phase2e/trusted-time.json) | Directly observed: raw T3N Date header, parsed timestamp, TTL, and calculated expiry |
| Authority was ACTIVE with 0/1 uses | [`incident-before.json`](../evidence/phase2e/incident-before.json) | Directly observed from private incident-map read |
| Agent request contained only incident_id | [`agent-request.json`](../evidence/phase2e/agent-request.json), [`t3n-execution.json`](../evidence/phase2e/t3n-execution.json) | Directly observed |
| Target came from the private authority | [`incident-before.json`](../evidence/phase2e/incident-before.json), [`t3n-execution.json`](../evidence/phase2e/t3n-execution.json) | Directly observed request exclusion plus contract-reported authority target |
| DELETE occurred once | [`t3n-execution.json`](../evidence/phase2e/t3n-execution.json) | T3N contract-reported: attempted true, count 1; no independent raw request observer |
| DELETE returned HTTP 204 | [`t3n-execution.json`](../evidence/phase2e/t3n-execution.json) | T3N-contract-reported external HTTP result |
| Contract verification GET returned 404 | [`t3n-execution.json`](../evidence/phase2e/t3n-execution.json) | T3N contract-reported authoritative verification |
| GitHub independently reports the target absent | [`github-independent-after.json`](../evidence/phase2e/github-independent-after.json) | Independently verified: exact GET 404, list GET 200, count 0 |
| Authority became CONSUMED | [`incident-after.json`](../evidence/phase2e/incident-after.json) | Directly observed from private incident-map read |
| Uses became 1/1 | [`incident-after.json`](../evidence/phase2e/incident-after.json) | Directly observed |
| Replay was refused | [`replay.json`](../evidence/phase2e/replay.json) | T3N contract-reported: REPLAY_REFUSED, before/after CONSUMED |
| Replay sent zero destructive calls | [`replay.json`](../evidence/phase2e/replay.json) | T3N contract-reported: count 0, DELETE attempted false |
| Target remains absent after replay | [`github-after-replay.json`](../evidence/phase2e/github-after-replay.json) | Independently verified |
| Agent surface exposes only execution | [`raw/mcp-tool-list.txt`](../evidence/phase2e/raw/mcp-tool-list.txt) | Directly observed MCP tool list |
| Extra target/action fields are rejected | [`raw/mcp-extra-fields.txt`](../evidence/phase2e/raw/mcp-extra-fields.txt) | Directly observed boundary check |
| Operator creation is unavailable through MCP | [`raw/mcp-operator-tool.txt`](../evidence/phase2e/raw/mcp-operator-tool.txt) | Directly observed unknown-tool response |
| Product boundary tests pass | [`raw/npm-test.txt`](../evidence/phase2e/raw/npm-test.txt) | Canonical Phase 2E artifact: unit 6/6; current post-hardening suite: unit 7/7 |
| Rust authority tests pass | [`raw/rust-test.txt`](../evidence/phase2e/raw/rust-test.txt) | Unit: 11/11 |
| Doctor passes | [`raw/npm-doctor.txt`](../evidence/phase2e/raw/npm-doctor.txt) | Safe live check: overall PASS; optional GitHub target subcheck warns when target env is not configured |
| Build passes | [`raw/npm-build.txt`](../evidence/phase2e/raw/npm-build.txt) | Native/build check: PASS |
| No credential values were exposed | [`raw/secret-audit.json`](../evidence/phase2e/raw/secret-audit.json) | Static audit: zero credential-value hits and zero private-key markers |

## Evidence boundary

The contract-reported DELETE `204` is not described as an independent raw GitHub trace. The strongest supported chain is:

```text
independent GitHub GET 200
  -> T3N contract reports DELETE 204
  -> T3N contract reports authoritative GET 404
  -> independent GitHub GET 404
  -> private authority read reports CONSUMED, 1/1
  -> replay reports REPLAY_REFUSED, zero destructive calls
```

The runtime does not expose a separate external event for every state transition. The evidence therefore does not claim that `ACTIVE → EXECUTING` was independently observed as two separate events.
