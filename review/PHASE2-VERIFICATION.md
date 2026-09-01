# Phase 2 Verification Bundle

Audit scope: compare Phase 2 code, preserved live evidence, and the claimed Phase 2 report. No Phase 3 work was performed. No new destructive GitHub request was issued during this audit.

## Checkpoint and environment

- Audit baseline HEAD: `414f5cf` (`checkpoint: phase 2 verification baseline`)
- Git status at baseline: clean (`## master`)
- Final bundle files are added after that immutable code/evidence checkpoint; the final local HEAD is reported in the handoff response.
- Node: `v22.14.0`
- npm: `11.7.0`
- `rustc`: `1.96.0 (ac68faa20 2026-05-25)`; host `x86_64-pc-windows-gnullvm`
- `cargo`: `1.96.0 (30a34c682 2026-05-25)`
- rustup active toolchain: `stable-x86_64-pc-windows-msvc (default)`
- SDK: `@terminal3/t3n-sdk@5.2.0`

## Raw non-destructive results

- [`npm test`](raw/npm-test.txt): PASS, 6/6.
- [`npm run build`](raw/npm-build.txt): PASS, WASI release build.
- [`npm run doctor`](raw/npm-doctor.txt): overall PASS; `github_target` is WARN because the post-demo `.env.bootstrap` has no current key ID; destructive actions 0; secrets printed false.
- [`cargo test --manifest-path contract/Cargo.toml --lib`](raw/rust-test.txt): PASS, 11/11.
- [`tools/list`](raw/mcp-tool-list.txt): exactly `breakglass_execute_incident`.
- [`tools/call` with owner/action extras](raw/mcp-extra-fields.txt): rejected with `agent input accepts only incident_id`.
- [`tools/call` requesting operator creation](raw/mcp-operator-tool.txt): rejected as `unknown agent tool`.
- Read-only consumed-authority lookup after the demo: [`incident-after-read.txt`](raw/incident-after-read.txt).

## File hashes

SHA-256 values were calculated from the working tree at the audit checkpoint. Lengths are included to make accidental substitutions easier to spot.

| Path | SHA-256 | Bytes |
| --- | --- | ---: |
| `package.json` | `e53b4f30932d7d5189b795396af4e440e6892443b22aaa69ee193799a64090e3` | 3540 |
| `scripts/incident-create.ts` | `2f020d21333260c6fea06ce55192c9dd47fb0ea5916d39352e497f2401cc2e04` | 11254 |
| `scripts/agent-mcp.ts` | `84d9ca1c0c7b0d6b6f6af082bfb11dc0017e64f20a907f3afecce3366520e780` | 2676 |
| `scripts/agent-execution.ts` | `27e8dfc03bbac64fe17048bf80c4d44c391246846fe98ae2eb508fba5142aaf2` | 1355 |
| `scripts/demo.ts` | `0cf1e6b1a388729bd503f9f2e458c33ff7dfe20603511512284a044aa0531585` | 4370 |
| `scripts/doctor.ts` | `23faaaf0a30b636688bc7d77d61a644f1c963ddbb080c7224a48f3714472d688` | 5341 |
| `contract/src/lib.rs` | `3bda3746ecde12ddba48bfd99e00b775c776f40c67281d1621a76853ee67f0ff` | 18740 |
| `contract/src/authority.rs` | `e84aec007d45e40c90632686faa9358c4ece2b621cdcc12abebb94cedbdd6fd8` | 11261 |
| `contract/wit/world.wit` | `474e5b8ded40f2aa2e95f6e072b866015e833df0e2bd30e856568a84148bdb3a` | 1084 |
| `docs/ARCHITECTURE.md` | `68692f9a48035fc8ba5595c4046db7bda077c7e7bf1b412f30a7ddadb823e94a` | 3527 |
| `docs/THREAT_MODEL.md` | `5daa4c26f38337e0460fdad40454d7b2f596a2475ef17ff1f6d8c1d67fcdc3a8` | 3944 |
| `docs/HANDOVER.md` | `c844b4c3cc194f3f52ce55e10044840e0c4fa65422cbca5324dad7d26233f172` | 5225 |
| `docs/BUGS.md` | `382c721287736100b9f28527def0714eb2cb4d6efef207a8b3448f8f7821b3a5` | 2797 |
| `evidence/phase2-demo.json` | `cc360641e18ddb317f8b93048ed732427c05fb0c45ba19b338bee6b95bbb8f97` | 4225 |
| `evidence/phase2-security-audit.json` | `7e9f3a6dad08cab6e828e52feaee243bb7d24091b38fb30b05acd42c401ed589` | 1279 |
| `tests/product-boundaries.test.ts` | `e9c728bb5e2efc6abb8934398d5eeb1cfe690c452e066f513580b335c0de00f9` | 3946 |

## Claim → evidence matrix

| Claim | Implementation symbol | Evidence | Classification | Result |
| --- | --- | --- | --- | --- |
| Operator incident creation exists | `scripts/incident-create.ts`: `prepareIncidentAuthority`, `persistPreparedIncident`, `main` | `evidence/phase2-incident-inc-phase2-demo-1788244572850.json`, `evidence/phase2-demo.json` | LIVE + STATIC | VERIFIED |
| Exact preview and explicit confirmation exist | `buildIncidentPreview`, `renderIncidentPreview`, `main` | `evidence/phase2-demo.json` authority preview; incident `operator_confirmation: true`; product test | LIVE + UNIT | VERIFIED |
| TTL is derived from trusted T3N time | `scripts/product.ts`: `trustedNodeTimeSeconds`; `prepareIncidentAuthority` | code; trusted-manifest doctor output; authority timestamps | STATIC + LIVE | PARTIAL — the original evidence does not preserve the raw HTTP Date header or a signed clock proof |
| Action is fixed to `revoke_github_deploy_key` | `buildIncidentPreview`, `persistPreparedIncident` | phase2 incident authority; product test | LIVE + UNIT | VERIFIED |
| `max_uses` is fixed to 1 | `buildIncidentPreview`, `persistPreparedIncident` | phase2 incident authority; product test | LIVE + UNIT | VERIFIED |
| Agent accepts only `incident_id` | `parseAgentInput`; `breakglassAgentToolDefinition` | MCP list, MCP extra-field rejection, product test | LIVE + UNIT + STATIC | VERIFIED |
| MCP exposes only the execution tool | `scripts/agent-mcp.ts`: `tools/list`; `scripts/agent-tool.ts` | MCP tool-list and operator-tool rejection | LIVE + STATIC | VERIFIED |
| Operator creation is unavailable from MCP | `agent-mcp.ts`: only `BREAKGLASS_AGENT_TOOL` accepted | `raw/mcp-operator-tool.txt` | LIVE + STATIC | VERIFIED |
| Target is loaded from the private authority | `contract/src/lib.rs`: `execute`; `contract/src/authority.rs`: request parsing; Rust target-is-record test | Rust test; phase2 authority and execution evidence | UNIT + STATIC + LIVE | VERIFIED for the implemented boundary |
| PAT is unavailable to the agent | `agent-execution.ts`, `agent-mcp.ts` environment guards; `demo.ts` child scrub | phase2 security audit; incident evidence; sanitized live agent execution | STATIC + LIVE | VERIFIED for normal agent execution; host/TEE compromise remains out of scope |
| Egress is restricted to `api.github.com` | `doctor.ts`; existing organization egress enforcement | doctor output; Phase 1 ownership evidence | LIVE | VERIFIED |
| Valid live DELETE returned HTTP 204 | Rust contract execution result | `phase2-demo.json` executed result | LIVE | VERIFIED as contract-reported; no independent raw HTTP request trace is preserved |
| Authoritative GET returned HTTP 404 | contract verification plus `verifyGithubAbsent` | `phase2-demo.json` executed verification and independent GitHub section | LIVE | VERIFIED; both contract-reported and independently queried evidence exist |
| Authority became `CONSUMED` | contract state machine | phase2 demo; read-only authority lookup | LIVE + STATIC | VERIFIED |
| Replay caused zero destructive calls | Rust consumed-state gate | phase2 demo replay; Rust replay test | LIVE + UNIT | VERIFIED |
| Product tests are 6/6 | `tests/product-boundaries.test.ts` | `raw/npm-test.txt` | UNIT | VERIFIED |
| Rust tests are 11/11 | `contract/src/authority.rs` tests and `lib.rs` test | `raw/rust-test.txt` | UNIT | VERIFIED |
| Doctor passes | `scripts/doctor.ts` | `raw/npm-doctor.txt` | LIVE | VERIFIED overall PASS; target readiness is explicitly WARN |
| Secret scan found zero credential-value hits | `.gitignore`, agent guards, audit procedure | `evidence/phase2-security-audit.json`; audit rerun | STATIC | VERIFIED: 0 exact env-secret hits and 0 likely token/private-key markers in non-ignored files |
| Demo target existed before execution | `scripts/github.ts`: `ensurePhase2DisposableTarget` | `evidence/phase2-demo-target.json` | LIVE + STATIC | PARTIAL — sanitized evidence records exact ID/count/read-only state but not the original HTTP status |

## Live-demo evidence integrity

Source: [`evidence/phase2-demo.json`](../evidence/phase2-demo.json), [`evidence/phase2-demo-target.json`](../evidence/phase2-demo-target.json), and the original authority artifact.

| Required fact | Present in original Phase 2 evidence? | Provenance |
| --- | --- | --- |
| Before target exists | Yes as sanitized target-ready record: ID `161914229`, count 1, read-only | Bootstrap/GitHub helper result; original raw HTTP status is not retained |
| Agent DID | Yes in authority preview/persisted authority | Operator/T3N authority record |
| Incident ID | Yes | Authority and execution result |
| DELETE attempted exactly once | Yes as `destructive_call_count: 1` | Contract-reported result; no raw HTTP trace |
| DELETE HTTP 204 | Yes | Contract-reported result |
| Authoritative GET HTTP 404 | Yes | Contract-reported verification and independent GitHub GET |
| Incident status `CONSUMED` | Yes | Contract result plus read-only authority lookup |
| Uses `1/1` | Not in original `phase2-demo.json` | Separately captured read-only authority lookup proves `uses: 1`, `max_uses: 1`; original evidence was not rewritten |
| Replay `REPLAY_REFUSED` | Yes | Contract-reported result |
| Replay destructive calls 0 | Yes | Contract-reported result |

Provenance boundaries:

- Contract-reported: execution target, status transitions, DELETE count/status, verification status, replay result.
- Independently queried: post-demo GitHub exact-key GET 404 and list absence; read-only T3N authority lookup proving `uses: 1/1`.
- Inferred: the complete `ACTIVE → EXECUTING` transition sequence from the persisted ACTIVE preview and execution `previous_status: EXECUTING`; before-target existence lacks its original HTTP status in the artifact.

## Security audit

The pre-commit and post-bundle repository scans covered non-ignored files while excluding `.env.*`, `evidence/raw/`, `contract/target/`, `tools/rust-sysroot/`, and `node_modules/` according to `.gitignore`:

- exact values from local GitHub/T3N/agent environment files outside ignored paths: 0 hits;
- likely GitHub token or private-key markers outside ignored paths: 0;
- private-key markers outside ignored `evidence/raw/`: 0;
- non-empty values in `.env.example`: 0;
- ignored coverage: `.env.*`, `evidence/raw/`, `target/`, and `tools/rust-sysroot/` all covered;
- no PAT/operator key is loaded by the agent execution path; contaminated environments are refused;
- the only MCP tool is execution, and agent arguments cannot supply target/action fields.

The committed security summary is [`evidence/phase2-security-audit.json`](../evidence/phase2-security-audit.json). It contains no secret values.

## Bug classification

| `docs/BUGS.md` item | Classification | Audit note |
| --- | --- | --- |
| SDK 5.3.0 requires missing `rtmr1_allowlist` while 5.2.0 accepts the same live manifest | LOCAL COMPATIBILITY FINDING | Reproduced in this environment and preserved with evidence; not independently confirmed as an upstream platform bug |
| `createAgent` / `defaultCard` no-card ownership result | DOCUMENTATION / API AMBIGUITY | The recorded call explicitly used `defaultCard: false`; source inspection supports API misuse/ambiguity as the primary cause |
| New organization-owned agents begin with zero usable credits | OBSERVED LIMITATION | Live credit preflight required external funding; not claimed as a guaranteed platform defect |
| Missing T3N log span IDs | OBSERVED LIMITATION | Observed in collected logs; no reproducible platform defect claim is made |

No item is classified as a proven platform bug solely from the current artifacts.

## Unresolved uncertainties

1. The original Phase 2 demo artifact does not contain the raw trusted-time response header, the raw GitHub-before HTTP response, or post-consumption `uses: 1/1`; these gaps are explicitly marked above and were not hidden by rewriting evidence.
2. DELETE 204 and the state transitions are sanitized contract output, not a raw T3N trace with span IDs.
3. The current doctor target warning is expected after the disposable target was consumed and the local bootstrap file lacks a current key ID.

Phase 3 is not approved by this bundle.
