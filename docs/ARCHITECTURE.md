# BreakGlass Architecture

BreakGlass gives an AI agent incident-bound emergency authority for one otherwise-dangerous operation without giving the agent the underlying administrative credential.

The only Phase 2 capability is `revoke_github_deploy_key`.

```text
Trusted Operator
      |
      v
private T3N Incident Authority
      |
      v
separate organization-owned Agent
      |
      v
execute-incident
      |
      v
Rust/WASM TEE contract
      |
      v
sealed GitHub PAT in private T3N map
      |
      v
api.github.com: GET -> DELETE -> authoritative GET
      |
      v
CONSUMED
```

## Two planes

### Trusted Operator / Incident Control Plane

`npm run incident:create` runs with `.env.bootstrap`. It authenticates the operator, resolves the existing organization-owned replacement agent from the organization roster, checks its private card and exact egress grant, validates the requested GitHub key with a read-only GET, obtains the trusted T3N node time, renders a preview, and waits for `CREATE` or an explicit `--confirm` flag. Only after confirmation does it write the complete authority to the private `incidents` map.

The action and use policy are fixed by the product code:

```text
action   = revoke_github_deploy_key
max_uses = 1
status   = ACTIVE
uses     = 0
```

The target is selected by the operator at authority creation and then frozen in the private record. A duplicate incident ID is rejected before the write, including a second check immediately before persistence.

### BreakGlass Agent / Execution Plane

`npm run agent` starts a small stdio MCP server. It exposes exactly one tool:

```text
breakglass_execute_incident({ incident_id })
```

`npm run agent:execute -- INC-...` is the equivalent command-line adapter. Both use only the replacement-agent credential, refuse processes containing `GITHUB_PAT` or operator `T3N_API_KEY`, and send only `{ "incident_id": "..." }` to T3N.

The agent surface has no operator client, organization-admin client, map-write operation, GitHub client, or incident-creation tool.

## Trust boundaries and knowledge

| Component | Knows | Does not receive |
| --- | --- | --- |
| Operator process | operator T3N key, GitHub PAT, requested target, replacement DID, authority record | agent private key as part of the normal create path |
| Private T3N incident map | incident ID, replacement DID, action, target, timestamps, use state | GitHub PAT |
| Replacement agent process | replacement-agent T3N key, incident ID, returned sanitized result | operator T3N key, GitHub PAT, authority-write capability |
| Rust/WASM contract | private authority, authenticated caller DID, cluster time, sealed PAT, fixed `api.github.com` base | caller-supplied target/action/expiry/max-use fields |
| GitHub | PAT presented only inside the TEE HTTP call, target URL | T3N operator or agent API keys |

The contract loads the target from the private authority. Its request type rejects unknown fields. It enters `EXECUTING` before the external call, never retries an ambiguous DELETE, and consumes only after an authoritative GET proves HTTP 404.

## State machine

```text
ACTIVE --valid caller and time--> EXECUTING
EXECUTING --DELETE 204 + GET 404--> CONSUMED
EXECUTING --ambiguous result--> RECONCILE_REQUIRED
RECONCILE_REQUIRED --GET 404--> CONSUMED
ACTIVE --expired--> EXPIRED
CONSUMED --any retry--> REPLAY_REFUSED
```

The authoritative Phase 1 evidence remains under `evidence/`. Phase 2 demo evidence is written separately to `evidence/phase2-demo.json`.
