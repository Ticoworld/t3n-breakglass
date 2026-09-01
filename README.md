# BreakGlass

BreakGlass gives an AI agent incident-bound emergency authority for one otherwise-dangerous operation without giving the agent the underlying administrative credential.

Phase 2 keeps exactly one capability: `revoke_github_deploy_key`.

```text
Operator -> private T3N Incident Authority -> organization-owned Agent
         -> execute-incident -> Rust/WASM TEE -> sealed GitHub PAT
         -> api.github.com GET/DELETE/GET -> CONSUMED
```

## Product commands

```powershell
npm install
npm run test
npm run build
npm run doctor

# Trusted operator/control plane; preview is shown before the write.
npm run incident:create -- INC-1043 Ticoworld t3n-breakglass-sandbox 123456 300

# Agent/execution plane: stdio MCP server exposing only breakglass_execute_incident.
npm run agent

# Equivalent one-shot agent adapter.
npm run agent:execute -- INC-1043

# Live, disposable, non-faked demo.
npm run demo
```

The operator/bootstrap commands read `.env.bootstrap`, which must contain only local operator/GitHub values. The agent commands read `.env.replacement-agent`, which must contain only the separately funded replacement-agent credential and identity. Never run the agent with `.env.bootstrap`.

Copy `.env.example` for placeholders. Real credentials are never committed or pasted into evidence.

## Control-plane / execution-plane separation

`npm run incident:create -- INCIDENT_ID OWNER REPOSITORY DEPLOY_KEY_ID TTL_SECONDS` resolves the real replacement agent from the existing organization roster, validates its private card and exact `api.github.com` egress, checks the requested GitHub key, computes expiry from trusted T3N node time, prints the frozen authority preview, and requires the operator to type `CREATE`. Direct `node`/`tsx` invocation also accepts named options and an explicit `--confirm` flag. It then writes the authority to the private T3N incident map.

`npm run agent` exposes only:

```json
{
  "name": "breakglass_execute_incident",
  "arguments": { "incident_id": "INC-1043" }
}
```

The agent cannot create authorities, supply target fields, change action/expiry/use policy, or read the GitHub PAT.

## State and safety

The contract performs `ACTIVE -> EXECUTING` before the external call. It consumes only after DELETE and an authoritative GET 404. Ambiguous outcomes become `RECONCILE_REQUIRED`; subsequent calls are GET-only. A consumed authority returns `REPLAY_REFUSED` without another DELETE.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Handover and reproducibility](docs/HANDOVER.md)
- [Bug package](docs/BUGS.md)

## Evidence and SDK policy

Phase 0 and Phase 1 evidence remains under `evidence/`. Phase 2 artifacts are separate. The exact dependency `@terminal3/t3n-sdk@5.2.0` is retained because the live testnet trust manifest is rejected by 5.3.0 due to its missing `rtmr1_allowlist` field. Do not upgrade until that regression is resolved and the trust-boundary evidence is repeated.
