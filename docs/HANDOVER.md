# BreakGlass Handover

## Prerequisites

- Node.js 22 or a compatible current Node release.
- Rust with the `wasm32-wasip2` target.
- `ssh-keygen` for a fresh disposable demo keypair.
- A Terminal 3 testnet operator key with enough credit for contract operations.
- The separately funded, organization-owned replacement agent key.
- A private GitHub repository and a fine-grained PAT restricted to that repository with Administration read/write permission.

Never commit `.env`, `.env.bootstrap`, `.env.agent`, `.env.replacement-agent`, or `evidence/raw/`.

## SDK pin

The repository intentionally pins exactly `@terminal3/t3n-sdk@5.2.0`. The live testnet trust manifest is accepted by 5.2.0 but rejected by 5.3.0 because 5.3.0 requires the missing `rtmr1_allowlist`. Do not upgrade until that compatibility issue is resolved and the trust-boundary evidence is rerun.

## Environment

Copy `.env.example` to `.env.bootstrap` and fill only the operator/GitHub values. The replacement agent file is separate:

```text
REPLACEMENT_AGENT_T3N_API_KEY=...
REPLACEMENT_AGENT_DID=did:t3n:...
REPLACEMENT_AGENT_ORGANISATION_DID=did:t3n:...
```

The replacement key must be funded. A new organization-owned agent observed in this project initially had zero usable credit until Terminal 3 funded it.

## Build and registration

The accepted Phase 1 contract and maps already exist. For a fresh environment, use the existing operator bootstrap path:

```powershell
npm install
npm run build
npm run setup-github
npm run bootstrap
npm run authorize-agent
npm run configure-agent-egress
```

Do not run provisioning or bootstrap against an existing checkpoint unless you have explicitly audited the target and evidence. The Phase 1 replacement scripts refuse to create a second replacement agent when their checkpoint files already exist.

## Safe health check

```powershell
npm run doctor
```

Doctor performs no destructive action. It verifies the pinned SDK, trusted manifest flow, operator authentication, contract/version, maps, replacement DID, organization ownership, private card, egress, and optionally the configured GitHub target.

## Create an Incident Authority

The operator supplies all target fields and TTL without editing JSON. The command validates the key, prints the exact preview, and requires explicit confirmation:

```powershell
npm run incident:create -- INC-1043 Ticoworld t3n-breakglass-sandbox 123456 300
```

For direct `node`/`tsx` automation where the confirmation is itself explicit and reviewed:

```powershell
node --env-file-if-exists=.env.bootstrap node_modules/tsx/dist/cli.mjs scripts/incident-create.ts --incident-id=INC-1043 --owner=Ticoworld --repo=t3n-breakglass-sandbox --key-id=123456 --ttl=300 --confirm
```

The positional form is `INCIDENT_ID OWNER REPOSITORY DEPLOY_KEY_ID TTL_SECONDS`. The command resolves the real replacement agent from the organization roster, fixes the action to `revoke_github_deploy_key`, fixes `max_uses=1`, computes expiry from the trusted T3N node time, and writes only after confirmation.

## Run the agent

For an AI tool client, start the stdio MCP server:

```powershell
npm run agent
```

It exposes only `breakglass_execute_incident({ incident_id })`. For a terminal run:

```powershell
npm run agent:execute -- INC-1043
```

The agent process must not be started with `.env.bootstrap`; its only credential is the replacement-agent key.

## Demo

```powershell
npm run demo
```

The live demo ensures a separate disposable read-only GitHub key through the bootstrap-style path, performs a nonexistent-authority denial, creates a five-minute authority with preview/confirmation, executes it through the agent CLI, independently verifies absence, and replays it. It does not fake T3N or GitHub and does not overwrite Phase 1 evidence.

## Reconciliation and recovery

If DELETE or its verification is ambiguous, the contract persists `RECONCILE_REQUIRED`. A subsequent execution request performs only an authoritative GET. HTTP 404 consumes the authority; any other result leaves reconciliation required. There is no destructive retry.

If the agent key is wrong, expired, unfunded, or unavailable, fix the external condition and use the same incident only if it remains `ACTIVE` and has not been partially executed. Do not manually edit the KV record. If execution has reached `EXECUTING` or `RECONCILE_REQUIRED`, use the GET-only reconciliation path.

## Replacement agent procedure

Provision exactly one new organization-owned agent through the documented default-card path, confirm its `whoami`, owner, roster membership, private card, funding, and exact egress. Update the local replacement-agent environment only after those checks. Do not reuse the malformed no-card agent evidence or grant the agent operator credentials.

## Adding a future emergency action

Do not add an action by widening the agent input. Add a separate, explicitly bounded contract action with its own authority schema, target validation, fixed egress policy, one-use/replay semantics, reconciliation behavior, unit tests, live disposable evidence, and threat-model entry. Keep the operator creation surface privileged and the agent request limited to an incident identifier.

## Post-challenge

I’m happy to continue developing BreakGlass after the challenge. The current implementation is deliberately limited to one proven emergency action, and this guide is intended for Terminal 3 or another maintainer if ownership needs to transfer.
