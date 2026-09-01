import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { SessionOrgDataClient } from "@terminal3/t3n-sdk";
import {
  CONTRACT_FUNCTION,
  CONTRACT_VERSION,
  INCIDENT_MAP_TAIL,
  connectTenant,
  redactError,
} from "./lib.js";
import { inspectGithubTarget, type GithubTarget } from "./github.js";
import {
  formatTimestamp,
  assertIncidentIsUnused,
  parsePositiveInteger,
  readPhase1Setup,
  readReplacementProvisioning,
  trustedNodeTimeSeconds,
  validateIncidentId,
  validateTtlSeconds,
} from "./product.js";

const root = path.resolve(import.meta.dirname, "..");
const agentName = "BreakGlass Agent";

export type IncidentCreateInput = {
  incidentId: string;
  owner: string;
  repository: string;
  deployKeyId: number;
  ttlSeconds: number;
};

type ReplacementAgent = {
  did: string;
  organizationDid: string;
};

export type IncidentPreview = {
  incident_id: string;
  agent_did: string;
  action: "revoke_github_deploy_key";
  target: { owner: string; repository: string; deploy_key_id: number; read_only: boolean | null };
  created_at: number;
  expires_at: number;
  ttl_seconds: number;
  max_uses: 1;
  uses: 0;
  status: "ACTIVE";
};

export type IncidentAuthorityRecord = Omit<IncidentPreview, "target" | "ttl_seconds"> & {
  github_owner: string;
  github_repo: string;
  deploy_key_id: number;
};

export type PreparedIncident = {
  preview: IncidentPreview;
  target: GithubTarget;
  operatorDid: string;
  contractId: string;
  nodeUrl: string;
  mapName: string;
};

function exactEgress(value: unknown, contractId: string): boolean {
  const response = value as { egress?: { contract_id?: string; allowed_hosts?: string[]; functions?: string[]; version_req?: string } };
  return response.egress?.contract_id === contractId
    && response.egress.allowed_hosts?.length === 1
    && response.egress.allowed_hosts[0] === "api.github.com"
    && response.egress.functions?.length === 1
    && response.egress.functions[0] === CONTRACT_FUNCTION
    && response.egress.version_req === CONTRACT_VERSION;
}

async function resolveReplacementAgent(
  t3n: Awaited<ReturnType<typeof connectTenant>>["t3n"],
  nodeUrl: string,
  contractId: string,
): Promise<ReplacementAgent> {
  const { organizationDid, expectedAgentDid } = await readReplacementProvisioning();
  const orgData = new SessionOrgDataClient(t3n, nodeUrl);
  if (!(await orgData.amIAdmin({ orgDid: organizationDid }))) throw new Error("operator is not an administrator of the existing organization");
  const roster = await orgData.listAgents({ orgDid: organizationDid, limit: 100 });
  const candidates = roster.agents.filter((agent) => agent.name === agentName);
  if (candidates.length !== 1) throw new Error(`expected exactly one organization-owned ${agentName}`);
  const agentDid = candidates[0].did;
  if (!/^did:t3n:[0-9a-f]{40}$/.test(agentDid)) throw new Error("organization roster returned an invalid agent DID");
  if (expectedAgentDid && agentDid !== expectedAgentDid) throw new Error("organization roster did not return the recorded replacement agent");
  const card = await orgData.agentCardGet({ ownerDid: organizationDid, agentDid });
  if (card.agent_did !== agentDid || typeof card.card !== "string" || card.card.length === 0) throw new Error("replacement private agent card is not readable");
  const egress = await orgData.getAgentEgress({ orgDid: organizationDid, agentDid, contractId });
  if (!exactEgress(egress, contractId)) throw new Error("replacement agent egress is not the exact GitHub execution policy");
  return { did: agentDid, organizationDid };
}

export function buildIncidentPreview(input: IncidentCreateInput, agentDid: string, createdAt: number, readOnly: boolean | null): IncidentPreview {
  return {
    incident_id: input.incidentId,
    agent_did: agentDid,
    action: "revoke_github_deploy_key",
    target: { owner: input.owner, repository: input.repository, deploy_key_id: input.deployKeyId, read_only: readOnly },
    created_at: createdAt,
    expires_at: createdAt + input.ttlSeconds,
    ttl_seconds: input.ttlSeconds,
    max_uses: 1,
    uses: 0,
    status: "ACTIVE",
  };
}

export function renderIncidentPreview(preview: IncidentPreview): string {
  return [
    "INCIDENT AUTHORITY PREVIEW",
    "",
    `Incident: ${preview.incident_id}`,
    `Agent: ${preview.agent_did}`,
    `Action: ${preview.action}`,
    `Target: ${preview.target.owner}/${preview.target.repository}#${preview.target.deploy_key_id}`,
    `Read-only key: ${preview.target.read_only === true ? "yes" : "no/unknown"}`,
    `Created: ${formatTimestamp(preview.created_at)}`,
    `Expires: ${formatTimestamp(preview.expires_at)}`,
    `Uses: ${preview.uses}/${preview.max_uses}`,
    `Status: ${preview.status}`,
  ].join("\n");
}

export async function prepareIncidentAuthority(input: IncidentCreateInput): Promise<PreparedIncident> {
  validateIncidentId(input.incidentId);
  const { contractId } = await readPhase1Setup();
  const { tenant, tenantDid, nodeUrl, t3n } = await connectTenant();
  const existing = await tenant.maps.entryGet(INCIDENT_MAP_TAIL, input.incidentId);
  assertIncidentIsUnused(existing, input.incidentId);
  const agent = await resolveReplacementAgent(t3n, nodeUrl, contractId);
  const target = await inspectGithubTarget(input.owner, input.repository, input.deployKeyId);
  const createdAt = await trustedNodeTimeSeconds(nodeUrl);
  const preview = buildIncidentPreview(input, agent.did, createdAt, target.readOnly ?? null);
  return { preview, target, operatorDid: tenantDid, contractId, nodeUrl, mapName: tenant.canonicalName(INCIDENT_MAP_TAIL) };
}

export async function persistPreparedIncident(prepared: PreparedIncident): Promise<IncidentAuthorityRecord> {
  const { tenant } = await connectTenant();
  const preview = prepared.preview;
  const existing = await tenant.maps.entryGet(INCIDENT_MAP_TAIL, preview.incident_id);
  assertIncidentIsUnused(existing, preview.incident_id);

  const authority = {
    incident_id: preview.incident_id,
    agent_did: preview.agent_did,
    action: preview.action,
    github_owner: preview.target.owner,
    github_repo: preview.target.repository,
    deploy_key_id: preview.target.deploy_key_id,
    created_at: preview.created_at,
    expires_at: preview.expires_at,
    max_uses: preview.max_uses,
    uses: preview.uses,
    status: preview.status,
  } satisfies IncidentAuthorityRecord;
  const encoded = JSON.stringify(authority);
  await tenant.maps.entrySet(INCIDENT_MAP_TAIL, preview.incident_id, encoded);
  const stored = await tenant.maps.entryGet(INCIDENT_MAP_TAIL, preview.incident_id);
  if (stored !== encoded) throw new Error("T3N did not return the exact Incident Authority after write");
  await mkdir(path.join(root, "evidence"), { recursive: true });
  await writeFile(
    path.join(root, "evidence", `phase2-incident-${preview.incident_id.toLowerCase().replace(/[^a-z0-9-]+/g, "-")}.json`),
    JSON.stringify({
      phase: "2",
      stage: "operator_incident_authority_created",
      environment: "testnet",
      t3n_node: prepared.nodeUrl,
      operator_did: prepared.operatorDid,
      storage: { map: prepared.mapName, private: true, key: preview.incident_id },
      authority,
      target_preflight: { host: prepared.target.host, repository_private: prepared.target.repositoryPrivate, key_get_verified: true, key_read_only: prepared.target.readOnly },
      operator_confirmation: true,
      github_pat_read_by_agent: false,
      github_pat_logged: false,
    }, null, 2) + "\n",
  );
  return authority;
}

export async function createIncidentAuthority(input: IncidentCreateInput, confirmed: boolean): Promise<{ preview: IncidentPreview; authority?: IncidentAuthorityRecord; operatorDid: string; contractId: string; nodeUrl: string }> {
  const prepared = await prepareIncidentAuthority(input);
  if (!confirmed) return prepared;
  const authority = await persistPreparedIncident(prepared);
  return { ...prepared, authority };
}

function parseFlags(args: string[]): { input: IncidentCreateInput; confirmed: boolean } {
  // Some npm 11 / PowerShell combinations consume `--name=value` options
  // while forwarding their values. Keep a positional adapter for the npm
  // surface; direct Node/tsx invocation still supports the named options.
  if (args.length === 5 && args.every((arg) => !arg.startsWith("--"))) {
    const [incident, owner, repository, keyId, ttl] = args;
    return {
      input: {
        incidentId: validateIncidentId(incident),
        owner,
        repository,
        deployKeyId: parsePositiveInteger(keyId, "deploy-key-id"),
        ttlSeconds: validateTtlSeconds(ttl),
      },
      confirmed: false,
    };
  }
  const values = new Map<string, string>();
  let confirmed = false;
  for (let i = 0; i < args.length; i += 1) {
    const rawFlag = args[i];
    const equalsAt = rawFlag?.indexOf("=") ?? -1;
    const flag = equalsAt >= 0 ? rawFlag.slice(0, equalsAt) : rawFlag;
    if (flag === "--confirm") {
      if (equalsAt >= 0) throw new Error("--confirm does not take a value");
      confirmed = true;
      continue;
    }
    if (!flag?.startsWith("--")) throw new Error("options must start with --");
    if (equalsAt >= 0) {
      const value = rawFlag.slice(equalsAt + 1);
      if (!value) throw new Error(`${flag} needs a value`);
      values.set(flag.slice(2), value);
      continue;
    }
    if (i + 1 >= args.length || args[i + 1].startsWith("--")) throw new Error("each option needs a value; use --confirm only as a flag");
    values.set(flag.slice(2), args[++i]);
  }
  const incidentId = validateIncidentId(values.get("incident-id") ?? values.get("incident") ?? "");
  const owner = values.get("owner") ?? "";
  const repository = values.get("repo") ?? values.get("repository") ?? "";
  const deployKeyId = parsePositiveInteger(values.get("key-id") ?? values.get("deploy-key-id") ?? "", "deploy-key-id");
  const ttlSeconds = validateTtlSeconds(values.get("ttl") ?? "");
  return { input: { incidentId, owner, repository, deployKeyId, ttlSeconds }, confirmed };
}

async function main() {
  const { input, confirmed: flagConfirmed } = parseFlags(process.argv.slice(2));
  const prepared = await prepareIncidentAuthority(input);
  console.log(renderIncidentPreview(prepared.preview));
  let confirmed = flagConfirmed;
  if (!confirmed) {
    const answer = await new Promise<string>((resolve) => {
      process.stdin.setEncoding("utf8");
      process.stdout.write("\nType CREATE to persist this authority: ");
      process.stdin.once("data", (chunk) => resolve(String(chunk).trim()));
    });
    confirmed = answer === "CREATE";
  }
  if (!confirmed) {
    console.log("\nCANCELLED — no Incident Authority was written.");
    return;
  }
  const authority = await persistPreparedIncident(prepared);
  console.log(`\nINCIDENT CREATED\n\n${renderIncidentPreview(prepared.preview)}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  main().catch((error) => {
    console.error(`incident:create failed: ${redactError(error, [process.env.GITHUB_PAT ?? "", process.env.T3N_API_KEY ?? ""] )}`);
    process.exitCode = 1;
  });
}
