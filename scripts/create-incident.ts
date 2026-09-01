import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  INCIDENT_MAP_TAIL,
  connectTenant,
  redactError,
  required,
} from "./lib.js";

const root = path.resolve(import.meta.dirname, "..");

type TargetEvidence = {
  owner?: string;
  repository?: string;
  deploy_key?: { id?: number; read_only?: boolean };
  repository_private?: boolean;
  deploy_key_count?: number;
};

async function loadTarget() {
  const target = JSON.parse(await readFile(path.join(root, "evidence", "phase1-github-target.json"), "utf8")) as TargetEvidence;
  const deployKeyId = Number(target.deploy_key?.id);
  if (
    target.owner !== "Ticoworld" ||
    target.repository !== "t3n-breakglass-sandbox" ||
    target.repository_private !== true ||
    target.deploy_key_count !== 1 ||
    target.deploy_key?.read_only !== true ||
    !Number.isSafeInteger(deployKeyId) ||
    deployKeyId <= 0
  ) throw new Error("phase1 GitHub target evidence is not a verified one-key private target");
  return { owner: target.owner, repository: target.repository, deployKeyId };
}

function positiveInteger(name: string, value: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) throw new Error(`${name} must be a positive integer`);
  return parsed;
}

async function main() {
  const incidentId = process.env.INCIDENT_ID ?? "INC-1042";
  const agentDid = required("AGENT_DID").toLowerCase();
  if (!/^did:t3n:[0-9a-f]{40}$/.test(agentDid)) throw new Error("AGENT_DID must be canonical did:t3n:<40-hex>");

  const target = await loadTarget();
  const createdAt = process.env.INCIDENT_CREATED_AT
    ? positiveInteger("INCIDENT_CREATED_AT", process.env.INCIDENT_CREATED_AT)
    : Math.floor(Date.now() / 1000);
  const expiresAt = process.env.INCIDENT_EXPIRES_AT
    ? positiveInteger("INCIDENT_EXPIRES_AT", process.env.INCIDENT_EXPIRES_AT)
    : createdAt + positiveInteger("INCIDENT_TTL_SECS", process.env.INCIDENT_TTL_SECS ?? "300");
  if (expiresAt <= createdAt) throw new Error("incident expiry must be after creation");

  const record = {
    incident_id: incidentId,
    agent_did: agentDid,
    action: "revoke_github_deploy_key",
    github_owner: target.owner,
    github_repo: target.repository,
    deploy_key_id: target.deployKeyId,
    created_at: createdAt,
    expires_at: expiresAt,
    max_uses: 1,
    uses: 0,
    status: "ACTIVE",
  };
  const encoded = JSON.stringify(record);
  const { tenant, tenantDid, nodeUrl } = await connectTenant();
  await tenant.maps.entrySet(INCIDENT_MAP_TAIL, incidentId, encoded);
  const stored = await tenant.maps.entryGet(INCIDENT_MAP_TAIL, incidentId);
  if (stored !== encoded) throw new Error("T3N did not return the exact authority record after write");

  const evidence = {
    phase: "1",
    status: "authority_created",
    environment: "testnet",
    t3n_node: nodeUrl,
    operator_did: tenantDid,
    storage: { map: tenant.canonicalName(INCIDENT_MAP_TAIL), key: incidentId, private: true },
    authority: record,
    agent_request_boundary: { accepted_fields: ["incident_id"], target_fields: "not accepted" },
    github_credential: { read: false, included: false, logged: false },
    stored_record_round_trip: true,
  };
  await mkdir(path.join(root, "evidence"), { recursive: true });
  const evidenceName = `phase1-incident-${incidentId.toLowerCase().replace(/[^a-z0-9-]+/g, "-")}.json`;
  await writeFile(path.join(root, "evidence", evidenceName), JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((error) => {
  console.error(`incident creation failed: ${redactError(error, [process.env.GITHUB_PAT ?? "", process.env.T3N_API_KEY ?? "", process.env.AGENT_T3N_API_KEY ?? ""])}`);
  process.exitCode = 1;
});
