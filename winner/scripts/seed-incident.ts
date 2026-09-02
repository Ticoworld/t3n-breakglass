import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { connectTenant, redactError } from "../../scripts/lib.js";
import { ACTION, CONTRACT_VERSION, GITHUB_OWNER, GITHUB_REPOSITORY, INCIDENT_MAP_TAIL } from "./constants.js";

const root = path.resolve(import.meta.dirname, "../..");

function required(name: string): string { const value = process.env[name]; if (!value) throw new Error(`${name} is required`); return value; }
function positive(name: string): number { const value = Number(required(name)); if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive safe integer`); return value; }

async function main() {
  if (process.env.GITHUB_PAT) throw new Error("C1 incident seeding refuses a GitHub PAT");
  const registration = JSON.parse(await readFile(path.join(root, "winner", "evidence", "contract-registration.json"), "utf8")) as { operator_did?: string; contract?: { name?: string } };
  const configured = JSON.parse(await readFile(path.join(root, "winner", "evidence", "delegation-configuration.json"), "utf8")) as { remediation_agent_did?: string; effect_broker_did?: string };
  if (!registration.operator_did || !registration.contract?.name || !configured.remediation_agent_did || !configured.effect_broker_did) throw new Error("C1 registration/configuration evidence is incomplete");
  const incidentId = required("C1_INCIDENT_ID");
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(incidentId)) throw new Error("C1_INCIDENT_ID has an invalid format");
  const owner = GITHUB_OWNER;
  const repo = GITHUB_REPOSITORY;
  if (process.env.C1_GITHUB_OWNER && process.env.C1_GITHUB_OWNER !== owner) throw new Error("C1_GITHUB_OWNER cannot override the committed broker target");
  if (process.env.C1_GITHUB_REPO && process.env.C1_GITHUB_REPO !== repo) throw new Error("C1_GITHUB_REPO cannot override the committed broker target");
  const createdAt = positive("C1_CREATED_AT");
  const expiresAt = positive("C1_EXPIRES_AT");
  if (expiresAt <= createdAt) throw new Error("expiry must be after creation");
  const keyId = positive("C1_DEPLOY_KEY_ID");
  const authority = {
    incident_id: incidentId,
    remediation_agent_did: configured.remediation_agent_did,
    effect_broker_did: configured.effect_broker_did,
    action: ACTION,
    github_owner: owner,
    github_repo: repo,
    deploy_key_id: keyId,
    created_at: createdAt,
    expires_at: expiresAt,
    max_effects: 1,
    effect_attempts: 0,
    status: "ACTIVE",
    reservation_id: null,
    reservation_version: 0,
    effect_claim_id: null,
    effect_claim_version: 0,
    final_result_classification: null,
  };
  const { tenant, tenantDid, nodeUrl } = await connectTenant();
  if (tenantDid !== registration.operator_did) throw new Error("authenticated operator DID differs from registration");
  const encoded = JSON.stringify(authority);
  await tenant.maps.entrySet(INCIDENT_MAP_TAIL, incidentId, encoded);
  const readback = await tenant.maps.entryGet(INCIDENT_MAP_TAIL, incidentId);
  if (readback !== encoded) throw new Error("authority readback differs from the seeded record");
  const evidence = { experiment: "C1 manual incident authority seed", status: "SEEDED", environment: "testnet", sdk: "@terminal3/t3n-sdk 5.2.0", t3n_node: nodeUrl, operator_did: tenantDid, contract: registration.contract.name, map: tenant.canonicalName(INCIDENT_MAP_TAIL), authority, provider_mutations: 0 };
  const evidencePath = path.join(root, "winner", "evidence", `incident-${incidentId.toLowerCase().replace(/[^a-z0-9-]+/g, "-")}.json`);
  await mkdir(path.dirname(evidencePath), { recursive: true });
  await writeFile(evidencePath, JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((error) => { console.error(`C1 incident seed failed: ${redactError(error, [process.env.T3N_API_KEY ?? "", process.env.GITHUB_PAT ?? ""])}`); process.exitCode = 1; });
