import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { connectTenant, redactError } from "../../scripts/lib.js";
import { CONTRACT_VERSION, contractName } from "./constants.js";
import { invokeC1, redact, requireValue } from "./t3n.js";

const root = path.resolve(import.meta.dirname, "../..");
const registrationPath = path.join(root, "winner", "evidence", "contract-registration.json");
const configurationPath = path.join(root, "winner", "evidence", "delegation-configuration.json");

function positive(name: string, fallback?: number): number {
  const raw = process.env[name] ?? (fallback === undefined ? undefined : String(fallback));
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive safe integer`);
  return value;
}

function resultObject(raw: unknown): Record<string, unknown> {
  const value = typeof raw === "string" ? JSON.parse(raw) : raw;
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("C1 contract returned a non-object result");
  return value as Record<string, unknown>;
}

function authorityFrom(response: unknown, result: string, functionName: string, incidentId: string): Record<string, unknown> {
  const value = resultObject(response);
  if (value.result !== result || value.function !== functionName || !value.detail || typeof value.detail !== "object" || Array.isArray(value.detail)) throw new Error(`C1 ${functionName} did not return the expected authority result`);
  const authority = value.detail as Record<string, unknown>;
  if (authority.incident_id !== incidentId || authority.action !== "revoke_github_deploy_key" || authority.github_owner !== "Ticoworld" || authority.github_repo !== "t3n-breakglass-sandbox" || authority.max_effects !== 1) throw new Error("C1 contract returned an unexpected authority target");
  return authority;
}

async function main() {
  if (process.env.GITHUB_PAT) throw new Error("C1 incident creation refuses a GitHub PAT");
  const operatorDid = requireValue("C1_OPERATOR_DID");
  const incidentId = requireValue("C1_INCIDENT_ID");
  const deployKeyId = positive("C1_DEPLOY_KEY_ID");
  const ttlSecs = positive("C1_TTL_SECS", 900);
  const registration = JSON.parse(await readFile(registrationPath, "utf8")) as { operator_did?: string; contract?: { name?: string; version?: string; contract_id?: number } };
  const configuration = JSON.parse(await readFile(configurationPath, "utf8")) as { status?: string; operator_did?: string; contract?: string; contract_version?: string; contract_id?: number; remediation_agent_did?: string; effect_broker_did?: string };
  const contractId = contractName(operatorDid);
  if (registration.operator_did !== operatorDid || registration.contract?.name !== contractId || registration.contract.version !== CONTRACT_VERSION || !Number.isSafeInteger(registration.contract.contract_id) || configuration.status !== "CONFIGURED_VERIFIED" || configuration.operator_did !== operatorDid || configuration.contract !== contractId || configuration.contract_version !== CONTRACT_VERSION || configuration.contract_id !== registration.contract.contract_id || !configuration.remediation_agent_did || !configuration.effect_broker_did) throw new Error("C1 registration/configuration evidence is incomplete or stale");
  const { tenantDid, nodeUrl } = await connectTenant();
  if (tenantDid !== operatorDid) throw new Error("authenticated operator DID differs from configured C1 operator");
  const operatorKey = requireValue("T3N_API_KEY");
  const input = { incident_id: incidentId, remediation_agent_did: configuration.remediation_agent_did, effect_broker_did: configuration.effect_broker_did, deploy_key_id: deployKeyId, ttl_secs: ttlSecs };
  const createResponse = await invokeC1(operatorKey, nodeUrl, contractId, "create-incident", input);
  const authority = authorityFrom(createResponse, "WON", "create-incident", incidentId);
  const readbackResponse = await invokeC1(operatorKey, nodeUrl, contractId, "get-incident", { incident_id: incidentId });
  const readback = authorityFrom(readbackResponse, "FOUND", "get-incident", incidentId);
  if (JSON.stringify(authority) !== JSON.stringify(readback)) throw new Error("C1 contract authority readback differs from create result");
  const evidence = { experiment: "C1 contract-mediated incident authority creation", status: "SEEDED", environment: "testnet", sdk: "@terminal3/t3n-sdk 5.2.0", t3n_node: nodeUrl, operator_did: tenantDid, contract: contractId, request_fields: ["incident_id", "remediation_agent_did", "effect_broker_did", "deploy_key_id", "ttl_secs"], authority: readback, provider_mutations: 0, operator_direct_map_access: false, credentials_in_evidence: false };
  const evidencePath = path.join(root, "winner", "evidence", `incident-${incidentId.toLowerCase().replace(/[^a-z0-9-]+/g, "-")}.json`);
  await mkdir(path.dirname(evidencePath), { recursive: true });
  await writeFile(evidencePath, JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((error) => { console.error(`C1 incident create failed: ${redactError(error, [process.env.T3N_API_KEY ?? "", process.env.GITHUB_PAT ?? ""])}`); process.exitCode = 1; });
