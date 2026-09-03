import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { connectTenant } from "../../scripts/lib.js";
import { invokeC1OperatorSession } from "./t3n.js";
import { BROKER_FUNCTIONS, CONTRACT_TAIL, CONTRACT_VERSION, INCIDENT_MAP_TAIL, ORGANISATION_DID, RESERVATION_FUNCTION, contractName } from "./constants.js";

const root = path.resolve(import.meta.dirname, "../..");
const OPERATOR_DID = "did:t3n:adb9365ee986cc6d0cb4006580782fe6fc7a431f";
const EXPECTED_NUMERIC_ID = 877;
const CONTRACT_ID = contractName(OPERATOR_DID);
// create-incident is probed separately with its complete strict input and an
// intentionally invalid TTL. Sending only incident_id to create-incident is
// malformed input, not a registered-surface probe.
const SURFACE_FUNCTIONS = ["get-incident", RESERVATION_FUNCTION, ...BROKER_FUNCTIONS] as const;
const ALL_FUNCTIONS = ["create-incident", ...SURFACE_FUNCTIONS] as const;

type JsonObject = Record<string, unknown>;

function isObject(value: unknown): value is JsonObject {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function parseResult(value: unknown): JsonObject | null {
  const parsed = typeof value === "string" ? (() => { try { return JSON.parse(value); } catch { return null; } })() : value;
  return isObject(parsed) ? parsed : null;
}

function sanitize(value: unknown, depth = 0): unknown {
  if (depth > 8) return "[DEPTH_LIMIT]";
  if (typeof value === "string") return value.slice(0, 1000);
  if (typeof value === "number" || typeof value === "boolean" || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, 40).map((entry) => sanitize(entry, depth + 1));
  if (!isObject(value)) return String(value);
  const output: JsonObject = {};
  for (const [key, entry] of Object.entries(value)) {
    output[key] = /api[_-]?key|authorization|bearer|token|jwt|private[_-]?key|pat|secret|credential/i.test(key) ? "[REDACTED]" : sanitize(entry, depth + 1);
  }
  return output;
}

function fresh(label: string): string {
  return `C1-R6B-SURFACE-${label}-${Date.now()}-${randomUUID().slice(0, 8)}`;
}

function errorRecord(error: unknown): JsonObject {
  return { class: error instanceof Error ? error.constructor.name : typeof error, name: error instanceof Error ? error.name : "unknown", message: sanitize(error instanceof Error ? error.message : String(error)) };
}

function observation(functionName: string, value: unknown): JsonObject {
  const response = parseResult(value);
  return {
    routing_recognized: Boolean(response),
    guest_reached: Boolean(response && response.function === functionName && typeof response.result === "string"),
    application_result: response?.result ?? null,
    application_note: response?.note ?? null,
    response: sanitize(value),
  };
}

async function writeFailure(probes: JsonObject[], invalidCreateId: string, create: JsonObject, absent: JsonObject, reason: string): Promise<void> {
  const failurePath = path.join(root, "winner", "evidence", "C1-R6B-SURFACE-FAILURE.json");
  await writeFile(failurePath, JSON.stringify({
    phase: "C1-R6B registered surface probe",
    status: "R6B_REGISTERED_SURFACE_FAILURE",
    contract: CONTRACT_ID,
    version: CONTRACT_VERSION,
    numeric_contract_id: EXPECTED_NUMERIC_ID,
    reason,
    probes,
    invalid_create_id: invalidCreateId,
    invalid_create_probe: create,
    post_probe_nonexistence: absent,
    successful_incident_creations: 0,
    map_entry_writes: 0,
    provider_operations: 0,
    credentials_in_evidence: false,
  }, null, 2) + "\n");
}

async function main(): Promise<void> {
  if (process.env.GITHUB_PAT || process.env.GITHUB_APP_ID || process.env.GITHUB_APP_INSTALLATION_ID || process.env.GITHUB_APP_PRIVATE_KEY_PATH) throw new Error("R6B surface probe refuses provider credentials");
  const { t3n, tenantDid } = await connectTenant();
  if (tenantDid !== OPERATOR_DID) throw new Error("R6B surface probe authenticated as an unexpected operator");
  const probes: JsonObject[] = [];
  const call = async (functionName: string, input: JsonObject, purpose: string): Promise<JsonObject> => {
    const record: JsonObject = { purpose, function: functionName, incident_id: input.incident_id, request_fields: Object.keys(input).sort(), transport: "authenticated T3nClient.executeAndDecode", contract: CONTRACT_ID, version: CONTRACT_VERSION, provider_operations: 0 };
    try { Object.assign(record, observation(functionName, await invokeC1OperatorSession(t3n, CONTRACT_ID, functionName, input))); }
    catch (error) { Object.assign(record, { routing_recognized: !/function not found/i.test(error instanceof Error ? error.message : String(error)), guest_reached: false, error: errorRecord(error) }); }
    probes.push(record);
    return record;
  };

  for (const functionName of SURFACE_FUNCTIONS) {
    const incidentId = fresh(functionName.replaceAll("-", "_"));
    const input: JsonObject = { incident_id: incidentId };
    if (functionName === "claim-effect") input.expected_claim_version = 0;
    if (["release-not-attempted", "begin-effect", "finalize-effect", "reconcile-effect"].includes(functionName)) input.claim_id = "r6b-surface";
    if (["finalize-effect", "reconcile-effect"].includes(functionName)) input.classification = "ATTEMPTED_OUTCOME_UNKNOWN";
    await call(functionName, input, "registered_surface_nonexistent");
  }

  const invalidCreateId = fresh("invalid_ttl_create");
  const create = await call("create-incident", { incident_id: invalidCreateId, remediation_agent_did: "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019", effect_broker_did: "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57", deploy_key_id: 1, ttl_secs: 1 }, "invalid_ttl_create");
  const absent = await call("get-incident", { incident_id: invalidCreateId }, "invalid_create_post_read");
  const expectedAbsent = (record: JsonObject) => record.guest_reached === true && record.application_result === "DENIED" && typeof record.application_note === "string" && /does not exist/i.test(record.application_note);
  const failedSurface = probes.filter((probe) => probe.routing_recognized !== true || probe.guest_reached !== true).map((probe) => ({ function: probe.function, routing_recognized: probe.routing_recognized, guest_reached: probe.guest_reached, application_result: probe.application_result ?? null, application_note: probe.application_note ?? null, error: probe.error ?? null }));
  if (failedSurface.length > 0) {
    await writeFailure(probes, invalidCreateId, create, absent, `surface functions failed: ${failedSurface.map((entry) => entry.function).join(", ")}`);
    throw new Error(`R6B registered surface did not reach guest behavior for: ${failedSurface.map((entry) => entry.function).join(", ")}`);
  }
  if (create.application_result !== "DENIED" || !/ttl|bounded|seconds|minimum/i.test(String(create.application_note)) || !expectedAbsent(absent)) {
    await writeFailure(probes, invalidCreateId, create, absent, "invalid TTL probe did not prove bounded denial and nonexistence");
    throw new Error("R6B invalid TTL probe did not prove bounded denial and nonexistence");
  }

  const registrationPath = path.join(root, "winner", "evidence", "contract-registration.json");
  const registration = JSON.parse(await readFile(registrationPath, "utf8")) as JsonObject;
  const contract = isObject(registration.contract) ? registration.contract : {};
  if (contract.name !== CONTRACT_ID || contract.version !== CONTRACT_VERSION || contract.contract_id !== EXPECTED_NUMERIC_ID || !isObject(registration.map) || registration.map.private !== true || registration.map.acl_contract_id !== EXPECTED_NUMERIC_ID) throw new Error("R6B registration evidence does not match contract 2.0.3/877");
  contract.node_routing_verified_functions = [...ALL_FUNCTIONS];
  contract.node_routing_observed_via = "authenticated operator session; every function returned guest-level application behavior";
  contract.node_routing_observed_at_utc = new Date().toISOString();
  registration.contract = contract;
  registration.surface_probe = { operator_did: tenantDid, organization_did: ORGANISATION_DID, probes, invalid_create_id: invalidCreateId, successful_incident_creations: 0, map_entry_writes: 0, provider_operations: 0 };
  await mkdir(path.dirname(registrationPath), { recursive: true });
  await writeFile(registrationPath, JSON.stringify(registration, null, 2) + "\n");
  process.stdout.write(JSON.stringify({ status: "R6B_REGISTERED_SURFACE_PASS", contract: { name: CONTRACT_ID, version: CONTRACT_VERSION, numeric_id: EXPECTED_NUMERIC_ID, map_tail: INCIDENT_MAP_TAIL, map_private: true }, probes: probes.length, invalid_create_id: invalidCreateId, invalid_create_denied: true, post_probe_absent: true, provider_operations: 0 }));
}

main().catch((error) => { console.error(`R6B surface probe failed: ${error instanceof Error ? error.message : String(error)}`); process.exitCode = 1; });
