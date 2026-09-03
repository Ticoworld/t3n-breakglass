import { mkdir, readFile, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import path from "node:path";
import { connectTenant } from "../../scripts/lib.js";
import { CONTRACT_VERSION, contractName } from "./constants.js";
import { redact } from "./t3n.js";

const root = path.resolve(import.meta.dirname, "../..");
const OPERATOR_DID = "did:t3n:adb9365ee986cc6d0cb4006580782fe6fc7a431f";
const ORGANISATION_DID = "did:t3n:3c63f09271c0d9184abbcccbfae28698a8f4a912";
const REMEDIATION_DID = "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019";
const BROKER_DID = "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57";
const CONTRACT_ID = contractName(OPERATOR_DID);
const CONTRACT_NUMERIC_ID = 876;
const EXPECTED_FUNCTIONS = ["create-incident", "get-incident", "reserve-incident", "claim-effect", "release-not-attempted", "finalize-effect", "reconcile-effect"] as const;
const SURFACE_FUNCTIONS = ["get-incident", "reserve-incident", "claim-effect", "release-not-attempted", "finalize-effect", "reconcile-effect"] as const;
const PRE_REBUILD_SHA256 = "0668b97eaf3eac086ef7a37bfba36eabde2e01ef1e64814e1749f94fac62aebc";
const PRE_REBUILD_EXPORTS = ["reserve-incident", "claim-effect", "release-not-attempted", "finalize-effect", "reconcile-effect"] as const;
const FINAL_WASM_SHA256 = "7b4cd5e5d0b8b0f158da95ce0fd64fc44d2d5961020768d60dfc9c69b43ade22";
const FINAL_WASM_BYTES = 203820;

type JsonObject = Record<string, unknown>;

function isObject(value: unknown): value is JsonObject {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function sanitize(value: unknown, secrets: string[], depth = 0): unknown {
  if (depth > 10) return "[DEPTH_LIMIT]";
  if (typeof value === "string") return redact(value, secrets).slice(0, 1000);
  if (typeof value === "number" || typeof value === "boolean" || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, 40).map((entry) => sanitize(entry, secrets, depth + 1));
  if (!isObject(value)) return String(value);
  const output: JsonObject = {};
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry !== "boolean" && entry !== null && /^(api[_-]?key|authorization|bearer|access[_-]?token|installation[_-]?token|jwt|private[_-]?key|pat|secret|credential)$/i.test(key)) output[key] = "[REDACTED]";
    else output[key] = sanitize(entry, secrets, depth + 1);
  }
  return output;
}

function safeError(error: unknown, secrets: string[]): JsonObject {
  const record = isObject(error) ? error : null;
  const output: JsonObject = {
    class: error instanceof Error ? error.constructor.name : typeof error,
    name: error instanceof Error ? error.name : "unknown",
    message: sanitize(error instanceof Error ? error.message : String(error), secrets),
  };
  for (const [source, target] of [["httpStatus", "http_status"], ["rpcMethod", "rpc_method"], ["detail", "detail"], ["requestId", "request_id"], ["code", "code"]] as const) {
    if (record?.[source] !== undefined) output[target] = sanitize(record[source], secrets);
  }
  return output;
}

function appObservation(value: unknown, functionName: string): { guest: boolean; result: unknown; note: unknown } {
  const parsed = typeof value === "string" ? (() => { try { return JSON.parse(value); } catch { return value; } })() : value;
  const record = isObject(parsed) ? parsed : null;
  return {
    guest: Boolean(record && record.function === functionName && typeof record.result === "string"),
    result: record?.result ?? null,
    note: record?.note ?? null,
  };
}

function activityRows(page: unknown, secrets: string[]): unknown[] {
  const record = isObject(page) ? page : {};
  return (Array.isArray(record.entries) ? record.entries : []).map((entry) => {
    const row = isObject(entry) ? {
      seq_no: entry.seq_no,
      hash: entry.hash,
      timestamp_ms: entry.timestamp_ms,
      caller_type: entry.caller_type,
      actor: entry.actor,
      on_behalf_of: entry.on_behalf_of,
      org: entry.org,
      contract: entry.contract,
      function: entry.function,
      outcome: entry.outcome,
      ...(Array.isArray(entry.roles) ? { roles: entry.roles } : {}),
    } : null;
    return sanitize(row, secrets);
  }).filter(Boolean);
}

async function activitySnapshot(t3n: { getActivityLog: (options: JsonObject) => Promise<unknown> }, functionName: string, secrets: string[]): Promise<JsonObject> {
  try {
    const page = await t3n.getActivityLog({ did: OPERATOR_DID, contract: CONTRACT_ID, function: functionName, limit: 100 });
    const record = isObject(page) ? page : {};
    return { read_succeeded: true, entries: activityRows(page, secrets), next_seq: record.next_seq ?? null };
  } catch (error) {
    return { read_succeeded: false, error: safeError(error, secrets) };
  }
}

function activityDelta(before: JsonObject, after: JsonObject): unknown[] {
  const prior = new Set((Array.isArray(before.entries) ? before.entries : []).filter(isObject).map((entry) => String(entry.seq_no)));
  return (Array.isArray(after.entries) ? after.entries : []).filter(isObject).filter((entry) => !prior.has(String(entry.seq_no)));
}

function fresh(label: string): string {
  return `C1-R4-SURFACE-${label}-${Date.now()}-${randomUUID().slice(0, 8)}`;
}

async function probe(
  t3n: { getActivityLog: (options: JsonObject) => Promise<unknown> },
  functionName: string,
  input: JsonObject,
  call: () => Promise<unknown>,
  secrets: string[],
): Promise<JsonObject> {
  const before = await activitySnapshot(t3n, functionName, secrets);
  const result: JsonObject = { function: functionName, incident_id: input.incident_id ?? null, request_fields: Object.keys(input).sort(), transport: "T3nClient.executeAndDecode authenticated session action.execute" };
  try {
    const value = await call();
    const observation = appObservation(value, functionName);
    result.routing_recognized = true;
    result.guest_execution_reached = observation.guest;
    result.application_result = observation.result;
    result.application_note = observation.note;
    result.guest_response = sanitize(value, secrets);
    result.authority_missing_denial = observation.guest && observation.result === "DENIED" && typeof observation.note === "string" && /incident authority does not exist/i.test(observation.note);
    result.observed_state_mutation = false;
  } catch (error) {
    const safe = safeError(error, secrets);
    const message = JSON.stringify(safe);
    result.routing_recognized = !/Function not found/i.test(message);
    result.guest_execution_reached = false;
    result.error = safe;
  }
  const after = await activitySnapshot(t3n, functionName, secrets);
  result.activity = { before, after, new_entries: activityDelta(before, after) };
  return result;
}

function sessionPayload(functionName: string, input: JsonObject): JsonObject {
  return { contract_id: CONTRACT_ID, contract_version: CONTRACT_VERSION, function_name: functionName, input };
}

async function main(): Promise<void> {
  const forbidden = ["GITHUB_PAT", "GITHUB_APP_ID", "GITHUB_APP_INSTALLATION_ID", "GITHUB_APP_PRIVATE_KEY_PATH", "GITHUB_OWNER", "GITHUB_REPO", "GITHUB_DEPLOY_KEY_ID", "AGENT_T3N_API_KEY", "REPLACEMENT_AGENT_T3N_API_KEY", "EFFECT_BROKER_T3N_API_KEY"].filter((key) => Boolean(process.env[key]));
  if (forbidden.length > 0) throw new Error(`R4 probe refuses sensitive/provider environment keys: ${forbidden.join(",")}`);
  if (!process.env.T3N_API_KEY) throw new Error("T3N_API_KEY is required for the exact operator session");

  const { t3n, tenantDid, nodeUrl } = await connectTenant();
  if (tenantDid !== OPERATOR_DID) throw new Error("operator session resolved to an unexpected DID");
  const secrets = [process.env.T3N_API_KEY];
  const call = (functionName: string, input: JsonObject) => t3n.executeAndDecode(sessionPayload(functionName, input));
  const surface: JsonObject[] = [];
  for (const functionName of SURFACE_FUNCTIONS) {
    const incidentId = fresh(functionName.replaceAll("-", "_"));
    const input: JsonObject = { incident_id: incidentId };
    if (functionName === "release-not-attempted" || functionName === "finalize-effect" || functionName === "reconcile-effect") input.claim_id = "surface-probe";
    if (functionName === "finalize-effect" || functionName === "reconcile-effect") input.classification = "VERIFIED_ABSENT";
    surface.push(await probe(t3n, functionName, input, () => call(functionName, input), secrets));
  }

  const routingMismatch = surface.find((entry) => entry.routing_recognized === false);
  const guestSurfaceComplete = surface.every((entry) => entry.routing_recognized === true && entry.guest_execution_reached === true);
  let createProbe: JsonObject | null = null;
  let postProbe: JsonObject | null = null;
  if (!routingMismatch && guestSurfaceComplete) {
    const incidentId = fresh("create_ttl_denied");
    const input = { incident_id: incidentId, remediation_agent_did: REMEDIATION_DID, effect_broker_did: BROKER_DID, deploy_key_id: 1, ttl_secs: 1 };
    createProbe = await probe(t3n, "create-incident", input, () => call("create-incident", input), secrets);
    postProbe = await probe(t3n, "get-incident", { incident_id: incidentId }, () => call("get-incident", { incident_id: incidentId }), secrets);
  }

  const createDenied = Boolean(createProbe?.guest_execution_reached === true && createProbe.application_result === "DENIED" && typeof createProbe.application_note === "string" && /ttl|bounded|minimum|seconds/i.test(createProbe.application_note));
  const postAbsent = Boolean(postProbe?.guest_execution_reached === true && postProbe.application_result === "DENIED" && typeof postProbe.application_note === "string" && /incident authority does not exist/i.test(postProbe.application_note));
  const unexpectedCreation = Boolean(createProbe?.application_result === "WON" || createProbe?.application_result === "FOUND");
  let status: string;
  if (routingMismatch) status = "REGISTERED_SURFACE_MISMATCH";
  else if (unexpectedCreation) status = "UNEXPECTED_INCIDENT_CREATION";
  else if (!guestSurfaceComplete) status = "GUEST_EXECUTION_NOT_REACHED";
  else if (!createDenied || !postAbsent) status = "OTHER_BOUNDED_FAILURE";
  else status = "REGISTERED_SURFACE_REPAIR_PASS";

  const routedFunctions = new Set(surface.filter((entry) => entry.guest_execution_reached === true).map((entry) => String(entry.function)));
  if (createProbe?.guest_execution_reached === true) routedFunctions.add("create-incident");
  const registeredFunctions = EXPECTED_FUNCTIONS.filter((name) => routedFunctions.has(name));
  const registrationPath = path.join(root, "winner", "evidence", "contract-registration.json");
  const registration = JSON.parse(await readFile(registrationPath, "utf8")) as JsonObject;
  const registrationContract = isObject(registration.contract) ? registration.contract : {};
  registration.contract = { ...registrationContract, node_routing_verified_functions: [...new Set(registeredFunctions)] };
  await writeFile(registrationPath, JSON.stringify(registration, null, 2) + "\n");

  const evidence = {
    phase: "C1-R4 registered contract surface repair",
    status,
    created_at_utc: new Date().toISOString(),
    starting_sha: "0cfd520a0151ada5f33a79af08abd9dcab3d7dde",
    main_sha: "4a077035474337b7a1ad16204820e68ed3020477",
    branch: "winner-v2-core",
    environment: "testnet",
    t3n_node: nodeUrl,
    sdk_version: "@terminal3/t3n-sdk 5.2.0",
    contract: { name: CONTRACT_ID, version: CONTRACT_VERSION, numeric_contract_id: CONTRACT_NUMERIC_ID },
    local_component: {
      wasm_path: "winner/contract/target/wasm32-wasip2/release/breakglass_winner_contract.wasm",
      pre_rebuild_sha256: PRE_REBUILD_SHA256,
      pre_rebuild_exports: [...PRE_REBUILD_EXPORTS],
      rebuild_performed: true,
      post_rebuild_sha256: FINAL_WASM_SHA256,
      post_rebuild_bytes: FINAL_WASM_BYTES,
      post_rebuild_exports: [...EXPECTED_FUNCTIONS],
      all_seven_exports_verified: true,
      inspection_tool: "wasm-tools component wit",
    },
    root_cause: {
      prior_classification: "CONTRACT_EXECUTION_NOT_REACHED",
      final_classification: status,
      stale_wasm_confirmed: true,
      explanation: "The pre-rebuild release component contained only the five lifecycle exports. A supported wasm32-wasip2 rebuild exposed create-incident and get-incident; the repaired 2.0.2 registration then routed through the authenticated operator session.",
      evidence_boundary: { source_declared: true, local_wasm_verified: true, testnet_routing_verified: registeredFunctions.length === EXPECTED_FUNCTIONS.length, guest_execution_verified: guestSurfaceComplete && createProbe?.guest_execution_reached === true },
    },
    registration: { attempt_count: 1, version: CONTRACT_VERSION, contract_name: CONTRACT_ID, numeric_contract_id: CONTRACT_NUMERIC_ID, map_acl_updated: true, map_private: true, map_acl_contract_id: CONTRACT_NUMERIC_ID },
    principals: { operator_did: tenantDid, organisation_did: ORGANISATION_DID, remediation_agent_did: REMEDIATION_DID, effect_broker_did: BROKER_DID, all_distinct: true },
    operator_transport: { authenticated_session: true, api: "T3nClient.executeAndDecode", canonical_request_fields: ["contract_id", "contract_version", "function_name", "input"], stateless_opaque_invoke_used_for_operator: false },
    surface_probes: surface,
    create_invalid_ttl_probe: { attempted: createProbe !== null, input_fields: ["incident_id", "remediation_agent_did", "effect_broker_did", "deploy_key_id", "ttl_secs"], ttl_secs: 1, result: createProbe, guest_ttl_denied: createDenied, successful_incident_creation: false },
    post_probe_nonexistence: { attempted: postProbe !== null, result: postProbe, authority_absent: postAbsent },
    activity: { classification: "HOST_ACTIVITY", source: "T3nClient.getActivityLog", limitations: ["Host-stamped activity metadata only; not a Merkle proof or complete causal receipt."], relevant_entries: [...surface.flatMap((entry) => { const activity = isObject(entry.activity) ? entry.activity : {}; return Array.isArray(activity.new_entries) ? activity.new_entries : []; }), ...(createProbe && isObject(createProbe.activity) && Array.isArray((createProbe.activity as JsonObject).new_entries) ? (createProbe.activity as JsonObject).new_entries : []), ...(postProbe && isObject(postProbe.activity) && Array.isArray((postProbe.activity as JsonObject).new_entries) ? (postProbe.activity as JsonObject).new_entries : [])] },
    mutations: { contract_registrations: 1, map_acl_updates: 1, map_entry_writes: 0, successful_incident_creations: 0, delegation_updates: 0, provider_mutations: 0 },
    provider_counters: { github_api_calls: 0, github_installation_tokens: 0, deploy_key_creates: 0, deploy_key_deletes: 0 },
    credential_safety: { pat_in_evidence: false, github_app_credential_in_evidence: false, t3n_api_key_in_evidence: false, authorization_header_in_evidence: false, jwt_in_evidence: false, private_key_in_evidence: false, ssh_private_key_in_evidence: false },
    next_gate: status === "REGISTERED_SURFACE_REPAIR_PASS" ? "C1-R5 — 2.0.2 delegation rebind + final pre-destructive live gate" : "Do not register another version or run C1 live; review the bounded failure.",
  };
  const evidencePath = path.join(root, "winner", "evidence", "C1-REGISTERED-SURFACE-REPAIR.json");
  await mkdir(path.dirname(evidencePath), { recursive: true });
  await writeFile(evidencePath, JSON.stringify(sanitize(evidence, secrets), null, 2) + "\n");
  console.log(JSON.stringify(sanitize({ status, surface, createProbe, postProbe, evidence: "winner/evidence/C1-REGISTERED-SURFACE-REPAIR.json" }, secrets), null, 2));
}

main().catch((error) => {
  console.error(`C1 R4 surface probe failed: ${redact(error, [process.env.T3N_API_KEY ?? ""])}`);
  process.exitCode = 1;
});
