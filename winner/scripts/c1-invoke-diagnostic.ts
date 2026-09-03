import { randomUUID } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { connectTenant } from "../../scripts/lib.js";
import { invokeC1, redact } from "./t3n.js";
import { CONTRACT_VERSION, contractName } from "./constants.js";

const root = path.resolve(import.meta.dirname, "../..");
const OPERATOR_DID = "did:t3n:adb9365ee986cc6d0cb4006580782fe6fc7a431f";
const ORGANISATION_DID = "did:t3n:3c63f09271c0d9184abbcccbfae28698a8f4a912";
const REMEDIATION_DID = "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019";
const BROKER_DID = "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57";
const CONTRACT_ID = contractName(OPERATOR_DID);
const EXPECTED_NUMERIC_CONTRACT_ID = 875;
const SDK_VERSION = "@terminal3/t3n-sdk 5.2.0";
const FORBIDDEN_ENVIRONMENT_KEYS = [
  "GITHUB_PAT",
  "GITHUB_APP_ID",
  "GITHUB_APP_INSTALLATION_ID",
  "GITHUB_APP_PRIVATE_KEY_PATH",
  "GITHUB_OWNER",
  "GITHUB_REPO",
  "GITHUB_DEPLOY_KEY_ID",
  "AGENT_T3N_API_KEY",
  "REPLACEMENT_AGENT_T3N_API_KEY",
  "EFFECT_BROKER_T3N_API_KEY",
];

type JsonObject = Record<string, unknown>;
type ProbeRecord = JsonObject & { guest_level_application_behavior_observed: boolean };

function isObject(value: unknown): value is JsonObject {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function secretSafeString(value: string, secrets: string[]): string {
  let result = value;
  for (const secret of secrets) if (secret) result = result.split(secret).join("[REDACTED]");
  return redact(result, secrets).slice(0, 1000);
}

function sanitize(value: unknown, secrets: string[], depth = 0): unknown {
  if (depth > 12) return "[DEPTH_LIMIT]";
  if (typeof value === "string") return secretSafeString(value, secrets);
  if (typeof value === "number" || typeof value === "boolean" || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, 50).map((entry) => sanitize(entry, secrets, depth + 1));
  if (!isObject(value)) return String(value);
  const output: JsonObject = {};
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry !== "boolean" && entry !== null && /^(api[_-]?key|authorization|bearer|access[_-]?token|installation[_-]?token|jwt|private[_-]?key|pat|secret|credential)$/i.test(key)) {
      output[key] = "[REDACTED]";
      continue;
    }
    output[key] = sanitize(entry, secrets, depth + 1);
  }
  return output;
}

function decoded(value: unknown): unknown {
  if (typeof value !== "string") return value;
  try { return JSON.parse(value); } catch { return value; }
}

function applicationObservation(value: unknown, functionName: string): { observed: boolean; result: unknown; note: unknown } {
  const parsed = decoded(value);
  const record = isObject(parsed) ? parsed : null;
  const hasContractShape = Boolean(record && record.function === functionName && typeof record.result === "string");
  return {
    observed: hasContractShape,
    result: record?.result ?? null,
    note: record?.note ?? null,
  };
}

function safeError(error: unknown, secrets: string[]): JsonObject {
  const record = isObject(error) ? error : null;
  const output: JsonObject = {
    class: error instanceof Error ? error.constructor.name : typeof error,
    name: error instanceof Error ? error.name : "unknown",
    message: secretSafeString(error instanceof Error ? error.message : String(error), secrets),
  };
  for (const [source, target] of [
    ["status", "status"],
    ["httpStatus", "http_status"],
    ["rpcMethod", "rpc_method"],
    ["code", "code"],
    ["detail", "detail"],
    ["requestId", "request_id"],
    ["request_id", "request_id"],
  ] as const) {
    const entry = record?.[source];
    if (entry !== undefined) output[target] = sanitize(entry, secrets);
  }
  return output;
}

function safeActivityEntry(value: unknown, secrets: string[]): unknown {
  if (!isObject(value)) return null;
  const row: JsonObject = {
    seq_no: value.seq_no,
    hash: value.hash,
    timestamp_ms: value.timestamp_ms,
    caller_type: value.caller_type,
    actor: value.actor,
    on_behalf_of: value.on_behalf_of,
    org: value.org,
    contract: value.contract,
    function: value.function,
    outcome: value.outcome,
  };
  if (Array.isArray(value.roles)) row.roles = value.roles;
  return sanitize(row, secrets);
}

async function activitySnapshot(t3n: { getActivityLog: (options: JsonObject) => Promise<unknown> }, functionName: string, secrets: string[]): Promise<JsonObject> {
  try {
    const page = await t3n.getActivityLog({ did: OPERATOR_DID, contract: CONTRACT_ID, function: functionName, limit: 100 });
    const record = isObject(page) ? page : {};
    const entries = Array.isArray(record.entries) ? record.entries.map((entry) => safeActivityEntry(entry, secrets)).filter(Boolean) : [];
    return { read_succeeded: true, entries, next_seq: record.next_seq ?? null };
  } catch (error) {
    return { read_succeeded: false, error: safeError(error, secrets) };
  }
}

async function runSdkProbe(
  label: string,
  transport: string,
  t3n: { getActivityLog: (options: JsonObject) => Promise<unknown> },
  functionName: string,
  input: JsonObject,
  call: () => Promise<unknown>,
  secrets: string[],
): Promise<ProbeRecord> {
  const before = await activitySnapshot(t3n, functionName, secrets);
  const record: ProbeRecord = {
    label,
    transport,
    function: functionName,
    incident_id: typeof input.incident_id === "string" ? input.incident_id : null,
    request_fields: Object.keys(input).sort(),
    guest_level_application_behavior_observed: false,
  };
  try {
    const value = await call();
    const observation = applicationObservation(value, functionName);
    record.success = true;
    record.result = sanitize(decoded(value), secrets);
    record.application_result = observation.result;
    record.application_note = observation.note;
    record.guest_level_application_behavior_observed = observation.observed;
  } catch (error) {
    record.success = false;
    record.error = safeError(error, secrets);
  }
  const after = await activitySnapshot(t3n, functionName, secrets);
  record.activity = {
    before,
    after,
    new_entries: activityDelta(before, after),
  };
  return record;
}

function activityDelta(before: JsonObject, after: JsonObject): unknown[] {
  const beforeEntries = new Set(
    (Array.isArray(before.entries) ? before.entries : [])
      .filter(isObject)
      .map((entry) => String(entry.seq_no)),
  );
  return (Array.isArray(after.entries) ? after.entries : [])
    .filter(isObject)
    .filter((entry) => !beforeEntries.has(String(entry.seq_no)));
}

async function rawInvoke(nodeUrl: string, apiKey: string, functionName: string, input: JsonObject): Promise<JsonObject> {
  const response = await fetch(`${nodeUrl}/api/invoke`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-T3N-Api-Key": apiKey },
    body: JSON.stringify({ contract_id: CONTRACT_ID, contract_version: CONTRACT_VERSION, function_name: functionName, input }),
    redirect: "error",
  });
  const raw = (await response.text()).slice(0, 1000);
  let body: unknown = raw;
  try { body = JSON.parse(raw); } catch { /* preserve a capped sanitized text body */ }
  return {
    http_status: response.status,
    ok: response.ok,
    response_code: isObject(body) ? body.code ?? null : null,
    detail: isObject(body) ? body.detail ?? null : null,
    request_id: isObject(body) ? body.request_id ?? null : null,
    body,
  };
}

async function runRawProbe(
  label: string,
  t3n: { getActivityLog: (options: JsonObject) => Promise<unknown> },
  nodeUrl: string,
  apiKey: string,
  functionName: string,
  input: JsonObject,
  secrets: string[],
): Promise<ProbeRecord> {
  const before = await activitySnapshot(t3n, functionName, secrets);
  const record: ProbeRecord = {
    label,
    transport: "direct POST /api/invoke with operator opaque key",
    function: functionName,
    incident_id: typeof input.incident_id === "string" ? input.incident_id : null,
    request_fields: Object.keys(input).sort(),
    guest_level_application_behavior_observed: false,
  };
  try {
    const result = await rawInvoke(nodeUrl, apiKey, functionName, input);
    const observation = applicationObservation(result.body, functionName);
    record.success = result.ok;
    record.http_status = result.http_status;
    record.response_code = sanitize(result.response_code, secrets);
    record.detail = sanitize(result.detail, secrets);
    record.request_id = sanitize(result.request_id, secrets);
    record.body = sanitize(result.body, secrets);
    record.application_result = observation.result;
    record.application_note = observation.note;
    record.guest_level_application_behavior_observed = observation.observed;
  } catch (error) {
    record.success = false;
    record.error = safeError(error, secrets);
  }
  const after = await activitySnapshot(t3n, functionName, secrets);
  record.activity = { before, after, new_entries: activityDelta(before, after) };
  return record;
}

function freshIncident(label: string): string {
  return `C1-INVOKE-DIAGNOSTIC-${label}-${Date.now()}-${randomUUID().slice(0, 8)}`;
}

function refusedEnvironmentKeys(): string[] {
  return FORBIDDEN_ENVIRONMENT_KEYS.filter((key) => Boolean(process.env[key]));
}

function sessionPayload(functionName: string, input: JsonObject): JsonObject {
  return { contract_id: CONTRACT_ID, contract_version: CONTRACT_VERSION, function_name: functionName, input };
}

async function main(): Promise<void> {
  const refused = refusedEnvironmentKeys();
  if (refused.length > 0) throw new Error(`diagnostic refuses sensitive/provider environment keys: ${refused.join(",")}`);
  if (!process.env.T3N_API_KEY) throw new Error("T3N_API_KEY is required for the exact operator boundary");

  const { t3n, did, nodeUrl } = await connectTenant();
  if (did !== OPERATOR_DID) throw new Error("operator credential resolved to an unexpected DID");
  if (new Set([OPERATOR_DID, REMEDIATION_DID, BROKER_DID]).size !== 3) throw new Error("C1 principals are not distinct");

  // connectTenant deliberately keeps the opaque key out of its return object;
  // this diagnostic may use the exact operator key only for the two stateless
  // comparisons, and never serialises it.
  const apiKey = process.env.T3N_API_KEY;
  if (!apiKey) throw new Error("T3N_API_KEY disappeared after operator authentication");
  const secrets = [apiKey];
  const helperIncident = freshIncident("helper-get");
  const helper = await runSdkProbe(
    "current-helper-get-incident",
    "top-level invokeC1 -> SDK invoke (opaque-key/stateless /api/invoke)",
    t3n,
    "get-incident",
    { incident_id: helperIncident },
    () => invokeC1(apiKey, nodeUrl, CONTRACT_ID, "get-incident", { incident_id: helperIncident }),
    secrets,
  );

  const sessionIncident = freshIncident("session-get");
  const sessionCall = (functionName: string, input: JsonObject) => t3n.executeAndDecode(sessionPayload(functionName, input));
  const session = await runSdkProbe(
    "authenticated-execute-get-incident",
    "T3nClient.executeAndDecode (authenticated session action.execute)",
    t3n,
    "get-incident",
    { incident_id: sessionIncident },
    () => sessionCall("get-incident", { incident_id: sessionIncident }),
    secrets,
  );

  let raw: ProbeRecord | null = null;
  if (!helper.guest_level_application_behavior_observed) {
    const rawIncident = freshIncident("raw-get");
    raw = await runRawProbe("raw-api-invoke-get-incident", t3n, nodeUrl, apiKey, "get-incident", { incident_id: rawIncident }, secrets);
  }

  const selected = session.guest_level_application_behavior_observed
    ? { name: "authenticated-execute", run: (label: string, fn: string, input: JsonObject) => runSdkProbe(label, "T3nClient.executeAndDecode (authenticated session action.execute)", t3n, fn, input, () => sessionCall(fn, input), secrets) }
    : raw?.guest_level_application_behavior_observed
      ? { name: "raw-api-invoke", run: (label: string, fn: string, input: JsonObject) => runRawProbe(label, t3n, nodeUrl, apiKey, fn, input, secrets) }
      : helper.guest_level_application_behavior_observed
        ? { name: "current-helper", run: (label: string, fn: string, input: JsonObject) => runSdkProbe(label, "top-level invokeC1 -> SDK invoke (opaque-key/stateless /api/invoke)", t3n, fn, input, () => invokeC1(apiKey, nodeUrl, CONTRACT_ID, fn, input), secrets) }
        : null;

  let createProbe: ProbeRecord | null = null;
  let postProbe: ProbeRecord | null = null;
  let selectedTransport: string | null = null;
  if (selected) {
    selectedTransport = selected.name;
    const createIncident = freshIncident("create-ttl-denied");
    createProbe = await selected.run("deliberate-create-ttl-below-minimum", "create-incident", {
      incident_id: createIncident,
      remediation_agent_did: REMEDIATION_DID,
      effect_broker_did: BROKER_DID,
      deploy_key_id: 2147483647,
      ttl_secs: 1,
    });
    postProbe = await selected.run("post-create-nonexistence-get", "get-incident", { incident_id: createIncident });
  }

  const createDeniedForTtl = Boolean(
    createProbe?.guest_level_application_behavior_observed &&
    createProbe.application_result === "DENIED" &&
    typeof createProbe.application_note === "string" &&
    /ttl|bounded|seconds|minimum/i.test(createProbe.application_note),
  );
  const postProbeAbsent = Boolean(
    postProbe?.guest_level_application_behavior_observed &&
    postProbe.application_result === "DENIED" &&
    typeof postProbe.application_note === "string" &&
    /does not exist/i.test(postProbe.application_note),
  );
  const allGetTransports = [helper, session, raw].filter(Boolean) as ProbeRecord[];
  const anyGetReached = allGetTransports.some((probe) => probe.guest_level_application_behavior_observed);
  const allGetReached = allGetTransports.filter((probe) => probe.label.includes("get-incident")).map((probe) => ({
    label: probe.label,
    guest_reached: probe.guest_level_application_behavior_observed,
    result: probe.application_result ?? null,
    note: probe.application_note ?? null,
  }));

  let classification: string;
  if (!helper.guest_level_application_behavior_observed && anyGetReached && createDeniedForTtl && postProbeAbsent) {
    classification = "TRANSPORT_MISMATCH_CONFIRMED";
  } else if (anyGetReached && !createDeniedForTtl) {
    classification = "CREATE_ABI_OR_REQUEST_ENCODING_FAILURE";
  } else if (!anyGetReached) {
    classification = "CONTRACT_EXECUTION_NOT_REACHED";
  } else {
    classification = "OTHER_BOUNDED_FAILURE — get-incident reached the guest, but the bounded TTL denial/nonexistence proof was incomplete";
  }

  const evidence = {
    phase: "C1 zero-mutation invocation diagnostic",
    created_at_utc: new Date().toISOString(),
    starting_branch: "winner-v2-core",
    starting_sha: "e5c486c2255960125af5f82b1a4e8ad1b5c513d7",
    main_sha: "4a077035474337b7a1ad16204820e68ed3020477",
    environment: "testnet",
    t3n_node: nodeUrl,
    sdk_version: SDK_VERSION,
    installed_sdk_findings: {
      package_files: ["node_modules/@terminal3/t3n-sdk/dist/index.d.ts", "node_modules/@terminal3/t3n-sdk/dist/index.js", "node_modules/@terminal3/t3n-sdk/dist/index.esm.js"],
      invoke: {
        type_source: "dist/index.d.ts lines 3965-3980, 4067-4085",
        semantics: "one stateless opaque-key invocation; decoded contract value on 2xx; InvokeError on non-2xx",
        request_fields: ["contract_id", "contract_version", "function_name", "input"],
        error_fields_preserved: ["status"],
        detail_code_request_id_preserved_by_thrown_error: false,
        implementation_source_note: "published JS is bundled/minified without a source map; public type/docs are the installed source evidence",
      },
      session_execute: {
        type_source: "dist/index.d.ts lines 2825-2831, 3007-3022, 3274-3291",
        semantics: "authenticated session action.execute; execute returns JSON text and executeAndDecode parses the contract value",
        request_fields: ["contract_id", "contract_version", "function_name", "input"],
        error_surface: ["RpcError.rpcMethod", "RpcError.httpStatus", "RpcError.detail", "RpcError.requestId"],
      },
      direct_project_comparison: "winner/scripts/broker-credit-preflight.ts uses a direct POST /api/invoke with Content-Type and X-T3N-Api-Key and the same canonical request field names",
    },
    contract: { name: CONTRACT_ID, version: CONTRACT_VERSION, numeric_id: EXPECTED_NUMERIC_CONTRACT_ID },
    principals: { operator_did: did, organisation_did: ORGANISATION_DID, remediation_agent_did: REMEDIATION_DID, effect_broker_did: BROKER_DID, all_distinct: true },
    diagnostics: { current_helper: helper, authenticated_execute: session, raw_api_invoke: raw, selected_transport_for_create: selectedTransport, deliberate_create_ttl_denied: createProbe, post_probe_nonexistence: postProbe, all_get_transports: allGetReached },
    deliberate_create_probe: {
      attempted: Boolean(createProbe),
      ttl_secs: 1,
      expected_guest_result: "DENIED for bounded TTL; no KV write",
      observed_ttl_denial: createDeniedForTtl,
      post_probe_confirmed_absent: postProbeAbsent,
    },
    native_tenant_control_plane_map_write_research: {
      no_call_made: true,
      entrySet_type_source: "dist/index.d.ts lines 5860-5874",
      entrySet_documented_semantics: "TenantMapsNamespace.entrySet writes a UTF-8 key/value through the tenant management map-entry-set surface and supports an optional tenantTarget for an org admin.",
      executeControl_type_source: "dist/index.d.ts lines 6035-6046",
      executeControl_documented_semantics: "TenantClient exposes a generic executeControl(functionName, input) method; the installed declaration does not expose a more specific map-entry-set input type.",
      conclusion: "T3N has an intentional tenant control-plane map-write surface in the SDK; this diagnostic did not use it. Whether it may seed a private map for this organization must be established by a separate reviewed control-plane experiment, not inferred from this read-only diagnostic.",
    },
    zero_provider_work: {
      github_api_calls: 0,
      deploy_key_creates: 0,
      deploy_key_deletes: 0,
      installation_tokens: 0,
      provider_mutations: 0,
      successful_incident_creations: 0,
      reservation_calls: 0,
      broker_race_calls: 0,
      replay_calls: 0,
    },
    c1_contract_invocation_attempts: [helper, session, raw, createProbe, postProbe].filter(Boolean).length,
    credentials_in_evidence: false,
    credential_safety: { pat: false, github_app_credential: false, authorization_header: false, t3n_api_key: false, provider_calls: false },
    final_root_cause_classification: classification,
  };

  const evidencePath = path.join(root, "winner", "evidence", "C1-INVOKE-DIAGNOSTIC.json");
  await mkdir(path.dirname(evidencePath), { recursive: true });
  await writeFile(evidencePath, JSON.stringify(sanitize(evidence, secrets), null, 2) + "\n");
  console.log(JSON.stringify(sanitize(evidence, secrets), null, 2));
}

main().catch((error) => {
  console.error(`C1 invocation diagnostic failed: ${redact(error, [process.env.T3N_API_KEY ?? ""])}`);
  process.exitCode = 1;
});
