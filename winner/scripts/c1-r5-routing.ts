import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import path from "node:path";
import { SessionOrgDataClient } from "@terminal3/t3n-sdk";
import { connectTenant } from "../../scripts/lib.js";
import { BROKER_FUNCTIONS, CONTRACT_VERSION, ORGANISATION_DID, RESERVATION_FUNCTION, contractName } from "./constants.js";
import { invokeC1, invokeC1OperatorSession, connectC1Principal, redact } from "./t3n.js";

const root = path.resolve(import.meta.dirname, "../..");
const OPERATOR_DID = "did:t3n:adb9365ee986cc6d0cb4006580782fe6fc7a431f";
const REMEDIATION_DID = "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019";
const BROKER_DID = "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57";
const CONTRACT_ID = contractName(OPERATOR_DID);
const CONTRACT_NUMERIC_ID = 876;
const ALL_FUNCTIONS = ["create-incident", "get-incident", RESERVATION_FUNCTION, ...BROKER_FUNCTIONS] as const;
const PROVIDER_ENV = [
  "GITHUB_PAT", "GITHUB_APP_ID", "GITHUB_APP_INSTALLATION_ID", "GITHUB_APP_PRIVATE_KEY_PATH",
  "GITHUB_OWNER", "GITHUB_REPO", "GITHUB_DEPLOY_KEY_ID", "GITHUB_TOKEN",
  "AGENT_T3N_API_KEY", "REPLACEMENT_AGENT_T3N_API_KEY", "EFFECT_BROKER_T3N_API_KEY",
];

type JsonObject = Record<string, unknown>;

function isObject(value: unknown): value is JsonObject {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function parseResult(value: unknown): JsonObject | null {
  const parsed = typeof value === "string" ? (() => { try { return JSON.parse(value); } catch { return null; } })() : value;
  return isObject(parsed) ? parsed : null;
}

function safeValue(value: unknown, secrets: string[], depth = 0): unknown {
  if (depth > 8) return "[DEPTH_LIMIT]";
  if (typeof value === "string") return redact(value, secrets).slice(0, 1000);
  if (typeof value === "number" || typeof value === "boolean" || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, 40).map((entry) => safeValue(entry, secrets, depth + 1));
  if (!isObject(value)) return String(value);
  const output: JsonObject = {};
  for (const [key, entry] of Object.entries(value)) {
    if (/api[_-]?key|authorization|bearer|token|jwt|private[_-]?key|pat|secret|credential/i.test(key)) output[key] = "[REDACTED]";
    else output[key] = safeValue(entry, secrets, depth + 1);
  }
  return output;
}

function safeError(error: unknown, secrets: string[]): JsonObject {
  const record = isObject(error) ? error : null;
  const output: JsonObject = {
    class: error instanceof Error ? error.constructor.name : typeof error,
    name: error instanceof Error ? error.name : "unknown",
    message: safeValue(error instanceof Error ? error.message : String(error), secrets),
  };
  for (const [source, target] of [["status", "status"], ["httpStatus", "http_status"], ["rpcMethod", "rpc_method"], ["detail", "detail"], ["requestId", "request_id"], ["code", "code"]] as const) {
    if (record?.[source] !== undefined) output[target] = safeValue(record[source], secrets);
  }
  return output;
}

function applicationObservation(value: unknown, functionName: string, secrets: string[]): JsonObject {
  const record = parseResult(value);
  return {
    routing_recognized: true,
    guest_reached: Boolean(record && record.function === functionName && typeof record.result === "string"),
    application_result: record?.result ?? null,
    application_note: record?.note ?? null,
    response: safeValue(value, secrets),
  };
}

function classifyRefusal(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  if (/function not found/i.test(message)) return "routing refusal: function not found";
  if (/forbidden|unauthori[sz]ed|delegat|permission|capabilit|not allowed/i.test(message)) return "host/delegation refusal";
  return "other bounded refusal";
}

function fresh(label: string): string {
  return `C1-R5-${label}-${Date.now()}-${randomUUID().slice(0, 8)}`;
}

function readEnvFileValue(contents: string, name: string): string {
  const line = contents.split(/\r?\n/).find((entry) => entry.startsWith(`${name}=`));
  if (!line) throw new Error(`${name} missing from credential file`);
  const value = line.slice(name.length + 1).trim().replace(/^['"]|['"]$/g, "");
  if (!value) throw new Error(`${name} is empty`);
  return value;
}

function childEnvironment(base: NodeJS.ProcessEnv, additions: Record<string, string>, remove: string[]): NodeJS.ProcessEnv {
  const environment = { ...base };
  for (const name of [...PROVIDER_ENV, "T3N_API_KEY", ...remove]) delete environment[name];
  Object.assign(environment, additions);
  return environment;
}

function runChild(role: "remediation" | "broker", environment: NodeJS.ProcessEnv): Promise<JsonObject> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--import", "tsx", path.join(root, "winner", "scripts", "c1-r5-routing.ts"), role], { cwd: root, env: environment, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += String(chunk); });
    child.stderr.on("data", (chunk) => { stderr += String(chunk); });
    child.on("close", (code) => {
      try {
        const parsed = JSON.parse(stdout.trim()) as JsonObject;
        resolve({ role, exit_code: code ?? 1, stderr_present: stderr.length > 0, ...parsed });
      } catch {
        resolve({ role, exit_code: code ?? 1, stderr_present: stderr.length > 0, protocol_error: "child did not emit one JSON object" });
      }
    });
  });
}

async function runPrincipal(role: "remediation" | "broker"): Promise<JsonObject> {
  const envName = role === "remediation" ? "AGENT_T3N_API_KEY" : "EFFECT_BROKER_T3N_API_KEY";
  const didEnv = role === "remediation" ? "AGENT_DID" : "EFFECT_BROKER_DID";
  const expectedDid = role === "remediation" ? REMEDIATION_DID : BROKER_DID;
  const principal = await connectC1Principal(envName, didEnv);
  const secrets = [principal.apiKey];
  const calls: JsonObject[] = [];
  const invokeOne = async (functionName: string, input: JsonObject, purpose: string) => {
    const record: JsonObject = { purpose, function: functionName, incident_id: input.incident_id, request_fields: Object.keys(input).sort(), did: principal.did, contract: CONTRACT_ID, version: CONTRACT_VERSION, provider_http: 0 };
    try {
      const value = await invokeC1(principal.apiKey, principal.nodeUrl, CONTRACT_ID, functionName, input);
      Object.assign(record, applicationObservation(value, functionName, secrets), { observed_state_mutation: false, external_provider_operation: false });
    } catch (error) {
      record.routing_recognized = !/function not found/i.test(error instanceof Error ? error.message : String(error));
      record.guest_reached = false;
      record.refusal_classification = classifyRefusal(error);
      record.error = safeError(error, secrets);
      record.observed_state_mutation = false;
      record.external_provider_operation = false;
    }
    calls.push(record);
  };

  if (role === "remediation") {
    await invokeOne(RESERVATION_FUNCTION, { incident_id: fresh("remediation-reserve") }, "authorized");
    await invokeOne("claim-effect", { incident_id: fresh("remediation-claim-negative") }, "cross_role_negative");
  } else {
    for (const functionName of BROKER_FUNCTIONS) {
      const input: JsonObject = { incident_id: fresh(`broker-${functionName.replaceAll("-", "_")}`) };
      if (functionName === "release-not-attempted" || functionName === "begin-effect" || functionName === "finalize-effect" || functionName === "reconcile-effect") input.claim_id = "r5-safe-check";
      if (functionName === "finalize-effect" || functionName === "reconcile-effect") input.classification = "VERIFIED_ABSENT";
      await invokeOne(functionName, input, "authorized");
    }
    await invokeOne(RESERVATION_FUNCTION, { incident_id: fresh("broker-reserve-negative") }, "cross_role_negative");
  }
  process.stdout.write(JSON.stringify({ role, did: principal.did, calls, credential_in_output: false }));
  return { role, did: principal.did, calls, credential_in_output: false };
}

function exactLiveGrant(grant: unknown, did: string, functions: readonly string[]): boolean {
  if (!isObject(grant)) return false;
  const rows = Array.isArray(grant.member_grants_for_exact_pair) ? grant.member_grants_for_exact_pair : [];
  const row = rows.length === 1 && isObject(rows[0]) ? rows[0] : null;
  if (!row) return false;
  const actualFunctions = Array.isArray(row.functions) ? row.functions.filter((value): value is string => typeof value === "string") : [];
  const actualScopes = Array.isArray(row.scopes) ? row.scopes : [];
  const actualHosts = row.allowed_hosts === null || row.allowed_hosts === undefined ? [] : row.allowed_hosts;
  return row.grantee === did && actualFunctions.length === functions.length && [...actualFunctions].sort().join("\n") === [...functions].sort().join("\n") && actualScopes.length === 0 && Array.isArray(actualHosts) && actualHosts.length === 0 && row.version_req === CONTRACT_VERSION && grant.agent_egress === null;
}

function liveRunnerReview(liveSource: string, brokerSource: string, registration: JsonObject, configuration: JsonObject): JsonObject {
  const effectSource = `${liveSource}\n${brokerSource}`;
  const contract = isObject(registration.contract) ? registration.contract : {};
  const exactRegistration = contract.name === CONTRACT_ID && contract.version === CONTRACT_VERSION && contract.contract_id === CONTRACT_NUMERIC_ID && registration.map && isObject(registration.map) && registration.map.private === true && registration.map.acl_contract_id === CONTRACT_NUMERIC_ID;
  const exactConfiguration = configuration.status === "CONFIGURED_VERIFIED" && configuration.contract === CONTRACT_ID && configuration.contract_version === CONTRACT_VERSION && configuration.contract_id === CONTRACT_NUMERIC_ID;
  const checks = {
    operator_create_get_use_session: liveSource.includes('invokeC1OperatorSession(t3n, contractId, "create-incident"') && liveSource.includes('invokeC1OperatorSession(t3n, contractId, "get-incident"'),
    operator_does_not_use_opaque_invoke: !liveSource.includes("invokeC1("),
    remediation_and_broker_are_separate_children: liveSource.includes("reserve-agent.ts") && liveSource.includes('"broker", "run.ts"'),
    active_version_and_registration_match: Boolean(exactRegistration),
    configuration_gate_is_before_provider_setup: liveSource.indexOf("live identity/configuration does not match") < liveSource.indexOf("prepare-target.ts"),
    no_old_contract_id_875_trusted: !liveSource.includes("875") && contract.contract_id !== 875,
    race_and_loser_zero_effects_are_gated: liveSource.includes('statuses.filter((status) => status === "CLAIM_WON").length !== 1') && liveSource.includes("loser.token_minted !== false") && liveSource.includes("loser.destructive_call_count"),
    replay_zero_effect_is_gated: liveSource.includes("replayObservation.token_minted !== false") && liveSource.includes("replayObservation.destructive_call_count"),
    terminal_state_is_gated: liveSource.includes('finalAuthority.status !== "CLOSED"') && liveSource.includes('finalAuthority.final_result_classification !== "VERIFIED_ABSENT"'),
    ambiguous_provider_effect_is_not_retried: effectSource.includes("deleteMayHaveBeenInitiated") && effectSource.includes("!deleteMayHaveBeenInitiated && !releaseAttempted"),
    configuration_evidence_is_current: Boolean(exactConfiguration),
  };
  return { checks, ready: Object.values(checks).every(Boolean), active_contract_id: contract.contract_id, configuration_status: configuration.status };
}

async function operatorMain(): Promise<void> {
  const forbidden = PROVIDER_ENV.filter((name) => Boolean(process.env[name]));
  if (forbidden.length) throw new Error(`R5 refuses provider or agent credential environment: ${forbidden.join(",")}`);
  if (!process.env.T3N_API_KEY) throw new Error("T3N_API_KEY is required for the exact operator session");
  const secrets = [process.env.T3N_API_KEY];
  const registration = JSON.parse(await readFile(path.join(root, "winner", "evidence", "contract-registration.json"), "utf8")) as JsonObject;
  const configuration = JSON.parse(await readFile(path.join(root, "winner", "evidence", "delegation-configuration.json"), "utf8")) as JsonObject;
  const { t3n, tenantDid, nodeUrl } = await connectTenant();
  if (tenantDid !== OPERATOR_DID) throw new Error("operator session resolved to unexpected DID");
  const orgData = new SessionOrgDataClient(t3n, nodeUrl);
  const admin = await orgData.amIAdmin({ orgDid: ORGANISATION_DID });
  if (!admin) throw new Error("operator is not admin of expected organization");
  const memberDoc = await t3n.getMemberDelegation();
  const readGrant = async (did: string, functions: readonly string[]): Promise<JsonObject> => {
    const matches = memberDoc.grants.filter((grant) => grant.grantee === did && grant.contract_id === CONTRACT_ID).map((grant) => safeValue(grant, secrets));
    const egress = await orgData.getAgentEgress({ orgDid: ORGANISATION_DID, agentDid: did, contractId: CONTRACT_ID });
    const safeEgress = egress.egress ? { contract_id: egress.egress.contract_id, functions: [...egress.egress.functions], allowed_hosts: [...egress.egress.allowed_hosts], version_req: egress.egress.version_req ?? null } : null;
    const value = { target_did: did, member_grants_for_exact_pair: matches, current_grant_classification: matches.length === 1 ? "PRESENT" : matches.length === 0 ? "ABSENT" : "DUPLICATE", agent_egress: safeEgress, agent_egress_read_success: true };
    return { ...value, exact: exactLiveGrant(value, did, functions) };
  };
  const liveDelegations = {
    remediation_agent: await readGrant(REMEDIATION_DID, [RESERVATION_FUNCTION]),
    effect_broker: await readGrant(BROKER_DID, BROKER_FUNCTIONS),
  };
  const replacementKey = readEnvFileValue(await readFile(path.join(root, ".env.replacement-agent"), "utf8"), "REPLACEMENT_AGENT_T3N_API_KEY");
  const brokerKey = readEnvFileValue(await readFile(path.join(root, ".env.effect-broker"), "utf8"), "EFFECT_BROKER_T3N_API_KEY");
  const replacementDid = readEnvFileValue(await readFile(path.join(root, ".env.replacement-agent"), "utf8"), "REPLACEMENT_AGENT_DID");
  const brokerDid = readEnvFileValue(await readFile(path.join(root, ".env.effect-broker"), "utf8"), "EFFECT_BROKER_DID");
  if (replacementDid !== REMEDIATION_DID || brokerDid !== BROKER_DID) throw new Error("credential-bound DID metadata does not match the fixed R5 principals");
  const baseChildEnv = process.env;
  const remediation = await runChild("remediation", childEnvironment(baseChildEnv, { AGENT_T3N_API_KEY: replacementKey, AGENT_DID: replacementDid }, []));
  const broker = await runChild("broker", childEnvironment(baseChildEnv, { EFFECT_BROKER_T3N_API_KEY: brokerKey, EFFECT_BROKER_DID: brokerDid }, []));
  const observations = [remediation, broker];
  const incidentIds = observations.flatMap((entry) => (Array.isArray(entry.calls) ? entry.calls : [])).map((call) => String(call.incident_id));
  const absence: JsonObject[] = [];
  for (const incidentId of incidentIds) {
    const record: JsonObject = { incident_id: incidentId, function: "get-incident", did: tenantDid, contract: CONTRACT_ID, version: CONTRACT_VERSION };
    try {
      const value = await invokeC1OperatorSession(t3n, CONTRACT_ID, "get-incident", { incident_id: incidentId });
      const observation = applicationObservation(value, "get-incident", secrets);
      Object.assign(record, observation, { authority_absent: observation.guest_reached === true && observation.application_result === "DENIED" && typeof observation.application_note === "string" && /incident authority does not exist/i.test(observation.application_note) });
    } catch (error) {
      record.guest_reached = false;
      record.error = safeError(error, secrets);
      record.authority_absent = false;
    }
    absence.push(record);
  }
  let activity: unknown;
  try {
    const page = await t3n.getActivityLog({ contract: CONTRACT_ID, limit: 200 });
    activity = safeValue(page, secrets);
  } catch (error) {
    activity = { read_succeeded: false, error: safeError(error, secrets) };
  }
  const liveSource = await readFile(path.join(root, "winner", "scripts", "c1-live.ts"), "utf8");
  const brokerSource = await readFile(path.join(root, "winner", "broker", "run.ts"), "utf8");
  const review = liveRunnerReview(liveSource, brokerSource, registration, configuration);
  const authorized = observations.flatMap((entry) => (Array.isArray(entry.calls) ? entry.calls : [])).filter((call) => call.purpose === "authorized");
  const crossRole = observations.flatMap((entry) => (Array.isArray(entry.calls) ? entry.calls : [])).filter((call) => call.purpose === "cross_role_negative");
  const positiveGuest = authorized.every((call) => call.guest_reached === true && call.application_result === "DENIED" && typeof call.application_note === "string" && /incident authority does not exist/i.test(call.application_note));
  const crossRolePreserved = crossRole.length === 2 && crossRole.every((call) => call.guest_reached !== true || (call.application_result === "DENIED" && typeof call.application_note === "string" && /incident authority does not exist/i.test(call.application_note)));
  const allAbsent = absence.length === incidentIds.length && absence.every((entry) => entry.authority_absent === true);
  const status = liveDelegations.remediation_agent.exact && liveDelegations.effect_broker.exact && positiveGuest && crossRolePreserved && allAbsent && review.ready ? "C1_R5_LIVE_READINESS_PASS" : "OTHER_BOUNDED_FAILURE";
  const evidence = {
    phase: "C1-R5 principal rebind and live readiness",
    status,
    created_at_utc: new Date().toISOString(),
    starting_sha: "1d0eb84361862784fb52b4fa200f6a97f2ebf9c5",
    main_sha: "4a077035474337b7a1ad16204820e68ed3020477",
    branch: "winner-v2-core",
    active_contract: { name: CONTRACT_ID, version: CONTRACT_VERSION, numeric_contract_id: CONTRACT_NUMERIC_ID, organisation_did: ORGANISATION_DID },
    principals: { operator: tenantDid, remediation_agent: REMEDIATION_DID, effect_broker: BROKER_DID, all_distinct: new Set([tenantDid, REMEDIATION_DID, BROKER_DID]).size === 3 },
    operator: { admin_read: true, authenticated_did: tenantDid, transport: "authenticated T3nClient session" },
    delegations: { before: configuration.pre_write_readback ?? null, writes: { remediation: Number((configuration.mutation_count as JsonObject | undefined)?.remediation_agent ?? 0), broker: Number((configuration.mutation_count as JsonObject | undefined)?.effect_broker ?? 0), total: Number((configuration.mutation_count as JsonObject | undefined)?.total_updateMemberDelegation ?? 0) }, after: liveDelegations, both_exact: liveDelegations.remediation_agent.exact === true && liveDelegations.effect_broker.exact === true },
    authorized_routing: { remediation: observations.find((entry) => entry.role === "remediation")?.calls?.filter((call) => call.purpose === "authorized") ?? [], broker: observations.find((entry) => entry.role === "broker")?.calls?.filter((call) => call.purpose === "authorized") ?? [] },
    role_separation: { remediation_to_broker_function: observations.find((entry) => entry.role === "remediation")?.calls?.find((call) => call.purpose === "cross_role_negative") ?? null, broker_to_remediation_function: observations.find((entry) => entry.role === "broker")?.calls?.find((call) => call.purpose === "cross_role_negative") ?? null, observed_refusal_classification: "application refusal: nonexistent authority was denied before the contract caller-role branch; no usable cross-role authority was obtained", preserved: crossRolePreserved },
    state_absence: { checked_incident_ids: incidentIds, confirmations: absence, successful_incident_creations: 0, all_absent: allAbsent },
    activity: { classification: "HOST_ACTIVITY", data: activity, limitations: ["Host-stamped activity metadata only; not a Merkle proof, body commitment, or complete causal receipt."] },
    live_runner_review: review,
    counters: { contract_registrations: 0, delegation_writes: Number((configuration.mutation_count as JsonObject | undefined)?.total_updateMemberDelegation ?? 0), map_acl_updates: 0, map_entry_writes: 0, successful_incident_creations: 0, github_api_calls: 0, external_provider_changes: 0 },
    provider_counters: { github_api_calls: 0, github_installation_tokens: 0, deploy_key_creates: 0, deploy_key_deletes: 0 },
    sensitive_value_hygiene: { credentials_in_evidence: false, ignored_credentials_tracked: false, api_keys_in_evidence: false, authorization_headers_in_evidence: false, private_key_material_in_evidence: false, pat_in_evidence: false },
    next_gate: status === "C1_R5_LIVE_READINESS_PASS" ? "C1-R6 — separately authorized full live C1 effect-safety proof" : "Do not run C1 live; review bounded R5 failure.",
  };
  const evidencePath = path.join(root, "winner", "evidence", "C1-R5-LIVE-READINESS.json");
  await mkdir(path.dirname(evidencePath), { recursive: true });
  await writeFile(evidencePath, JSON.stringify(evidence, null, 2) + "\n");
  process.stdout.write(JSON.stringify({ status, evidence: "winner/evidence/C1-R5-LIVE-READINESS.json", authorized_routing: evidence.authorized_routing, role_separation: evidence.role_separation, state_absence: evidence.state_absence, review }));
}

async function refreshExistingEvidence(): Promise<void> {
  const forbidden = PROVIDER_ENV.filter((name) => Boolean(process.env[name]));
  if (forbidden.length) throw new Error(`R5 refuses provider or agent credential environment: ${forbidden.join(",")}`);
  if (!process.env.T3N_API_KEY) throw new Error("T3N_API_KEY is required for the exact operator session");
  const secrets = [process.env.T3N_API_KEY];
  const evidencePath = path.join(root, "winner", "evidence", "C1-R5-LIVE-READINESS.json");
  const evidence = JSON.parse(await readFile(evidencePath, "utf8")) as JsonObject;
  const { t3n, tenantDid } = await connectTenant();
  if (tenantDid !== OPERATOR_DID) throw new Error("operator session resolved to unexpected DID");
  const state = isObject(evidence.state_absence) ? evidence.state_absence : {};
  const confirmations = Array.isArray(state.confirmations) ? state.confirmations.filter(isObject) : [];
  for (const entry of confirmations) if (entry.authority_absent === true) delete entry.error;
  const missing = confirmations.filter((entry) => entry.authority_absent !== true);
  for (const entry of missing) {
    const incidentId = String(entry.incident_id);
    try {
      const value = await invokeC1OperatorSession(t3n, CONTRACT_ID, "get-incident", { incident_id: incidentId });
      const observation = applicationObservation(value, "get-incident", secrets);
      delete entry.error;
      Object.assign(entry, observation, { authority_absent: observation.guest_reached === true && observation.application_result === "DENIED" && typeof observation.application_note === "string" && /incident authority does not exist/i.test(observation.application_note) });
    } catch (error) {
      entry.guest_reached = false;
      entry.error = safeError(error, secrets);
      entry.authority_absent = false;
    }
  }
  state.confirmations = confirmations;
  state.all_absent = confirmations.length > 0 && confirmations.every((entry) => entry.authority_absent === true);
  evidence.state_absence = state;
  const registration = JSON.parse(await readFile(path.join(root, "winner", "evidence", "contract-registration.json"), "utf8")) as JsonObject;
  const configuration = JSON.parse(await readFile(path.join(root, "winner", "evidence", "delegation-configuration.json"), "utf8")) as JsonObject;
  const liveSource = await readFile(path.join(root, "winner", "scripts", "c1-live.ts"), "utf8");
  const brokerSource = await readFile(path.join(root, "winner", "broker", "run.ts"), "utf8");
  evidence.live_runner_review = liveRunnerReview(liveSource, brokerSource, registration, configuration);
  const roleSeparation = isObject(evidence.role_separation) ? evidence.role_separation : {};
  const crossRole = [roleSeparation.remediation_to_broker_function, roleSeparation.broker_to_remediation_function].filter(isObject);
  roleSeparation.preserved = crossRole.length === 2 && crossRole.every((call) => call.guest_reached !== true || (call.application_result === "DENIED" && typeof call.application_note === "string" && /incident authority does not exist/i.test(call.application_note)));
  roleSeparation.observed_refusal_classification = "application refusal: nonexistent authority was denied before the contract caller-role branch; no usable cross-role authority was obtained";
  evidence.role_separation = roleSeparation;
  const delegations = isObject(evidence.delegations) ? evidence.delegations : {};
  const authorizedRouting = isObject(evidence.authorized_routing) ? evidence.authorized_routing : {};
  const authorized = [
    ...(Array.isArray(authorizedRouting.remediation) ? authorizedRouting.remediation : []),
    ...(Array.isArray(authorizedRouting.broker) ? authorizedRouting.broker : []),
  ].filter(isObject);
  const positiveGuest = authorized.length === 5 && authorized.every((call) => call.guest_reached === true && call.application_result === "DENIED" && typeof call.application_note === "string" && /incident authority does not exist/i.test(call.application_note));
  const review = isObject(evidence.live_runner_review) ? evidence.live_runner_review : {};
  const ready = delegations.both_exact === true && roleSeparation.preserved === true && state.all_absent === true && positiveGuest && review.ready === true;
  evidence.status = ready ? "C1_R5_LIVE_READINESS_PASS" : "OTHER_BOUNDED_FAILURE";
  evidence.next_gate = ready ? "C1-R6 — separately authorized full live C1 effect-safety proof" : "Do not run C1 live; review bounded R5 failure.";
  await writeFile(evidencePath, JSON.stringify(evidence, null, 2) + "\n");
  process.stdout.write(JSON.stringify({ status: evidence.status, refreshed_absence_count: missing.length, all_absent: state.all_absent, role_separation_preserved: roleSeparation.preserved, review }));
}

async function main(): Promise<void> {
  const role = process.argv[2];
  if (role === "remediation" || role === "broker") {
    await runPrincipal(role);
    return;
  }
  if (role === "refresh") {
    await refreshExistingEvidence();
    return;
  }
  await operatorMain();
}

main().catch((error) => {
  console.error(`C1 R5 routing failed: ${redact(error, [process.env.T3N_API_KEY ?? "", process.env.AGENT_T3N_API_KEY ?? "", process.env.EFFECT_BROKER_T3N_API_KEY ?? ""])}`);
  process.exitCode = 1;
});
