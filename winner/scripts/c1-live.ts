import { createHash, randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import path from "node:path";
import { SessionOrgDataClient } from "@terminal3/t3n-sdk";
import { connectTenant, redactError } from "../../scripts/lib.js";
import { ACTION, BROKER_FUNCTIONS, CONTRACT_TAIL, CONTRACT_VERSION, GITHUB_OWNER, GITHUB_REPOSITORY, INCIDENT_MAP_TAIL, ORGANISATION_DID, RESERVATION_FUNCTION, contractName } from "./constants.js";
import { parseChildJson } from "./child-protocol.js";
import { invokeC1, invokeC1OperatorSession, requireValue, redact, connectC1Principal } from "./t3n.js";
import { readJsonFile, writeAtomicJson } from "./result-file.js";
import { verifyBundle } from "./c1-r6b-r4e-r1-evidence-verify.js";

const root = path.resolve(import.meta.dirname, "../..");
const OPERATOR_DID = "did:t3n:adb9365ee986cc6d0cb4006580782fe6fc7a431f";
const REMEDIATION_DID = "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019";
const BROKER_DID = "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57";
const CONTRACT_NUMERIC_ID = 878;
const WASM_BYTES = 227011;
const WASM_SHA256 = "ca7032b112b837b06e4334c10bca8820447f6ea1756b74db9bccd3181ad4d5d0";
const TARGET_ID = 162351194;
const TARGET_TITLE = "breakglass-r4e-disposable-20260904";
const HISTORICAL_TARGET_ID = 162181065;
const CONTRACT_ID = contractName(OPERATOR_DID);
const EVIDENCE_ROOT = path.join(root, "winner", "evidence");
const PACING_MS = 70_000;

type JsonObject = Record<string, any>;

let activeRunDirectory: string | null = null;
let activeIncidentId: string | null = null;
let activeEvidence: JsonObject | null = null;

function parseObject(value: unknown): JsonObject {
  const parsed = typeof value === "string" ? JSON.parse(value) : value;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Terminal 3 response was not an object");
  return parsed as JsonObject;
}

function valueFromEnvFile(contents: string, name: string): string {
  const line = contents.split(/\r?\n/).find((entry) => entry.startsWith(`${name}=`));
  if (!line) throw new Error(`${name} missing from environment file`);
  const value = line.slice(name.length + 1).trim().replace(/^['"]|['"]$/g, "");
  if (!value) throw new Error(`${name} is empty`);
  return value;
}

async function envFileValue(file: string, name: string): Promise<string> {
  return valueFromEnvFile(await readFile(path.join(root, file), "utf8"), name);
}

function childEnvironment(additions: Record<string, string>, remove: string[] = []): NodeJS.ProcessEnv {
  const env = { ...process.env };
  for (const key of remove) delete env[key];
  Object.assign(env, additions);
  return env;
}

function runChild(script: string, args: string[], env: NodeJS.ProcessEnv): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--import", "tsx", script, ...args], { cwd: root, env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += String(chunk); });
    child.stderr.on("data", (chunk) => { stderr += String(chunk); });
    child.on("close", (code) => resolve({ code: code ?? 1, stdout, stderr }));
  });
}

async function waitFor(file: string, timeoutMs = 120_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!existsSync(file)) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${path.basename(file)}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

function sanitize(value: unknown, secrets: string[] = [], seen = new WeakSet<object>()): unknown {
  if (value === null || value === undefined || typeof value === "boolean" || typeof value === "number") return value;
  if (typeof value === "string") return redact(value, secrets);
  if (typeof value !== "object") return String(value);
  if (seen.has(value)) return "[CIRCULAR]";
  seen.add(value);
  if (Array.isArray(value)) return value.map((entry) => sanitize(entry, secrets, seen));
  const output: JsonObject = {};
  for (const [key, entry] of Object.entries(value)) {
    const lower = key.toLowerCase();
    output[key] = lower === "token" || lower.endsWith("_token") || lower.includes("authorization") || lower.includes("api_key") || lower.includes("private_key") || lower.includes("jwt") || lower.includes("pem") || lower.includes("password") || lower === "pat" || lower.endsWith("_pat") ? "[REDACTED]" : sanitize(entry, secrets, seen);
  }
  return output;
}

function relative(file: string): string { return path.relative(root, file).replaceAll("\\", "/"); }

function requireResponse(value: unknown, functionName: string, result?: string): JsonObject {
  const response = parseObject(value);
  if (response.function !== functionName) throw new Error(`${functionName} returned an unexpected function label`);
  if (result !== undefined && response.result !== result) throw new Error(`${functionName} expected ${result}, got ${String(response.result)}`);
  return response;
}

function exactGrant(value: unknown, did: string, functions: string[]): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const grant = value as JsonObject;
  const actual = Array.isArray(grant.functions) ? [...grant.functions].sort() : [];
  return grant.grantee === did && grant.contract_id === CONTRACT_ID && JSON.stringify(actual) === JSON.stringify([...functions].sort()) && (grant.scopes === undefined || grant.scopes === null || (Array.isArray(grant.scopes) && grant.scopes.length === 0)) && (grant.allowed_hosts === undefined || grant.allowed_hosts === null || (Array.isArray(grant.allowed_hosts) && grant.allowed_hosts.length === 0)) && grant.version_req === CONTRACT_VERSION;
}

async function persist(file: string, value: unknown): Promise<JsonObject> {
  await writeAtomicJson(file, value);
  return readJsonFile<JsonObject>(file);
}

async function routeProbe(apiKey: string, nodeUrl: string, functionName: string, input: JsonObject): Promise<JsonObject> {
  const response = requireResponse(await invokeC1(apiKey, nodeUrl, CONTRACT_ID, functionName, input), functionName, "DENIED");
  if (response.note !== "incident authority does not exist") throw new Error(`${functionName} routing probe did not return the expected harmless application denial`);
  return { function: functionName, request: input, response, routing_recognized: true, state_mutation: false, provider_action: false };
}

async function captureReadiness(t3n: Awaited<ReturnType<typeof connectTenant>>["t3n"], operatorKey: string, probeDir: string): Promise<JsonObject> {
  const incidentId = `C1-R6B-R4E-R1-READINESS-${Date.now()}-${randomBytes(6).toString("hex")}`;
  const context = await persist(path.join(probeDir, "00-readiness-context.json"), { function: "get-incident", incident_id: incidentId, request_sent: false, provider_counters: { github_api_calls: 0, installation_tokens: 0, deploy_key_creates: 0, deploy_key_deletes: 0, provider_mutations: 0 }, persisted_before_classification: true });
  let result: JsonObject;
  try {
    const response = await invokeC1OperatorSession(t3n, CONTRACT_ID, "get-incident", { incident_id: incidentId });
    result = { function: "get-incident", incident_id: incidentId, outcome_kind: "RETURNED_RESPONSE", request_sent: true, sanitized_response: sanitize(response, [operatorKey]) };
  } catch (error) {
    result = { function: "get-incident", incident_id: incidentId, outcome_kind: "THROWN_ERROR", request_sent: true, sanitized_error_message: redactError(error, [operatorKey]) };
  }
  const resultFile = await persist(path.join(probeDir, "01-readiness-result.json"), result);
  const response = resultFile.sanitized_response as JsonObject | undefined;
  if (resultFile.outcome_kind !== "RETURNED_RESPONSE" || response?.function !== "get-incident" || response.result !== "DENIED" || response.note !== "incident authority does not exist") throw new Error("readiness did not prove a normal nonexistent-incident denial");
  if (/fuel_per_minute|quota|credit[_ -]?exhausted|insufficient[_ -]?credit/i.test(JSON.stringify(resultFile))) throw new Error("readiness exposed an explicit quota or credit failure");
  return { context, result: resultFile, classification: "R4E_R1_READINESS_PASS", result_file: relative(path.join(probeDir, "01-readiness-result.json")) };
}

function safeProviderActivity(value: unknown): JsonObject {
  const rows = Array.isArray(value) ? value : value && typeof value === "object" && Array.isArray((value as JsonObject).entries) ? (value as JsonObject).entries : [];
  return { classification: "HOST_ACTIVITY_SUPPORTING_METADATA", entries: rows.map((entry: unknown) => { const row = entry && typeof entry === "object" && !Array.isArray(entry) ? entry as JsonObject : {}; const safe: JsonObject = {}; for (const key of ["seq_no", "sequence", "hash", "timestamp_ms", "timestamp", "actor", "caller", "on_behalf_of", "org", "contract", "function", "function_name", "outcome", "result"]) if (row[key] !== undefined) safe[key] = row[key]; return safe; }) };
}

async function sleepPacing(): Promise<void> { await new Promise((resolve) => setTimeout(resolve, PACING_MS)); }

async function main(): Promise<void> {
  if (process.env.GITHUB_PAT) throw new Error("C1 live runner refuses a GitHub PAT");
  if (process.env.C1_OPERATOR_DID && process.env.C1_OPERATOR_DID !== OPERATOR_DID) throw new Error("operator DID override mismatch");
  if (new Set([OPERATOR_DID, REMEDIATION_DID, BROKER_DID]).size !== 3) throw new Error("C1 principals are not three distinct DIDs");

  const operatorKey = requireValue("T3N_API_KEY");
  const remediationKey = await envFileValue(".env.replacement-agent", "REPLACEMENT_AGENT_T3N_API_KEY");
  const brokerKey = await envFileValue(".env.effect-broker", "EFFECT_BROKER_T3N_API_KEY");
  const remediationDid = await envFileValue(".env.replacement-agent", "REPLACEMENT_AGENT_DID");
  const brokerDid = await envFileValue(".env.effect-broker", "EFFECT_BROKER_DID");
  if (remediationDid !== REMEDIATION_DID || brokerDid !== BROKER_DID) throw new Error("credential-bound DID metadata does not match fixed C1 principals");

  const { t3n, tenant, tenantDid, nodeUrl } = await connectTenant();
  if (tenantDid !== OPERATOR_DID) throw new Error("authenticated operator DID mismatch");
  const inventory = (await tenant.contracts.listDetailed()).contracts.find((item) => item.name === CONTRACT_ID && item.version === CONTRACT_VERSION);
  const mapStatus = await tenant.maps.getStatus(INCIDENT_MAP_TAIL);
  if (!inventory || inventory.status !== "active" || mapStatus !== "active") throw new Error("2.0.4 contract or winner-incidents map is not active");
  const orgData = new SessionOrgDataClient(t3n, nodeUrl);
  if (!(await orgData.amIAdmin({ orgDid: ORGANISATION_DID }))) throw new Error("operator is not admin of the expected organization");
  const delegationDocument = await t3n.getMemberDelegation();
  const remediationGrant = delegationDocument.grants.find((grant) => grant.grantee === REMEDIATION_DID && grant.contract_id === CONTRACT_ID);
  const brokerGrant = delegationDocument.grants.find((grant) => grant.grantee === BROKER_DID && grant.contract_id === CONTRACT_ID);
  const remEgress = await orgData.getAgentEgress({ orgDid: ORGANISATION_DID, agentDid: REMEDIATION_DID, contractId: CONTRACT_ID });
  const brokerEgress = await orgData.getAgentEgress({ orgDid: ORGANISATION_DID, agentDid: BROKER_DID, contractId: CONTRACT_ID });
  if (!exactGrant(remediationGrant, REMEDIATION_DID, [RESERVATION_FUNCTION]) || !exactGrant(brokerGrant, BROKER_DID, [...BROKER_FUNCTIONS]) || remEgress.egress || brokerEgress.egress) throw new Error("live identity/configuration does not match the frozen C1 delegation");

  const routeDirectory = path.join(EVIDENCE_ROOT, `C1-R6B-R4E-R1-routing-${Date.now()}-${randomBytes(4).toString("hex")}`);
  await mkdir(routeDirectory, { recursive: true });
  const routeFinalize = await routeProbe(brokerKey, nodeUrl, "finalize-effect", { incident_id: `C1-R6B-R4E-R1-NONEXISTENT-F-${randomBytes(8).toString("hex")}`, claim_id: "claim-1-00000000000000000000000000000000", effect_start_id: "start-1-00000000000000000000000000000000", classification: "VERIFIED_ABSENT" });
  const routeReconcile = await routeProbe(brokerKey, nodeUrl, "reconcile-effect", { incident_id: `C1-R6B-R4E-R1-NONEXISTENT-R-${randomBytes(8).toString("hex")}`, claim_id: "claim-1-00000000000000000000000000000000", effect_start_id: "start-1-00000000000000000000000000000000", classification: "VERIFIED_ABSENT" });
  await persist(path.join(routeDirectory, "finalize-effect-routing.json"), routeFinalize);
  await persist(path.join(routeDirectory, "reconcile-effect-routing.json"), routeReconcile);
  const canonicalRegistrationFile = path.join(EVIDENCE_ROOT, "contract-registration.json");
  const canonicalRegistration = JSON.parse(await readFile(canonicalRegistrationFile, "utf8")) as JsonObject;
  canonicalRegistration.contract.node_routing_verified_functions = ["create-incident", "get-incident", RESERVATION_FUNCTION, ...BROKER_FUNCTIONS];
  canonicalRegistration.contract.node_routing_unverified_functions = [];
  canonicalRegistration.contract.node_routing_observed_via = "R4E-R1 harmless nonexistent-incident probes for finalize-effect and reconcile-effect";
  canonicalRegistration.contract.node_routing_observed_at_utc = new Date().toISOString();
  await writeAtomicJson(canonicalRegistrationFile, canonicalRegistration);

  const readinessDirectory = path.join(EVIDENCE_ROOT, `C1-R6B-R4E-R1-readiness-${Date.now()}-${randomBytes(4).toString("hex")}`);
  await mkdir(readinessDirectory, { recursive: true });
  const readiness = await captureReadiness(t3n, operatorKey, readinessDirectory);
  await sleepPacing();

  const runId = `C1-R6B-R4E-R1-${Date.now()}-${randomBytes(8).toString("hex")}`;
  const runDirectory = path.join(EVIDENCE_ROOT, runId);
  const incidentId = `${runId}-INCIDENT`;
  activeRunDirectory = runDirectory;
  activeIncidentId = incidentId;
  await mkdir(runDirectory, { recursive: true });
  const evidence: JsonObject = {
    kind: "C1_R6B_R4E_R1_PROVIDER_BUNDLE",
    status: "IN_PROGRESS",
    run_id: runId,
    incident_id: null,
    starting_sha: "390acdf6d6aaeaaa145a68deb102e453be040fd5",
    main_sha: "4a077035474337b7a1ad16204820e68ed3020477",
    contract: { name: CONTRACT_ID, version: CONTRACT_VERSION, numeric_id: CONTRACT_NUMERIC_ID, wasm_bytes: WASM_BYTES, wasm_sha256: WASM_SHA256, status: inventory.status },
    principals: { operator: OPERATOR_DID, remediation_agent: REMEDIATION_DID, effect_broker: BROKER_DID, organization: ORGANISATION_DID, all_distinct: true },
    configuration: { map: { name: `z:${OPERATOR_DID.slice("did:t3n:".length)}:${INCIDENT_MAP_TAIL}`, status: mapStatus, private: true, acl_basis: CONTRACT_NUMERIC_ID }, delegations: { remediation: { did: REMEDIATION_DID, functions: [RESERVATION_FUNCTION], scopes: [], allowed_hosts: [], version_req: CONTRACT_VERSION }, broker: { did: BROKER_DID, functions: [...BROKER_FUNCTIONS], scopes: [], allowed_hosts: [], version_req: CONTRACT_VERSION } } },
    incident_count: 1,
    readiness,
    routing: { finalize: routeFinalize, reconcile: routeReconcile, all_ten_verified: true },
    target: { id: TARGET_ID, title: TARGET_TITLE, read_only: true, repository: `${GITHUB_OWNER}/${GITHUB_REPOSITORY}`, historical_target_forbidden: HISTORICAL_TARGET_ID },
    provider_counters: { preflight_token_mints: 0, effect_token_mints: 0, verifier_token_mints: 0, deploy_key_posts: 0, deploy_key_deletes: 0, provider_mutations: 0 },
    credentials_in_evidence: false,
  };
  activeEvidence = evidence;
  await persist(path.join(runDirectory, "00-run-context.json"), { phase: "C1-R6B-R4E-R1 existing fresh target provider-backed execution", run_id: runId, starting_sha: evidence.starting_sha, main_sha: evidence.main_sha, contract: evidence.contract, principals: evidence.principals, repository: `${GITHUB_OWNER}/${GITHUB_REPOSITORY}`, expected_target_id: TARGET_ID, expected_target_title: TARGET_TITLE, expected_read_only: true, historical_target_forbidden: HISTORICAL_TARGET_ID, provider_counters: evidence.provider_counters, incident_id: null, persisted_before_provider_preflight: true });

  const appFile = await readFile(path.join(root, ".env.c0r-github-app"), "utf8");
  const appEnvironment: Record<string, string> = {};
  for (const name of ["GITHUB_APP_ID", "GITHUB_APP_INSTALLATION_ID", "GITHUB_APP_PRIVATE_KEY_PATH"]) appEnvironment[name] = valueFromEnvFile(appFile, name);
  const inheritedProviderKeys = Object.keys(process.env).filter((key) => key.startsWith("GITHUB_"));
  const targetEvidenceFile = path.join(runDirectory, "01-target-preflight.json");
  const targetChild = await runChild(path.join(root, "winner", "broker", "prepare-target.ts"), [], childEnvironment({ ...appEnvironment, C1_TARGET_MODE: "existing", C1_EXISTING_TARGET_ID: String(TARGET_ID), C1_EXISTING_TARGET_TITLE: TARGET_TITLE, C1_TARGET_EVIDENCE_FILE: targetEvidenceFile }, ["T3N_API_KEY", "AGENT_T3N_API_KEY", "EFFECT_BROKER_T3N_API_KEY", "GITHUB_PAT", ...inheritedProviderKeys]));
  if (targetChild.code !== 0) throw new Error(`target setup failed: ${redact(targetChild.stderr, [brokerKey])}`);
  const targetSetup = parseChildJson(targetChild.stdout);
  const target = targetSetup.target as JsonObject;
  if (Number(target?.id) !== TARGET_ID || target?.title !== TARGET_TITLE || target?.read_only !== true || target?.repository !== `${GITHUB_OWNER}/${GITHUB_REPOSITORY}` || targetSetup.mode !== "existing" || (targetSetup.provider_mutations as JsonObject)?.deploy_key_create_count !== 0) throw new Error("existing target preflight did not prove the exact frozen target without POST");
  evidence.target_preflight = targetSetup;
  evidence.provider_counters.preflight_token_mints = 1;
  await persist(targetEvidenceFile, targetSetup);

  evidence.incident_id = incidentId;
  const verifiedTargetId = Number(target.id);
  const create = requireResponse(await invokeC1OperatorSession(t3n, CONTRACT_ID, "create-incident", { incident_id: incidentId, remediation_agent_did: REMEDIATION_DID, effect_broker_did: BROKER_DID, deploy_key_id: verifiedTargetId, ttl_secs: 900 }), "create-incident", "WON");
  if (create.detail?.action !== ACTION || create.detail?.github_owner !== GITHUB_OWNER || create.detail?.github_repo !== GITHUB_REPOSITORY || create.detail?.deploy_key_id !== TARGET_ID || create.detail?.effect_attempts !== 0 || create.state !== "ACTIVE") throw new Error("incident authority did not bind the exact preflight target");
  const active = requireResponse(await invokeC1OperatorSession(t3n, CONTRACT_ID, "get-incident", { incident_id: incidentId }), "get-incident", "FOUND");
  if (active.state !== "ACTIVE" || active.detail?.deploy_key_id !== TARGET_ID || active.detail?.effect_attempts !== 0) throw new Error("ACTIVE readback mismatch");
  evidence.incident = { create, active_readback: active, target_fields_supplied_to_create_from_frozen_preflight: true };
  await persist(path.join(runDirectory, "02-create.json"), create);
  await persist(path.join(runDirectory, "03-active-readback.json"), active);

  const reserveEnv = childEnvironment({ AGENT_T3N_API_KEY: remediationKey, AGENT_DID: REMEDIATION_DID, C1_OPERATOR_DID: OPERATOR_DID, C1_INCIDENT_ID: incidentId }, ["T3N_API_KEY", "EFFECT_BROKER_T3N_API_KEY", "GITHUB_PAT"]);
  const reserveChild = await runChild(path.join(root, "winner", "scripts", "reserve-agent.ts"), [], reserveEnv);
  if (reserveChild.code !== 0) throw new Error(`reserve failed: ${reserveChild.stderr.slice(0, 500)}`);
  const reserveResult = parseChildJson(reserveChild.stdout);
  const reserve = requireResponse(reserveResult.result, RESERVATION_FUNCTION, "WON");
  if (reserve.state !== "RESERVED") throw new Error("reservation did not reach RESERVED");
  evidence.reservation = { response: reserve, provider_mutations: 0, target_fields_supplied: false };
  await persist(path.join(runDirectory, "04-reservation.json"), reserveResult);
  const reserved = requireResponse(await invokeC1OperatorSession(t3n, CONTRACT_ID, "get-incident", { incident_id: incidentId }), "get-incident", "FOUND");
  if (reserved.state !== "RESERVED" || reserved.detail?.effect_attempts !== 0) throw new Error("RESERVED readback mismatch");
  evidence.reservation.readback = reserved;
  await persist(path.join(runDirectory, "05-reserved-readback.json"), reserved);

  const barrier = path.join(runDirectory, "claim-release.json");
  const proposalsComplete = path.join(runDirectory, "claim-proposals-complete.json");
  const effectStartReady = path.join(runDirectory, "effect-start-ready.json");
  const preDeleteRelease = path.join(runDirectory, "pre-delete-release.json");
  const brokerBase = childEnvironment({ EFFECT_BROKER_T3N_API_KEY: brokerKey, EFFECT_BROKER_DID: BROKER_DID, C1_BARRIER_FILE: barrier, C1_PROPOSALS_COMPLETE_FILE: proposalsComplete, C1_OPERATOR_DID: OPERATOR_DID, C1_EXPECTED_CLAIM_VERSION: "0", C1_EXPECTED_TARGET_TITLE: TARGET_TITLE, C1_EFFECT_START_READY_FILE: effectStartReady, C1_PRE_DELETE_RELEASE_FILE: preDeleteRelease, ...appEnvironment }, ["T3N_API_KEY", "AGENT_T3N_API_KEY", "GITHUB_PAT", ...inheritedProviderKeys]);
  const brokerAResultFile = path.join(runDirectory, "broker-a.result.json");
  const brokerBResultFile = path.join(runDirectory, "broker-b.result.json");
  const brokerAReadyFile = path.join(runDirectory, "broker-a.ready.json");
  const brokerBReadyFile = path.join(runDirectory, "broker-b.ready.json");
  const aPromise = runChild(path.join(root, "winner", "broker", "run.ts"), [incidentId], { ...brokerBase, C1_READY_FILE: brokerAReadyFile, C1_RESULT_FILE: brokerAResultFile, C1_CONTENDER_ID: "broker-a" });
  const bPromise = runChild(path.join(root, "winner", "broker", "run.ts"), [incidentId], { ...brokerBase, C1_READY_FILE: brokerBReadyFile, C1_RESULT_FILE: brokerBResultFile, C1_CONTENDER_ID: "broker-b" });
  await Promise.all([waitFor(brokerAReadyFile), waitFor(brokerBReadyFile)]);
  const readyA = await readJsonFile<JsonObject>(brokerAReadyFile);
  const readyB = await readJsonFile<JsonObject>(brokerBReadyFile);
  const readyDocs = [readyA, readyB];
  const pids = readyDocs.map((doc) => doc.process_id);
  const nonces = readyDocs.map((doc) => doc.contender_nonce);
  if (!readyDocs.every((doc, index) => doc.incident_id === incidentId && doc.broker_did === BROKER_DID && doc.contender === `broker-${index === 0 ? "a" : "b"}` && typeof doc.contender_nonce === "string" && /^[0-9a-f]{32}$/.test(doc.contender_nonce) && Number.isSafeInteger(doc.process_id) && doc.process_id > 0 && Number.isSafeInteger(doc.ready_at_unix_ms) && doc.ready_at_unix_ms > 0) || new Set(pids).size !== 2 || new Set(nonces).size !== 2) {
    await writeFile(barrier, JSON.stringify({ abort: true, reason: "invalid_or_duplicate_contender_identity", incident_id: incidentId }));
    await Promise.all([aPromise, bPromise]);
    throw new Error("broker identity barrier failed before claim calls");
  }
  evidence.broker_race = { contenders: readyDocs, distinct_pids: true, distinct_nonces: true, claim_release_once: true };
  await writeAtomicJson(barrier, { incident_id: incidentId, released_once: true, released_at_unix_ms: Date.now() });
  await Promise.all([waitFor(brokerAResultFile), waitFor(brokerBResultFile)]);
  await writeAtomicJson(proposalsComplete, { incident_id: incidentId, phase: "claim proposals complete", both_results_persisted: true, confirmation_allowed_after_marker: true, completed_at_unix_ms: Date.now() });
  const effectReadyDeadline = Date.now() + 120_000;
  while (!existsSync(effectStartReady) && Date.now() < effectReadyDeadline) await new Promise((resolve) => setTimeout(resolve, 10));
  if (!existsSync(effectStartReady)) throw new Error("confirmed winner did not reach pre-delete effect-start gate");
  const effectReady = await readJsonFile<JsonObject>(effectStartReady);
  const preDelete = requireResponse(await invokeC1OperatorSession(t3n, CONTRACT_ID, "get-incident", { incident_id: incidentId }), "get-incident", "FOUND");
  if (preDelete.state !== "EFFECT_STARTED" || preDelete.detail?.effect_attempts !== 1 || preDelete.detail?.effect_start_id !== effectReady.effect_start_id || preDelete.detail?.final_result_classification !== null) throw new Error("pre-DELETE T3N authority is not confirmed EFFECT_STARTED");
  evidence.claim_proposals_complete = await readJsonFile<JsonObject>(proposalsComplete);
  evidence.pre_delete_authority = { effect_ready: effectReady, operator_readback: preDelete, delete_allowed_after_this_read: true };
  await persist(path.join(runDirectory, "06-claim-proposals-complete.json"), evidence.claim_proposals_complete);
  await persist(path.join(runDirectory, "07-pre-delete-authority.json"), evidence.pre_delete_authority);
  await writeAtomicJson(preDeleteRelease, { incident_id: incidentId, released_once: true, operator_authority_verified: true, released_at_unix_ms: Date.now() });

  const [a, b] = await Promise.all([aPromise, bPromise]);
  const brokers = [await readJsonFile<JsonObject>(brokerAResultFile), await readJsonFile<JsonObject>(brokerBResultFile)];
  if (a.code !== 0 || b.code !== 0) throw new Error(`broker child failed after durable result capture: ${a.stderr.slice(0, 500)} ${b.stderr.slice(0, 500)}`);
  const winner = brokers.find((item) => item.ownership_confirmation === "CONFIRMED");
  const loser = brokers.find((item) => item.ownership_confirmation === "NOT_OWNER");
  if (!winner || !loser || brokers.filter((item) => item.ownership_confirmation === "CONFIRMED").length !== 1 || brokers.filter((item) => item.ownership_confirmation === "NOT_OWNER").length !== 1) throw new Error("claim confirmation did not produce exactly one owner");
  if (loser.token_minted !== false || loser.provider_credential_mint_count !== 0 || loser.destructive_call_count !== 0 || loser.delete_attempted !== false || loser.provider_calls_after_ownership_loss !== 0 || Object.keys(loser).some((key) => ["installation_validation", "effect_token", "effect_token_scope", "before", "delete", "after", "verifier_token"].includes(key))) throw new Error("loser crossed the provider hard boundary");
  evidence.brokers = { broker_a: brokers[0], broker_b: brokers[1], winner: winner.contender, loser: loser.contender, claim_proposals_complete: true, confirmed_owner_count: 1 };
  evidence.provider_counters.effect_token_mints = winner.provider_credential_mint_count;
  evidence.provider_counters.verifier_token_mints = winner.verifier_token?.issued === true ? 1 : 0;
  evidence.provider_counters.deploy_key_deletes = winner.destructive_call_count;
  evidence.provider_counters.provider_mutations = winner.destructive_call_count;
  evidence.protocol_order = ["provider_before", "begin-effect", "confirm-effect-start", "pre-delete-authority", "DELETE", "provider_after", "effect_token_revoke", "verifier_issue", "verifier_after", "verifier_revoke", "finalize-effect"];
  await persist(path.join(runDirectory, "08-broker-a.json"), brokers[0]);
  await persist(path.join(runDirectory, "09-broker-b.json"), brokers[1]);
  await persist(path.join(runDirectory, "10-provider-after-and-token-cleanup.json"), { winner: { before: winner.before, delete: winner.delete, after: winner.after, classification: winner.classification, effect_token_cleanup: winner.effect_token_cleanup, verifier_token: winner.verifier_token, verifier_token_cleanup: winner.verifier_token_cleanup, independent_provider_verification: winner.independent_provider_verification }, loser: { provider_credential_mint_count: loser.provider_credential_mint_count, destructive_call_count: loser.destructive_call_count, provider_calls_after_ownership_loss: loser.provider_calls_after_ownership_loss } });

  const terminalBeforeReplay = requireResponse(await invokeC1OperatorSession((await connectTenant()).t3n, CONTRACT_ID, "get-incident", { incident_id: incidentId }), "get-incident", "FOUND");
  if (terminalBeforeReplay.state !== "CLOSED" || terminalBeforeReplay.detail?.effect_attempts !== 1 || terminalBeforeReplay.detail?.final_result_classification !== "VERIFIED_ABSENT") throw new Error("winner did not finalize CLOSED/VERIFIED_ABSENT");
  evidence.terminal = terminalBeforeReplay;

  const replayReserveRaw = await invokeC1(remediationKey, nodeUrl, CONTRACT_ID, RESERVATION_FUNCTION, { incident_id: incidentId });
  const replayReserve = requireResponse(replayReserveRaw, RESERVATION_FUNCTION);
  if (replayReserve.result === "WON") throw new Error("replay reservation reopened authority");
  const replayRelease = path.join(runDirectory, "replay-release.json");
  const replayReady = path.join(runDirectory, "replay.ready.json");
  const replayResultFile = path.join(runDirectory, "replay.result.json");
  const replayProposalComplete = path.join(runDirectory, "replay-proposals-complete.json");
  const replayPromise = runChild(path.join(root, "winner", "broker", "run.ts"), [incidentId], { ...brokerBase, C1_BARRIER_FILE: replayRelease, C1_PROPOSALS_COMPLETE_FILE: replayProposalComplete, C1_READY_FILE: replayReady, C1_RESULT_FILE: replayResultFile, C1_CONTENDER_ID: "replay", C1_EXPECTED_CLAIM_VERSION: String(terminalBeforeReplay.detail?.effect_claim_version ?? 1), C1_EFFECT_START_READY_FILE: "", C1_PRE_DELETE_RELEASE_FILE: "" });
  await waitFor(replayReady, 60_000);
  await writeAtomicJson(replayRelease, { incident_id: incidentId, released_once: true });
  const replay = await replayPromise;
  if (replay.code !== 0) throw new Error(`replay broker failed: ${redact(replay.stderr, [brokerKey])}`);
  const replayObservation = await readJsonFile<JsonObject>(replayResultFile);
  if (replayObservation.token_minted !== false || replayObservation.provider_credential_mint_count !== 0 || replayObservation.destructive_call_count !== 0 || replayObservation.delete_attempted !== false || replayObservation.provider_calls_after_ownership_loss !== 0) throw new Error("terminal replay obtained provider authority");
  evidence.replay = { remediation_reserve: replayReserve, broker: replayObservation, provider_token_mint_count: 0, destructive_call_count: 0 };
  await persist(path.join(runDirectory, "11-replay.json"), evidence.replay);
  const terminalAfterReplay = requireResponse(await invokeC1OperatorSession((await connectTenant()).t3n, CONTRACT_ID, "get-incident", { incident_id: incidentId }), "get-incident", "FOUND");
  if (JSON.stringify(terminalAfterReplay) !== JSON.stringify(terminalBeforeReplay)) throw new Error("terminal replay changed CLOSED authority");
  evidence.independent_terminal_reread = terminalAfterReplay;
  evidence.replay.final_readback = terminalAfterReplay;
  await persist(path.join(runDirectory, "12-independent-terminal-reread.json"), terminalAfterReplay);

  const activity = safeProviderActivity(await t3n.getActivityLog({ contract: CONTRACT_ID, limit: 200 }));
  evidence.host_activity = activity;
  await persist(path.join(runDirectory, "13-host-activity.json"), activity);
  evidence.status = "C1_R6B_R4E_R1_PROVIDER_BACKED_PASS";
  evidence.classification = "LIVE_EXISTING_FRESH_TARGET_CONFIRMED_OWNER_PROVIDER_EXECUTION_PASS";
  evidence.exactly_one_delete = winner.destructive_call_count === 1 && winner.delete?.http_status === 204;
  evidence.allowed_claims = ["one fresh existing GitHub target was verified before one private incident", "one persisted confirmed broker owner", "one committed effect-start preceded exactly one observed GitHub DELETE", "independent provider reads verified absence", "effect and verifier credentials were revoked and refused", "terminal replay produced zero provider authority or mutation"];
  evidence.forbidden_claims = ["GitHub globally guarantees exactly-once", "atomic T3N/GitHub transaction", "zero-standing GitHub trust root", "GitHub App private key is ephemeral", "real causal webhook ingress", "C2 completion", "winner/submission readiness"];
  const bundlePath = path.join(runDirectory, "bundle.json");
  await persist(bundlePath, evidence);
  const offline = verifyBundle(bundlePath);
  await persist(path.join(runDirectory, "offline-verifier.json"), offline);
  if (!offline.ok) throw new Error(`offline verifier rejected R4E-R1 bundle: ${offline.errors.join("; ")}`);
  await writeAtomicJson(path.join(EVIDENCE_ROOT, "C1-R6B-R4E-R1-PROVIDER-PROOF.json"), { status: "C1_R6B_R4E_R1_PROVIDER_BACKED_PASS", classification: "LIVE_EXISTING_FRESH_TARGET_CONFIRMED_OWNER_PROVIDER_EXECUTION_PASS", target_id: TARGET_ID, run_id: runId, bundle: relative(bundlePath), offline_verifier: relative(path.join(runDirectory, "offline-verifier.json")), exact_claims_earned: evidence.allowed_claims, exact_claims_forbidden: evidence.forbidden_claims });
  console.log(JSON.stringify({ status: evidence.status, classification: evidence.classification, run_id: runId, incident_id: incidentId, target_id: TARGET_ID, delete_count: winner.destructive_call_count, evidence: relative(bundlePath) }, null, 2));
}

main().catch(async (error) => {
  const failure = { status: "C1_R6B_R4E_R1_PROVIDER_BACKED_FAILURE", classification: "PROVIDER_BACKED_C1_REMAINS_UNPROVEN", run_id: activeRunDirectory ? path.basename(activeRunDirectory) : null, incident_id: activeIncidentId, error: redactError(error, [process.env.T3N_API_KEY ?? "", process.env.AGENT_T3N_API_KEY ?? "", process.env.EFFECT_BROKER_T3N_API_KEY ?? "", process.env.GITHUB_PAT ?? ""]), no_automatic_second_full_execution: true, historical_evidence_modified: false };
  if (activeRunDirectory) await writeAtomicJson(path.join(activeRunDirectory, "failure.json"), { ...failure, partial_evidence: activeEvidence });
  await writeAtomicJson(path.join(EVIDENCE_ROOT, "C1-R6B-R4E-R1-PROVIDER-FAILURE.json"), failure);
  console.error(JSON.stringify(failure, null, 2));
  process.exitCode = 1;
});
