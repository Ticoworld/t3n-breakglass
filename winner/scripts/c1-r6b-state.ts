import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { connectTenant } from "../../scripts/lib.js";
import { invokeC1OperatorSession } from "./t3n.js";
import { BROKER_FUNCTIONS, CONTRACT_VERSION, GITHUB_OWNER, GITHUB_REPOSITORY, RESERVATION_FUNCTION, contractName } from "./constants.js";
import { readJsonFile, writeAtomicJson } from "./result-file.js";

const root = path.resolve(import.meta.dirname, "../..");
const OPERATOR_DID = "did:t3n:adb9365ee986cc6d0cb4006580782fe6fc7a431f";
const REMEDIATION_DID = "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019";
const BROKER_DID = "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57";
const CONTRACT_ID = contractName(OPERATOR_DID);
const CONTRACT_NUMERIC_ID = 877;
const ALL_FUNCTIONS = ["create-incident", "get-incident", RESERVATION_FUNCTION, ...BROKER_FUNCTIONS] as const;
const PROVIDER_ENV = ["GITHUB_PAT", "GITHUB_APP_ID", "GITHUB_APP_INSTALLATION_ID", "GITHUB_APP_PRIVATE_KEY_PATH", "GITHUB_OWNER", "GITHUB_REPO", "GITHUB_DEPLOY_KEY_ID", "GITHUB_TOKEN", "AGENT_T3N_API_KEY", "REPLACEMENT_AGENT_T3N_API_KEY", "EFFECT_BROKER_T3N_API_KEY"];
let activeRunContext: JsonObject | null = null;

type JsonObject = Record<string, any>;

function isObject(value: unknown): value is JsonObject { return Boolean(value) && typeof value === "object" && !Array.isArray(value); }
function parseResult(value: unknown): JsonObject { const parsed = typeof value === "string" ? JSON.parse(value) : value; if (!isObject(parsed)) throw new Error("C1 response was not a JSON object"); return parsed; }
function safe(value: unknown, depth = 0): unknown {
  if (depth > 8) return "[DEPTH_LIMIT]";
  if (typeof value === "string") return value.slice(0, 1200);
  if (typeof value === "number" || typeof value === "boolean" || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, 50).map((entry) => safe(entry, depth + 1));
  if (!isObject(value)) return String(value);
  const output: JsonObject = {};
  for (const [key, entry] of Object.entries(value)) output[key] = /api[_-]?key|authorization|bearer|token|jwt|private[_-]?key|pat|secret|credential/i.test(key) ? "[REDACTED]" : safe(entry, depth + 1);
  return output;
}
function errorRecord(error: unknown): JsonObject { return { class: error instanceof Error ? error.constructor.name : typeof error, message: safe(error instanceof Error ? error.message : String(error)) }; }
function fresh(label: string): string { return `C1-R6B-STATE-${label}-${Date.now()}-${randomUUID().slice(0, 8)}`; }
function childEnv(base: NodeJS.ProcessEnv, additions: Record<string, string>, remove: string[]): NodeJS.ProcessEnv {
  const env = { ...base };
  for (const existing of Object.keys(env)) if (existing.startsWith("GITHUB_")) delete env[existing];
  for (const key of [...PROVIDER_ENV, "T3N_API_KEY", ...remove]) delete env[key];
  Object.assign(env, additions);
  return env;
}
function runProcess(args: string[], env: NodeJS.ProcessEnv): Promise<{ code: number; stdout: string; stderr: string }> { return new Promise((resolve) => { const child = spawn(process.execPath, ["--import", "tsx", ...args], { cwd: root, env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] }); let stdout = ""; let stderr = ""; child.stdout.on("data", (chunk) => { stdout += String(chunk); }); child.stderr.on("data", (chunk) => { stderr += String(chunk); }); child.on("close", (code) => resolve({ code: code ?? 1, stdout, stderr })); }); }
function authority(response: unknown): JsonObject { const value = parseResult(response); if (!isObject(value.detail)) throw new Error("C1 response did not include authority detail"); return value.detail; }
function expectState(response: unknown, expected: Record<string, unknown>, label: string): JsonObject { const value = parseResult(response); const detail = authority(value); for (const [key, expectedValue] of Object.entries(expected)) if (detail[key] !== expectedValue) throw new Error(`${label}: ${key} expected ${String(expectedValue)} got ${String(detail[key])}`); return detail; }
function applicationRecord(role: string, raw: JsonObject, functionName: string, incidentId: string): JsonObject {
  const response = isObject(raw.response) ? raw.response : isObject(raw.application_response) ? raw.application_response : null;
  return { ...raw, role, function: functionName, incident_id: incidentId, routing_recognized: Boolean(response), guest_reached: Boolean(response && response.function === functionName && typeof response.result === "string"), application_result: response?.result ?? null, application_note: response?.note ?? null, provider_operations: 0 };
}

async function readCredential(file: string, name: string): Promise<string> { const contents = await readFile(path.join(root, file), "utf8"); const line = contents.split(/\r?\n/).find((entry) => entry.startsWith(`${name}=`)); if (!line) throw new Error(`${name} missing from ${file}`); return line.slice(name.length + 1).trim().replace(/^['"]|['"]$/g, ""); }

async function runRole(role: "remediation" | "broker", functionName: string, input: JsonObject, label: string): Promise<JsonObject> {
  const expectedDid = role === "remediation" ? REMEDIATION_DID : BROKER_DID;
  const env = childEnv(process.env, { C1_OPERATOR_DID: OPERATOR_DID, C1_R6B_ROLE: role, C1_R6B_EXPECTED_DID: expectedDid, C1_R6B_FUNCTION: functionName, C1_R6B_INPUT: JSON.stringify(input) }, []);
  const result = await runProcess([path.join(root, "winner", "scripts", "c1-r6b-principal-call.ts")], env);
  let parsed: JsonObject;
  try { parsed = JSON.parse(result.stdout.trim()) as JsonObject; } catch { parsed = { role, did: expectedDid, function: functionName, error: { class: "OutputParseError", message: "principal child did not return JSON", stderr: result.stderr.slice(0, 500) }, provider_operations: 0 }; }
  const record = applicationRecord(role, parsed, functionName, String(input.incident_id ?? ""));
  record.label = label;
  record.exit_code = result.code;
  if (result.stderr) record.stderr_present = true;
  return record;
}

async function waitFor(file: string, timeoutMs: number): Promise<boolean> { const deadline = Date.now() + timeoutMs; while (!existsSync(file) && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 10)); return existsSync(file); }

async function main(): Promise<void> {
  const forbidden = Object.keys(process.env).filter((key) => key.startsWith("GITHUB_") || ["AGENT_T3N_API_KEY", "REPLACEMENT_AGENT_T3N_API_KEY", "EFFECT_BROKER_T3N_API_KEY"].includes(key)).filter((key) => Boolean(process.env[key]));
  if (forbidden.length || process.env.GITHUB_PAT) throw new Error(`R6B state proof refuses provider credentials: ${forbidden.join(",")}`);
  if (!process.env.T3N_API_KEY) throw new Error("T3N_API_KEY is required for operator session");
  const registration = JSON.parse(await readFile(path.join(root, "winner", "evidence", "contract-registration.json"), "utf8")) as JsonObject;
  const config = JSON.parse(await readFile(path.join(root, "winner", "evidence", "delegation-configuration.json"), "utf8")) as JsonObject;
  if (registration.contract?.name !== CONTRACT_ID || registration.contract.version !== CONTRACT_VERSION || registration.contract.contract_id !== CONTRACT_NUMERIC_ID || registration.map?.private !== true || registration.map.acl_contract_id !== CONTRACT_NUMERIC_ID) throw new Error("R6B registration evidence is not 2.0.3/877");
  if (config.status !== "CONFIGURED_VERIFIED" || config.contract !== CONTRACT_ID || config.contract_version !== CONTRACT_VERSION || config.contract_id !== CONTRACT_NUMERIC_ID) throw new Error("R6B delegation evidence is not 2.0.3/877");
  const { t3n, tenantDid, nodeUrl } = await connectTenant();
  if (tenantDid !== OPERATOR_DID) throw new Error("R6B authenticated operator mismatch");
  const context: JsonObject = { phase: "C1-R6B live state-only effect-start and generation-fence proof", status: "C1_R6B_STATE_PROTOCOL_FAILURE", environment: "testnet", node: nodeUrl, sdk: "@terminal3/t3n-sdk 5.2.0", contract: { name: CONTRACT_ID, version: CONTRACT_VERSION, numeric_contract_id: CONTRACT_NUMERIC_ID }, principals: { operator: OPERATOR_DID, remediation_agent: REMEDIATION_DID, effect_broker: BROKER_DID, all_distinct: new Set([OPERATOR_DID, REMEDIATION_DID, BROKER_DID]).size === 3 }, provider_counters: { github_api_calls: 0, github_installation_tokens: 0, deploy_key_creates: 0, deploy_key_deletes: 0, provider_mutations: 0 }, counters: { contract_registrations: 0, map_acl_updates: 0, map_entry_writes: 0, successful_incident_creations: 0, reservations: 0, claims: 0, releases: 0, begins: 0, finalizations: 0, reconciliations: 0 }, credential_safety: { credentials_in_evidence: false, t3n_api_key_in_evidence: false, github_api_call: false, provider_mutation: false } };
  // Keep a sanitized context reachable by the top-level failure handler. This
  // is needed when a later parent read/error occurs after create-incident: the
  // incident ID and already-observed child outcomes must not exist only in
  // transient parent memory.
  activeRunContext = context;
  const operatorCall = async (functionName: string, input: JsonObject): Promise<unknown> => invokeC1OperatorSession(t3n, CONTRACT_ID, functionName, input);
  const routeChecks: JsonObject[] = [];
  const routeIds: string[] = [];
  const addRoute = async (role: "remediation" | "broker", functionName: string, input: JsonObject, label: string) => { const record = await runRole(role, functionName, input, label); routeChecks.push(record); routeIds.push(String(input.incident_id)); return record; };
  await addRoute("remediation", RESERVATION_FUNCTION, { incident_id: fresh("route-remediation") }, "authorized");
  for (const functionName of BROKER_FUNCTIONS) { const input: JsonObject = { incident_id: fresh(`route-${functionName.replaceAll("-", "_")}`) }; if (functionName === "claim-effect") input.expected_claim_version = 0; if (["release-not-attempted", "begin-effect", "finalize-effect", "reconcile-effect"].includes(functionName)) input.claim_id = "r6b-route"; if (["finalize-effect", "reconcile-effect"].includes(functionName)) input.classification = "VERIFIED_ABSENT"; await addRoute("broker", functionName, input, "authorized"); }
  const separation = { broker_to_reservation: await addRoute("broker", RESERVATION_FUNCTION, { incident_id: fresh("cross-broker-reserve") }, "cross_role_negative"), remediation_to_claim: await addRoute("remediation", "claim-effect", { incident_id: fresh("cross-remediation-claim"), expected_claim_version: 0 }, "cross_role_negative") };
  const routeIdsBeforeState = [...routeIds];
  const stateIncidentId = fresh("incident");
  context.incident_id = stateIncidentId;
  context.routing_checks = routeChecks;
  context.role_separation = separation;
  const createdResponse = await operatorCall("create-incident", { incident_id: stateIncidentId, remediation_agent_did: REMEDIATION_DID, effect_broker_did: BROKER_DID, deploy_key_id: 1, ttl_secs: 900 });
  context.creation = { request_fields: ["incident_id", "remediation_agent_did", "effect_broker_did", "deploy_key_id", "ttl_secs"], result: safe(createdResponse), valid_incident_created: true };
  context.counters.successful_incident_creations = 1;
  const created = expectState(createdResponse, { incident_id: stateIncidentId, action: "revoke_github_deploy_key", github_owner: GITHUB_OWNER, github_repo: GITHUB_REPOSITORY, remediation_agent_did: REMEDIATION_DID, effect_broker_did: BROKER_DID, deploy_key_id: 1, max_effects: 1, effect_attempts: 0, status: "ACTIVE", reservation_id: null, reservation_version: 0, effect_claim_id: null, effect_claim_version: 0, final_result_classification: null }, "create");
  const initialRead = await operatorCall("get-incident", { incident_id: stateIncidentId });
  const initial = expectState(initialRead, { incident_id: stateIncidentId, status: "ACTIVE", effect_attempts: 0, max_effects: 1, effect_claim_id: null, effect_claim_version: 0, final_result_classification: null }, "initial readback");
  context.creation.operator_readback = safe(initialRead);
  context.creation.exact_active = JSON.stringify(created) === JSON.stringify(initial);
  if (!context.creation.exact_active) throw new Error("operator ACTIVE readback mismatch");
  const absence: JsonObject[] = [];
  for (const incidentId of routeIdsBeforeState) { const response = parseResult(await operatorCall("get-incident", { incident_id: incidentId })); absence.push({ incident_id: incidentId, function: "get-incident", guest_reached: response.function === "get-incident" && typeof response.result === "string", result: response.result, note: response.note, authority_absent: response.result === "DENIED" && response.note === "incident authority does not exist" }); }
  context.state_absence_before = absence;
  const reserve = await runRole("remediation", RESERVATION_FUNCTION, { incident_id: stateIncidentId }, "state_reservation");
  context.reservation = reserve;
  context.counters.reservations = reserve.application_result === "WON" ? 1 : 0;
  if (reserve.application_result !== "WON" || reserve.guest_reached !== true) throw new Error("state reservation did not reach guest and commit");
  const reservedRead = await operatorCall("get-incident", { incident_id: stateIncidentId });
  expectState(reservedRead, { status: "RESERVED", effect_attempts: 0, effect_claim_id: null, effect_claim_version: 0 }, "reserved readback");
  context.after_reservation = safe(reservedRead);
  const raceDir = path.join(os.tmpdir(), `breakglass-c1-r6b-${Date.now()}-${randomUUID().slice(0, 8)}`);
  await mkdir(raceDir, { recursive: true });
  const barrier = path.join(raceDir, "release");
  const brokerKey = await readCredential(".env.effect-broker", "EFFECT_BROKER_T3N_API_KEY");
  const common = { C1_R6B_INCIDENT_ID: stateIncidentId, C1_OPERATOR_DID: OPERATOR_DID, C1_R6B_EXPECTED_CLAIM_VERSION: "0", EFFECT_BROKER_T3N_API_KEY: brokerKey, EFFECT_BROKER_DID: BROKER_DID, C1_R6B_BARRIER_FILE: barrier };
  const base = childEnv(process.env, common, []);
  const aReady = path.join(raceDir, "broker-a.ready"); const bReady = path.join(raceDir, "broker-b.ready"); const aResult = path.join(raceDir, "broker-a.result.json"); const bResult = path.join(raceDir, "broker-b.result.json");
  const aPromise = runProcess([path.join(root, "winner", "scripts", "c1-r6b-claim-contender.ts")], { ...base, C1_R6B_CONTENDER: "broker-a", C1_R6B_READY_FILE: aReady, C1_R6B_RESULT_FILE: aResult });
  const bPromise = runProcess([path.join(root, "winner", "scripts", "c1-r6b-claim-contender.ts")], { ...base, C1_R6B_CONTENDER: "broker-b", C1_R6B_READY_FILE: bReady, C1_R6B_RESULT_FILE: bResult });
  const bothReady = await waitFor(aReady, 120000) && await waitFor(bReady, 120000);
  if (!bothReady) throw new Error("state-only broker race did not reach the common barrier");
  const readyA = await readJsonFile<JsonObject>(aReady); const readyB = await readJsonFile<JsonObject>(bReady);
  await writeFile(barrier, JSON.stringify({ released_at_unix_ms: Date.now(), incident_id: stateIncidentId }));
  const [aProcess, bProcess] = await Promise.all([aPromise, bPromise]);
  const raceA = await readJsonFile<JsonObject>(aResult); const raceB = await readJsonFile<JsonObject>(bResult);
  const race = { common_barrier: { both_ready: bothReady, ready_files: [readyA, readyB], released: true }, contenders: [raceA, raceB], process_exit_codes: [aProcess.code, bProcess.code] };
  context.race = race;
  const winners = [raceA, raceB].filter((entry) => entry.claim_outcome === "CLAIM_WON"); const losers = [raceA, raceB].filter((entry) => entry.claim_outcome === "CLAIM_LOST");
  if (winners.length !== 1 || losers.length !== 1 || winners[0].token_minted !== false || losers[0].token_minted !== false || Number(winners[0].destructive_call_count) !== 0 || Number(losers[0].destructive_call_count) !== 0) throw new Error("state-only race did not produce exactly one fenced winner and one zero-effect loser");
  context.counters.claims = 1;
  const afterRace = await operatorCall("get-incident", { incident_id: stateIncidentId });
  const claimed = expectState(afterRace, { status: "EFFECT_CLAIMED", effect_attempts: 0, effect_claim_version: 1, final_result_classification: null }, "race readback");
  if (claimed.effect_claim_id !== winners[0].claim_id) throw new Error("race winner claim ID did not remain attached");
  const winningClaimId = String(winners[0].claim_id);
  const release = await runRole("broker", "release-not-attempted", { incident_id: stateIncidentId, claim_id: winningClaimId }, "release_not_attempted");
  context.release = release;
  context.counters.releases = release.application_result === "WON" ? 1 : 0;
  if (release.application_result !== "WON" || release.guest_reached !== true) throw new Error("NOT_ATTEMPTED release did not commit");
  const afterRelease = await operatorCall("get-incident", { incident_id: stateIncidentId });
  expectState(afterRelease, { status: "READY_RETRY", effect_attempts: 0, effect_claim_id: null, effect_claim_version: 1 }, "release readback");
  context.after_release = safe(afterRelease);
  const staleDir = path.join(raceDir, "stale"); await mkdir(staleDir, { recursive: true }); const staleBarrier = path.join(staleDir, "release"); const staleReady = path.join(staleDir, "ready"); const staleResult = path.join(staleDir, "result.json");
  const staleProcessPromise = runProcess([path.join(root, "winner", "scripts", "c1-r6b-claim-contender.ts")], { ...base, C1_R6B_CONTENDER: "stale-after-release", C1_R6B_EXPECTED_CLAIM_VERSION: "0", C1_R6B_BARRIER_FILE: staleBarrier, C1_R6B_READY_FILE: staleReady, C1_R6B_RESULT_FILE: staleResult });
  if (!await waitFor(staleReady, 60000)) throw new Error("stale contender did not reach its barrier");
  await writeFile(staleBarrier, "release");
  const staleProcess = await staleProcessPromise; const stale = await readJsonFile<JsonObject>(staleResult); context.stale_contender = { result: stale, process_exit_code: staleProcess.code };
  if (stale.claim_outcome !== "CLAIM_LOST" || stale.token_minted !== false || Number(stale.destructive_call_count) !== 0) throw new Error("stale generation contender unexpectedly won");
  const afterStale = await operatorCall("get-incident", { incident_id: stateIncidentId }); expectState(afterStale, { status: "READY_RETRY", effect_attempts: 0, effect_claim_id: null, effect_claim_version: 1 }, "stale readback");
  const freshClaim = await runRole("broker", "claim-effect", { incident_id: stateIncidentId, expected_claim_version: 1 }, "fresh_generation_claim"); context.fresh_claim = freshClaim; context.counters.claims = 2;
  if (freshClaim.application_result !== "WON" || freshClaim.guest_reached !== true) throw new Error("fresh generation claim did not commit");
  const freshResponse = isObject(freshClaim.response) ? freshClaim.response : {};
  const freshDetail = isObject(freshResponse.detail) ? freshResponse.detail : {};
  const freshClaimId = String(freshDetail.claim_id ?? ""); if (!freshClaimId) throw new Error("fresh generation claim did not return a claim ID");
  const afterFresh = await operatorCall("get-incident", { incident_id: stateIncidentId }); const claimedFresh = expectState(afterFresh, { status: "EFFECT_CLAIMED", effect_attempts: 0, effect_claim_version: 2, final_result_classification: null }, "fresh claim readback"); if (claimedFresh.effect_claim_id !== freshClaimId) throw new Error("fresh claim ID mismatch");
  const remediationBegin = await runRole("remediation", "begin-effect", { incident_id: stateIncidentId, claim_id: freshClaimId }, "cross_role_begin"); context.remediation_begin_negative = remediationBegin;
  const begin = await runRole("broker", "begin-effect", { incident_id: stateIncidentId, claim_id: freshClaimId }, "begin_effect"); context.begin = begin; context.counters.begins = begin.application_result === "WON" ? 1 : 0;
  if (begin.application_result !== "WON" || begin.guest_reached !== true) throw new Error("broker begin-effect did not commit");
  const afterBegin = await operatorCall("get-incident", { incident_id: stateIncidentId }); const started = expectState(afterBegin, { status: "EFFECT_STARTED", effect_attempts: 1, effect_claim_version: 2, final_result_classification: null }, "begin readback"); if (started.effect_claim_id !== freshClaimId) throw new Error("begin claim identity changed"); context.after_begin = safe(afterBegin);
  const postBeginRelease = await runRole("broker", "release-not-attempted", { incident_id: stateIncidentId, claim_id: freshClaimId }, "release_after_begin");
  const postBeginAgain = await runRole("broker", "begin-effect", { incident_id: stateIncidentId, claim_id: freshClaimId }, "begin_after_begin");
  const postBeginClaim = await runRole("broker", "claim-effect", { incident_id: stateIncidentId, expected_claim_version: 2 }, "claim_after_begin");
  const postBeginReserve = await runRole("remediation", RESERVATION_FUNCTION, { incident_id: stateIncidentId }, "reserve_after_begin");
  context.post_begin_denials = { release: postBeginRelease, begin_again: postBeginAgain, claim_again: postBeginClaim, reserve_again: postBeginReserve };
  const finalRead = await operatorCall("get-incident", { incident_id: stateIncidentId }); const finalState = expectState(finalRead, { status: "EFFECT_STARTED", effect_attempts: 1, effect_claim_version: 2, final_result_classification: null }, "final state-only readback"); if (finalState.effect_claim_id !== freshClaimId) throw new Error("final state-only claim identity changed"); context.final_state = safe(finalRead);
  let activity: unknown = null; try { activity = safe(await t3n.getActivityLog({ contract: CONTRACT_ID, limit: 300 })); } catch (error) { activity = { read_succeeded: false, error: errorRecord(error) }; }
  context.activity = { classification: "HOST_ACTIVITY", data: activity, limitations: ["Host-stamped metadata only; not a Merkle proof, body commitment, or complete causal receipt."] };
  const authRoutes = routeChecks.filter((entry) => entry.label === "authorized"); const crossRoutes = routeChecks.filter((entry) => entry.label === "cross_role_negative");
  const routePass = authRoutes.length === 6 && authRoutes.every((entry) => entry.guest_reached === true && entry.application_result === "DENIED" && entry.application_note === "incident authority does not exist");
  const crossPass = crossRoutes.length === 2 && crossRoutes.every((entry) => entry.guest_reached !== true || entry.application_result === "DENIED");
  const rolePass = remediationBegin.guest_reached !== true || remediationBegin.application_result === "DENIED";
  const postPass = postBeginRelease.application_result === "DENIED" && postBeginAgain.application_result === "DENIED" && postBeginClaim.application_result !== "WON" && postBeginReserve.application_result !== "WON";
  if (!routePass || !crossPass || !rolePass || !postPass) throw new Error("R6B role routing or post-begin denial criteria failed");
  context.status = "C1_R6B_STATE_PROTOCOL_PASS";
  context.next_gate = "C1-R6B passed; separately authorize provider-backed C1 proof only after review";
  const evidencePath = path.join(root, "winner", "evidence", "C1-R6B-STATE-PROOF.json");
  await writeFile(evidencePath, JSON.stringify(context, null, 2) + "\n");
  process.stdout.write(JSON.stringify({ status: context.status, incident_id: stateIncidentId, final_state: finalState, provider_counters: context.provider_counters, evidence: "winner/evidence/C1-R6B-STATE-PROOF.json" }));
}

main().catch(async (error) => {
  const failure = { ...(activeRunContext ?? { phase: "C1-R6B live state-only effect-start and generation-fence proof" }), status: "C1_R6B_STATE_PROTOCOL_FAILURE", error: errorRecord(error), provider_counters: { github_api_calls: 0, github_installation_tokens: 0, deploy_key_creates: 0, deploy_key_deletes: 0, provider_mutations: 0 }, credentials_in_evidence: false, no_provider_operation_performed: true };
  await writeAtomicJson(path.join(root, "winner", "evidence", "C1-R6B-STATE-FAILURE.json"), failure);
  console.error(`R6B state proof failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
