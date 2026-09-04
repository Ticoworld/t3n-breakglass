import { createHash, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { connectTenant } from "../../scripts/lib.js";
import { invokeC1OperatorSession } from "./t3n.js";
import { CONTRACT_VERSION, GITHUB_OWNER, GITHUB_REPOSITORY, RESERVATION_FUNCTION, contractName } from "./constants.js";
import { readJsonFile, writeAtomicJson } from "./result-file.js";
import { verifyR6BRunBundle, REQUIRED_FILES } from "./c1-r6b-r3-evidence-verify.js";

type JsonObject = Record<string, any>;

const root = path.resolve(import.meta.dirname, "../..");
const STARTING_BRANCH = "winner-v2-core";
const STARTING_SHA = "0e78cf60f54bea7c47b9dd9b50cfa30cef2bb1cb";
const MAIN_SHA = "4a077035474337b7a1ad16204820e68ed3020477";
const OPERATOR_DID = "did:t3n:adb9365ee986cc6d0cb4006580782fe6fc7a431f";
const REMEDIATION_DID = "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019";
const BROKER_DID = "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57";
const CONTRACT_ID = contractName(OPERATOR_DID);
const CONTRACT_NUMERIC_ID = 877;
const PACING_MS = 70_000;
const PROVIDER_ENV = [
  "GITHUB_PAT", "GITHUB_APP_ID", "GITHUB_APP_INSTALLATION_ID",
  "GITHUB_APP_PRIVATE_KEY_PATH", "GITHUB_OWNER", "GITHUB_REPO",
  "GITHUB_DEPLOY_KEY_ID", "GITHUB_TOKEN", "AGENT_T3N_API_KEY",
  "REPLACEMENT_AGENT_T3N_API_KEY", "EFFECT_BROKER_T3N_API_KEY",
];

let runDirectory = "";
let activeRun: JsonObject | null = null;

function isObject(value: unknown): value is JsonObject {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function parseResult(value: unknown): JsonObject {
  const parsed = typeof value === "string" ? JSON.parse(value) : value;
  if (!isObject(parsed)) throw new Error("C1 response was not a JSON object");
  return parsed;
}

function safe(value: unknown, depth = 0): unknown {
  if (depth > 8) return "[DEPTH_LIMIT]";
  if (typeof value === "string") return value.slice(0, 1200);
  if (typeof value === "number" || typeof value === "boolean" || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, 50).map((entry) => safe(entry, depth + 1));
  if (!isObject(value)) return String(value);
  const result: JsonObject = {};
  for (const [key, entry] of Object.entries(value)) {
    const normalizedKey = key.toLowerCase().replaceAll("-", "_");
    const sensitiveKey = normalizedKey === "token" || normalizedKey === "jwt" || normalizedKey === "pat" ||
      normalizedKey.includes("api_key") || normalizedKey.includes("authorization") || normalizedKey.includes("bearer") ||
      normalizedKey.includes("access_token") || normalizedKey.includes("installation_token") || normalizedKey.includes("private_key") ||
      normalizedKey.endsWith("_jwt") || normalizedKey.endsWith("_pat") || normalizedKey.includes("secret") || normalizedKey.includes("credential");
    result[key] = sensitiveKey
      ? "[REDACTED]"
      : safe(entry, depth + 1);
  }
  return result;
}

function errorRecord(error: unknown): JsonObject {
  return {
    class: error instanceof Error ? error.constructor.name : typeof error,
    message: safe(error instanceof Error ? error.message : String(error)),
  };
}

function isQuotaError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /fuel[_ -]?per[_ -]?minute|quota/i.test(message);
}

function fresh(label: string): string {
  return `C1-R6B-R3-STATE-${label}-${Date.now()}-${randomUUID().slice(0, 8)}`;
}

function childEnv(base: NodeJS.ProcessEnv, additions: Record<string, string>): NodeJS.ProcessEnv {
  const env = { ...base };
  for (const existing of Object.keys(env)) if (existing.startsWith("GITHUB_")) delete env[existing];
  for (const key of [...PROVIDER_ENV, "T3N_API_KEY"]) delete env[key];
  Object.assign(env, additions);
  return env;
}

function runProcess(args: string[], env: NodeJS.ProcessEnv): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--import", "tsx", ...args], {
      cwd: root,
      env,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += String(chunk); });
    child.stderr.on("data", (chunk) => { stderr += String(chunk); });
    child.on("close", (code) => resolve({ code: code ?? 1, stdout, stderr }));
  });
}

async function waitFor(file: string, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (!existsSync(file) && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 10));
  return existsSync(file);
}

async function persistPrimary(file: string, value: JsonObject, updateCheckpoint = true): Promise<JsonObject> {
  const target = path.join(runDirectory, file);
  await writeAtomicJson(target, value);
  const reread = await readJsonFile<JsonObject>(target);
  if (JSON.stringify(reread) !== JSON.stringify(value)) throw new Error(`primary evidence readback mismatch: ${file}`);
  if (activeRun && updateCheckpoint) activeRun.last_primary_file = file;
  return reread;
}

async function readPrimary(file: string): Promise<JsonObject> {
  const value = await readJsonFile<JsonObject>(path.join(runDirectory, file));
  if (activeRun) activeRun.last_primary_file = file;
  return value;
}

function responseOf(record: JsonObject): JsonObject {
  return isObject(record.response) ? record.response : {};
}

function detailOf(record: JsonObject): JsonObject {
  return isObject(responseOf(record).detail) ? responseOf(record).detail : {};
}

function requireCondition(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

function updateLastAuthority(record: JsonObject): void {
  const detail = detailOf(record);
  if (activeRun && Object.keys(detail).length > 0) activeRun.last_durable_authority = safe(detail);
}

async function operatorCall(file: string, functionName: string, input: JsonObject, t3n: any): Promise<JsonObject> {
  if (activeRun) {
    activeRun.stage = functionName;
    activeRun.request_sent = true;
  }
  const raw = await invokeC1OperatorSession(t3n, CONTRACT_ID, functionName, input);
  const record = {
    phase: "C1-R6B-R3 primary operator observation",
    transport: "authenticated-operator-session",
    function: functionName,
    incident_id: String(input.incident_id),
    request_fields: Object.keys(input).sort(),
    input: safe(input),
    observed_at_unix_ms: Date.now(),
    response: safe(raw),
    provider_operations: 0,
  };
  const saved = await persistPrimary(file, record);
  if (activeRun) activeRun.request_sent = false;
  updateLastAuthority(saved);
  return saved;
}

async function readCredential(file: string, name: string): Promise<string> {
  const contents = await readFile(path.join(root, file), "utf8");
  const line = contents.split(/\r?\n/).find((entry) => entry.startsWith(`${name}=`));
  if (!line) throw new Error(`${name} missing from ${file}`);
  return line.slice(name.length + 1).trim().replace(/^['"]|['"]$/g, "");
}

function applicationRecord(role: string, raw: JsonObject, functionName: string, incidentId: string): JsonObject {
  const response = isObject(raw.response) ? raw.response : isObject(raw.application_response) ? raw.application_response : null;
  return {
    ...raw,
    role,
    function: functionName,
    incident_id: incidentId,
    routing_recognized: Boolean(response),
    guest_reached: Boolean(response && response.function === functionName && typeof response.result === "string"),
    application_result: response?.result ?? null,
    application_note: response?.note ?? null,
    provider_operations: 0,
  };
}

async function runRole(file: string, role: "remediation" | "broker", functionName: string, input: JsonObject, label: string): Promise<JsonObject> {
  const expectedDid = role === "remediation" ? REMEDIATION_DID : BROKER_DID;
  if (activeRun) {
    activeRun.stage = functionName;
    activeRun.request_sent = true;
  }
  const env = childEnv(process.env, {
    C1_OPERATOR_DID: OPERATOR_DID,
    C1_R6B_ROLE: role,
    C1_R6B_EXPECTED_DID: expectedDid,
    C1_R6B_FUNCTION: functionName,
    C1_R6B_INPUT: JSON.stringify(input),
  });
  const result = await runProcess([path.join(root, "winner", "scripts", "c1-r6b-principal-call.ts")], env);
  let parsed: JsonObject;
  try {
    parsed = JSON.parse(result.stdout.trim()) as JsonObject;
  } catch {
    parsed = {
      role,
      did: expectedDid,
      function: functionName,
      response: null,
      error: { class: "OutputParseError", message: "principal child did not return JSON" },
      provider_operations: 0,
    };
  }
  const record = applicationRecord(role, parsed, functionName, String(input.incident_id ?? ""));
  record.label = label;
  record.exit_code = result.code;
  record.stderr_present = Boolean(result.stderr);
  const saved = await persistPrimary(file, record);
  if (activeRun) activeRun.request_sent = false;
  return saved;
}

async function pace(label: string): Promise<void> {
  if (!activeRun) throw new Error("run context is not initialized");
  const entry = { label, started_at_unix_ms: Date.now(), wait_ms: PACING_MS };
  activeRun.pacing.push(entry);
  await new Promise((resolve) => setTimeout(resolve, PACING_MS));
  entry.completed_at_unix_ms = Date.now();
  await persistPrimary("00-run-context.json", activeRun, false);
}

async function assertOperatorState(record: JsonObject, expected: Record<string, unknown>, label: string): Promise<JsonObject> {
  const detail = detailOf(record);
  for (const [key, value] of Object.entries(expected)) requireCondition(detail[key] === value, `${label}: ${key} expected ${String(value)} got ${String(detail[key])}`);
  updateLastAuthority(record);
  return detail;
}

async function assertRole(record: JsonObject, result: string, state?: string): Promise<void> {
  requireCondition(record.guest_reached === true, `${record.function}: guest behavior was not reached`);
  requireCondition(record.application_result === result, `${record.function}: expected ${result}, got ${String(record.application_result)}`);
  if (state !== undefined) requireCondition(responseOf(record).state === state, `${record.function}: expected state ${state}`);
}

async function runRace(incidentId: string): Promise<void> {
  const raceDir = path.join(os.tmpdir(), `breakglass-c1-r6b-r3-${Date.now()}-${randomUUID().slice(0, 8)}`);
  await mkdir(raceDir, { recursive: true });
  const barrier = path.join(raceDir, "release");
  const aReady = path.join(raceDir, "broker-a.ready.json");
  const bReady = path.join(raceDir, "broker-b.ready.json");
  const aResult = path.join(runDirectory, "07-race-broker-a.json");
  const bResult = path.join(runDirectory, "08-race-broker-b.json");
  const brokerKey = await readCredential(".env.effect-broker", "EFFECT_BROKER_T3N_API_KEY");
  const base = childEnv(process.env, {
    C1_R6B_INCIDENT_ID: incidentId,
    C1_OPERATOR_DID: OPERATOR_DID,
    C1_R6B_EXPECTED_CLAIM_VERSION: "0",
    EFFECT_BROKER_T3N_API_KEY: brokerKey,
    EFFECT_BROKER_DID: BROKER_DID,
    C1_R6B_BARRIER_FILE: barrier,
  });
  const aPromise = runProcess([path.join(root, "winner", "scripts", "c1-r6b-claim-contender.ts")], { ...base, C1_R6B_CONTENDER: "broker-a", C1_R6B_READY_FILE: aReady, C1_R6B_RESULT_FILE: aResult });
  const bPromise = runProcess([path.join(root, "winner", "scripts", "c1-r6b-claim-contender.ts")], { ...base, C1_R6B_CONTENDER: "broker-b", C1_R6B_READY_FILE: bReady, C1_R6B_RESULT_FILE: bResult });
  const bothReady = await waitFor(aReady, 120000) && await waitFor(bReady, 120000);
  requireCondition(bothReady, "both broker contenders did not reach common barrier");
  const readyA = await readJsonFile<JsonObject>(aReady);
  const readyB = await readJsonFile<JsonObject>(bReady);
  const releasedAt = Date.now();
  await persistPrimary("06-race-barrier.json", {
    phase: "C1-R6B-R3 race barrier",
    incident_id: incidentId,
    contenders: [
      { name: readyA.contender, pid: readyA.pid, ready_at_unix_ms: readyA.ready_at_unix_ms, expected_claim_version: 0 },
      { name: readyB.contender, pid: readyB.pid, ready_at_unix_ms: readyB.ready_at_unix_ms, expected_claim_version: 0 },
    ],
    common_barrier_ready: true,
    released_at_unix_ms: releasedAt,
    provider_operations: 0,
  });
  await writeFile(barrier, JSON.stringify({ released_at_unix_ms: releasedAt, incident_id: incidentId }));
  const [aProcess, bProcess] = await Promise.all([aPromise, bPromise]);
  const raceA = safe(await readJsonFile<JsonObject>(aResult)) as JsonObject;
  const raceB = safe(await readJsonFile<JsonObject>(bResult)) as JsonObject;
  await persistPrimary("07-race-broker-a.json", raceA);
  await persistPrimary("08-race-broker-b.json", raceB);
  requireCondition(aProcess.code === 0 && bProcess.code === 0, "broker child process failed");
  const contenders = [raceA, raceB];
  const winners = contenders.filter((entry) => entry.claim_outcome === "CLAIM_WON");
  const losers = contenders.filter((entry) => entry.claim_outcome === "CLAIM_LOST");
  requireCondition(winners.length === 1 && losers.length === 1, "race did not produce one winner and one loser");
  requireCondition(winners[0].token_minted === false && winners[0].destructive_call_count === 0 && winners[0].provider_operations === 0, "race winner has unexpected effect activity");
  requireCondition(losers[0].token_minted === false && losers[0].destructive_call_count === 0 && losers[0].provider_operations === 0, "race loser has unexpected effect activity");
}

async function sha256File(file: string): Promise<string> {
  return createHash("sha256").update(await readFile(file)).digest("hex");
}

async function main(): Promise<void> {
  const forbidden = Object.keys(process.env)
    .filter((key) => key.startsWith("GITHUB_") || ["AGENT_T3N_API_KEY", "REPLACEMENT_AGENT_T3N_API_KEY", "EFFECT_BROKER_T3N_API_KEY"].includes(key))
    .filter((key) => Boolean(process.env[key]));
  if (forbidden.length || process.env.GITHUB_PAT) throw new Error(`R6B-R3 state proof refuses provider credentials: ${forbidden.join(",")}`);
  if (!process.env.T3N_API_KEY) throw new Error("T3N_API_KEY is required for operator session");

  const registration = JSON.parse(await readFile(path.join(root, "winner", "evidence", "contract-registration.json"), "utf8")) as JsonObject;
  const config = JSON.parse(await readFile(path.join(root, "winner", "evidence", "delegation-configuration.json"), "utf8")) as JsonObject;
  requireCondition(registration.contract?.name === CONTRACT_ID && registration.contract.version === CONTRACT_VERSION && registration.contract.contract_id === CONTRACT_NUMERIC_ID && registration.map?.private === true && registration.map.acl_contract_id === CONTRACT_NUMERIC_ID, "active registration evidence is not 2.0.3/877");
  requireCondition(config.status === "CONFIGURED_VERIFIED" && config.contract === CONTRACT_ID && config.contract_version === CONTRACT_VERSION && config.contract_id === CONTRACT_NUMERIC_ID, "active delegation evidence is not 2.0.3/877");

  const { t3n, tenantDid, nodeUrl } = await connectTenant();
  requireCondition(tenantDid === OPERATOR_DID, "authenticated operator DID mismatch");

  const runId = `C1-R6B-R3-${Date.now()}-${randomUUID().slice(0, 8)}`;
  const incidentId = fresh("incident");
  runDirectory = path.join(root, "winner", "evidence", `C1-R6B-R3-${runId}`);
  await mkdir(runDirectory, { recursive: true });
  activeRun = {
    phase: "C1-R6B-R3",
    run_id: runId,
    incident_id: incidentId,
    branch: STARTING_BRANCH,
    starting_sha: STARTING_SHA,
    main_sha: MAIN_SHA,
    environment: "testnet",
    node: nodeUrl,
    sdk: "@terminal3/t3n-sdk 5.2.0",
    contract: { name: CONTRACT_ID, version: CONTRACT_VERSION, numeric_contract_id: CONTRACT_NUMERIC_ID },
    principals: { operator: OPERATOR_DID, remediation_agent: REMEDIATION_DID, effect_broker: BROKER_DID, all_distinct: new Set([OPERATOR_DID, REMEDIATION_DID, BROKER_DID]).size === 3 },
    provider_counters: { github_api_calls: 0, github_installation_tokens: 0, deploy_key_creates: 0, deploy_key_deletes: 0, provider_mutations: 0 },
    provider_helpers_imported: false,
    created_at_local: new Date().toISOString(),
    persisted_before_create: true,
    pacing: [],
    no_historical_incident_touched: true,
    credentials_in_evidence: false,
    last_primary_file: "00-run-context.json",
    request_sent: false,
  };
  await persistPrimary("00-run-context.json", activeRun, false);
  await readPrimary("00-run-context.json");

  if (activeRun) activeRun.quota_readiness = true;
  const quotaId = fresh("quota-readiness");
  let quota: JsonObject;
  try {
    quota = await operatorCall("01-quota-readiness.json", "get-incident", { incident_id: quotaId }, t3n);
  } catch (error) {
    if (activeRun && isQuotaError(error)) activeRun.quota_errors = 1;
    throw error;
  }
  requireCondition(responseOf(quota).result === "DENIED" && responseOf(quota).note === "incident authority does not exist", "quota readiness did not return nonexistent-incident denial");
  await pace("after_quota_readiness");

  const create = await operatorCall("02-create.json", "create-incident", { incident_id: incidentId, remediation_agent_did: REMEDIATION_DID, effect_broker_did: BROKER_DID, deploy_key_id: 1, ttl_secs: 900 }, t3n);
  requireCondition(responseOf(create).result === "WON" && responseOf(create).state === "ACTIVE", "create-incident did not commit ACTIVE");
  const initial = await operatorCall("03-initial-active-read.json", "get-incident", { incident_id: incidentId }, t3n);
  await assertOperatorState(initial, { status: "ACTIVE", effect_attempts: 0, effect_claim_version: 0, reservation_id: null, effect_claim_id: null, final_result_classification: null }, "initial ACTIVE read");

  const reserve = await runRole("04-reserve.json", "remediation", RESERVATION_FUNCTION, { incident_id: incidentId }, "reservation");
  await assertRole(reserve, "WON", "RESERVED");
  const reserved = await operatorCall("05-reserved-read.json", "get-incident", { incident_id: incidentId }, t3n);
  await assertOperatorState(reserved, { status: "RESERVED", reservation_version: 1, effect_attempts: 0, effect_claim_version: 0, effect_claim_id: null }, "reserved read");
  await pace("after_reservation");

  await runRace(incidentId);
  const postRace = await operatorCall("09-post-race-read.json", "get-incident", { incident_id: incidentId }, t3n);
  const raceA = await readPrimary("07-race-broker-a.json");
  const raceB = await readPrimary("08-race-broker-b.json");
  const raceWinner = [raceA, raceB].find((entry) => entry.claim_outcome === "CLAIM_WON");
  requireCondition(isObject(raceWinner), "race winner result missing");
  await assertOperatorState(postRace, { status: "EFFECT_CLAIMED", effect_attempts: 0, effect_claim_version: 1, effect_claim_id: raceWinner.claim_id }, "post-race read");
  await pace("after_generation_zero_race");

  const release = await runRole("10-release.json", "broker", "release-not-attempted", { incident_id: incidentId, claim_id: raceWinner.claim_id }, "release");
  await assertRole(release, "WON", "READY_RETRY");
  const postRelease = await operatorCall("11-post-release-read.json", "get-incident", { incident_id: incidentId }, t3n);
  await assertOperatorState(postRelease, { status: "READY_RETRY", effect_attempts: 0, effect_claim_id: null, effect_claim_version: 1 }, "post-release read");
  await pace("after_release");

  const staleDir = path.join(os.tmpdir(), `breakglass-c1-r6b-r3-stale-${Date.now()}-${randomUUID().slice(0, 8)}`);
  await mkdir(staleDir, { recursive: true });
  const staleBarrier = path.join(staleDir, "release");
  const staleReady = path.join(staleDir, "ready.json");
  const staleResult = path.join(runDirectory, "12-stale-claim.json");
  const brokerKey = await readCredential(".env.effect-broker", "EFFECT_BROKER_T3N_API_KEY");
  const staleEnv = childEnv(process.env, { C1_R6B_INCIDENT_ID: incidentId, C1_OPERATOR_DID: OPERATOR_DID, C1_R6B_EXPECTED_CLAIM_VERSION: "0", EFFECT_BROKER_T3N_API_KEY: brokerKey, EFFECT_BROKER_DID: BROKER_DID, C1_R6B_BARRIER_FILE: staleBarrier, C1_R6B_CONTENDER: "stale-after-release", C1_R6B_READY_FILE: staleReady, C1_R6B_RESULT_FILE: staleResult });
  if (activeRun) { activeRun.stage = "claim-effect-stale-generation"; activeRun.request_sent = true; }
  const stalePromise = runProcess([path.join(root, "winner", "scripts", "c1-r6b-claim-contender.ts")], staleEnv);
  requireCondition(await waitFor(staleReady, 60000), "stale contender did not reach barrier");
  await writeFile(staleBarrier, "release");
  const staleProcess = await stalePromise;
  const stale = await readPrimary("12-stale-claim.json");
  if (activeRun) activeRun.request_sent = false;
  requireCondition(staleProcess.code === 0 && stale.claim_outcome === "CLAIM_LOST" && stale.expected_claim_version === 0 && stale.token_minted === false && stale.provider_operations === 0 && stale.destructive_call_count === 0, "stale generation did not lose safely");
  const postStale = await operatorCall("13-post-stale-read.json", "get-incident", { incident_id: incidentId }, t3n);
  await assertOperatorState(postStale, { status: "READY_RETRY", effect_attempts: 0, effect_claim_version: 1, effect_claim_id: null }, "post-stale read");
  await pace("after_stale_generation");

  const freshClaim = await runRole("14-fresh-claim.json", "broker", "claim-effect", { incident_id: incidentId, expected_claim_version: 1 }, "fresh generation");
  await assertRole(freshClaim, "WON", "EFFECT_CLAIMED");
  const freshClaimId = detailOf(freshClaim).claim_id;
  requireCondition(typeof freshClaimId === "string" && freshClaimId.length > 0 && freshClaimId !== raceWinner.claim_id, "fresh claim ID invalid");
  const postFresh = await operatorCall("15-post-fresh-read.json", "get-incident", { incident_id: incidentId }, t3n);
  await assertOperatorState(postFresh, { status: "EFFECT_CLAIMED", effect_attempts: 0, effect_claim_version: 2, effect_claim_id: freshClaimId }, "post-fresh read");

  const remediationBegin = await runRole("16-remediation-begin.json", "remediation", "begin-effect", { incident_id: incidentId, claim_id: freshClaimId }, "remediation negative");
  requireCondition(remediationBegin.application_result !== "WON" && remediationBegin.guest_reached === true, "remediation unexpectedly began effect");
  const postRemediation = await operatorCall("17-post-remediation-begin-read.json", "get-incident", { incident_id: incidentId }, t3n);
  await assertOperatorState(postRemediation, { status: "EFFECT_CLAIMED", effect_attempts: 0, effect_claim_version: 2, effect_claim_id: freshClaimId }, "post-remediation read");
  await pace("after_remediation_begin");

  const brokerBegin = await runRole("18-broker-begin.json", "broker", "begin-effect", { incident_id: incidentId, claim_id: freshClaimId }, "broker begin");
  await assertRole(brokerBegin, "WON", "EFFECT_STARTED");
  requireCondition(responseOf(brokerBegin).effect_attempts === 1, "broker begin did not consume effect budget");
  const postBegin = await operatorCall("19-post-begin-read.json", "get-incident", { incident_id: incidentId }, t3n);
  await assertOperatorState(postBegin, { status: "EFFECT_STARTED", effect_attempts: 1, max_effects: 1, effect_claim_version: 2, effect_claim_id: freshClaimId, final_result_classification: null }, "post-begin read");
  requireCondition(detailOf(postBegin).reservation_id !== null && detailOf(postBegin).reservation_id !== undefined, "reservation identity was lost");
  await pace("after_broker_begin");

  const releaseAfter = await runRole("20-release-after-begin.json", "broker", "release-not-attempted", { incident_id: incidentId, claim_id: freshClaimId }, "release after begin");
  requireCondition(releaseAfter.application_result !== "WON", "release after begin unexpectedly won");
  const beginAfter = await runRole("21-begin-after-begin.json", "broker", "begin-effect", { incident_id: incidentId, claim_id: freshClaimId }, "begin after begin");
  requireCondition(beginAfter.application_result !== "WON", "second begin unexpectedly won");
  const claimAfter = await runRole("22-claim-after-begin.json", "broker", "claim-effect", { incident_id: incidentId, expected_claim_version: 2 }, "claim after begin");
  requireCondition(claimAfter.application_result !== "WON", "claim after begin unexpectedly won");
  const reserveAfter = await runRole("23-reserve-after-begin.json", "remediation", RESERVATION_FUNCTION, { incident_id: incidentId }, "reserve after begin");
  requireCondition(reserveAfter.application_result !== "WON", "reserve after begin unexpectedly won");

  const final = await operatorCall("24-final-authority-read.json", "get-incident", { incident_id: incidentId }, t3n);
  const finalDetail = await assertOperatorState(final, { status: "EFFECT_STARTED", effect_attempts: 1, max_effects: 1, effect_claim_version: 2, effect_claim_id: freshClaimId, final_result_classification: null }, "final authority read");
  requireCondition(finalDetail.reservation_id === detailOf(postBegin).reservation_id, "final reservation identity changed");
  await operatorObservationHostActivity("25-host-activity.json", t3n);
  await persistPrimary("26-provider-counters.json", { phase: "C1-R6B-R3 provider counters", incident_id: incidentId, github_api_calls: 0, github_installation_tokens: 0, deploy_key_creates: 0, deploy_key_deletes: 0, provider_mutations: 0, provider_helpers_imported: false, observed_at_unix_ms: Date.now() });
  await persistPrimary("27-run-complete.json", { phase: "C1-R6B-R3 completion marker", incident_id: incidentId, live_sequence_complete: true, all_required_primary_files_present: true, claim_version_final: 2, effect_attempts_final: 1, provider_operations: 0, completed_at: new Date().toISOString() });

  const verification = await verifyR6BRunBundle(runDirectory);
  if (activeRun) activeRun.offline_verifier = verification;
  requireCondition(verification.pass === true, `R6B-R3 offline verifier failed: ${verification.errors.join(", ")}`);
  const hashes: JsonObject = {};
  for (const file of REQUIRED_FILES) hashes[file] = await sha256File(path.join(runDirectory, file));
  const proof = {
    phase: "C1-R6B-R3 evidence-complete live state protocol",
    status: "C1_R6B_STATE_PROTOCOL_PASS",
    classification: "LIVE_EVIDENCE_COMPLETE_STATE_PROTOCOL_PASS",
    run_directory: path.relative(root, runDirectory).replaceAll("\\", "/"),
    incident_id: incidentId,
    contract: { name: CONTRACT_ID, version: CONTRACT_VERSION, numeric_contract_id: CONTRACT_NUMERIC_ID },
    starting_sha: STARTING_SHA,
    main_sha: MAIN_SHA,
    primary_file_sha256: hashes,
    offline_verifier: "PASS",
    quota_errors: 0,
    provider_counters: { github_api_calls: 0, github_installation_tokens: 0, deploy_key_creates: 0, deploy_key_deletes: 0, provider_mutations: 0 },
    limitations: ["State-only proof; no provider operation.", "Pacing was a conservative execution strategy, not a claimed Terminal 3 guarantee.", "Host activity is supporting metadata, not a body-bound or Merkle receipt.", "The GitHub App private key remains a standing trust root."],
    historical_incidents_touched: false,
  };
  await writeAtomicJson(path.join(root, "winner", "evidence", "C1-R6B-R3-STATE-PROOF.json"), proof);
  process.stdout.write(JSON.stringify({ status: proof.status, incident_id: incidentId, run_directory: proof.run_directory, provider_counters: proof.provider_counters }));
}

async function operatorObservationHostActivity(file: string, t3n: any): Promise<void> {
  if (activeRun) { activeRun.stage = "host-activity"; activeRun.request_sent = true; }
  try {
    const raw = await t3n.getActivityLog({ contract: CONTRACT_ID, limit: 300 });
    await persistPrimary(file, { phase: "C1-R6B-R3 host activity", incident_id: activeRun?.incident_id, classification: "HOST_ACTIVITY", observed_at_unix_ms: Date.now(), response: safe(raw), limitations: ["Supporting host metadata only; not a body commitment, Merkle proof, or complete causal receipt."], provider_operations: 0 });
  } catch (error) {
    await persistPrimary(file, { phase: "C1-R6B-R3 host activity", incident_id: activeRun?.incident_id, classification: "HOST_ACTIVITY_READ_FAILED", observed_at_unix_ms: Date.now(), error: errorRecord(error), provider_operations: 0 });
    throw error;
  } finally {
    if (activeRun) activeRun.request_sent = false;
  }
}

main().catch(async (error) => {
  const failure = {
    phase: "C1-R6B-R3 evidence-complete live state-protocol reproduction",
    status: activeRun?.failure_classification ?? "C1_R6B_R3_STATE_PROTOCOL_FAILURE",
    run_directory: runDirectory ? path.relative(root, runDirectory).replaceAll("\\", "/") : null,
    incident_id: activeRun?.incident_id ?? null,
    run_id: activeRun?.run_id ?? null,
    failed_stage: activeRun?.stage ?? "initialization",
    request_sent: activeRun?.request_sent ?? false,
    last_successful_primary_checkpoint: activeRun?.last_primary_file ?? null,
    last_durable_authority: activeRun?.last_durable_authority ?? null,
    error: errorRecord(error),
    quota: { readiness_attempted: Boolean(activeRun?.quota_readiness), errors: activeRun?.quota_errors ?? 0, quota_error: isQuotaError(error) },
    provider_counters: { github_api_calls: 0, github_installation_tokens: 0, deploy_key_creates: 0, deploy_key_deletes: 0, provider_mutations: 0 },
    no_automatic_retry: true,
    no_historical_incident_touched: true,
    credentials_in_evidence: false,
  };
  await writeAtomicJson(path.join(root, "winner", "evidence", "C1-R6B-R3-STATE-FAILURE.json"), failure);
  console.error(`R6B-R3 state proof failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
