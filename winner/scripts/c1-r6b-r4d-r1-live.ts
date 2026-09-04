import { createHash, randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { SessionOrgDataClient, type BoundGrant } from "@terminal3/t3n-sdk";
import { connectTenant } from "../../scripts/lib.js";
import { BROKER_FUNCTIONS, CONTRACT_VERSION, INCIDENT_MAP_TAIL, ORGANISATION_DID, RESERVATION_FUNCTION, contractName } from "./constants.js";
import { connectC1Principal, invokeC1, invokeC1OperatorSession, redact, requireValue } from "./t3n.js";
import { readJsonFile, writeAtomicJson } from "./result-file.js";
import { verifyBundle } from "./c1-r6b-r4d-r1-evidence-verify.js";

const root = path.resolve(import.meta.dirname, "../..");
const STARTING_SHA = "06a050d7a5b32ed1cf6e228e06c2d62e6ddd4f4d";
const MAIN_SHA = "4a077035474337b7a1ad16204820e68ed3020477";
const OPERATOR_DID = "did:t3n:adb9365ee986cc6d0cb4006580782fe6fc7a431f";
const REMEDIATION_DID = "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019";
const BROKER_DID = "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57";
const CONTRACT_ID = contractName(OPERATOR_DID);
const CONTRACT_NUMERIC_ID = 878;
const WASM_BYTES = 227011;
const WASM_SHA256 = "ca7032b112b837b06e4334c10bca8820447f6ea1756b74db9bccd3181ad4d5d0";
const REGISTRATION_EVIDENCE = path.join(root, "winner", "evidence", "C1-R6B-R4B-REGISTRATION.json");
const CANONICAL_REGISTRATION = path.join(root, "winner", "evidence", "contract-registration.json");
const CANONICAL_DELEGATION = path.join(root, "winner", "evidence", "delegation-configuration.json");
const PACING_MS = 70_000;

type JsonObject = Record<string, any>;

let currentStage = "startup";
let activeRunDirectory: string | null = null;
let activeIncidentId: string | null = null;
let lastKnownAuthority: unknown = null;
let readinessFailureWritten = false;

function parseObject(value: unknown): JsonObject {
  const parsed = typeof value === "string" ? JSON.parse(value) : value;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Terminal 3 response was not an object");
  return parsed as JsonObject;
}

function objectAt(value: unknown): JsonObject | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as JsonObject : null;
}

export function sanitizeEvidence(value: unknown, secrets: string[] = [], seen = new WeakSet<object>()): unknown {
  if (value === null || value === undefined || typeof value === "boolean" || typeof value === "number") return value;
  if (typeof value === "string") return redact(value, secrets);
  if (typeof value !== "object") return String(value);
  if (seen.has(value)) return "[CIRCULAR]";
  seen.add(value);
  if (Array.isArray(value)) return value.map((entry) => sanitizeEvidence(entry, secrets, seen));
  const output: JsonObject = {};
  for (const [key, entry] of Object.entries(value)) {
    const normalized = key.toLowerCase();
    if (normalized === "token" || normalized.endsWith("_token") || normalized.includes("authorization") || normalized.includes("api_key") || normalized.includes("private_key") || normalized.includes("jwt") || normalized.includes("pem") || normalized.includes("password") || normalized === "pat" || normalized.endsWith("_pat")) {
      output[key] = "[REDACTED]";
    } else {
      output[key] = sanitizeEvidence(entry, secrets, seen);
    }
  }
  return output;
}

function safeThrownError(error: unknown, secret: string): JsonObject {
  const object = error && typeof error === "object" ? error as JsonObject : null;
  return {
    error_class: error instanceof Error ? error.constructor.name : typeof error,
    sanitized_error_message: redact(error instanceof Error ? error.message : String(error), [secret]),
    error_code: sanitizeEvidence(object?.code ?? object?.error_code, [secret]),
    request_id: sanitizeEvidence(object?.request_id ?? object?.requestId, [secret]),
    response_status: sanitizeEvidence(object?.status ?? object?.status_code ?? object?.response?.status, [secret]),
    response_detail: sanitizeEvidence(object?.detail ?? object?.response?.detail, [secret]),
    response_body: sanitizeEvidence(object?.body ?? object?.response?.body, [secret]),
    error_metadata: sanitizeEvidence(error, [secret]),
  };
}

function explicitReadinessSignal(value: unknown, patterns: RegExp[]): boolean {
  const text = JSON.stringify(sanitizeEvidence(value)).toLowerCase();
  return patterns.some((pattern) => pattern.test(text));
}

export function classifyReadiness(result: JsonObject): string {
  const payload = result.outcome_kind === "RETURNED_RESPONSE" ? result.sanitized_response : result;
  if (explicitReadinessSignal(payload, [/fuel[_ ]per[_ ]minute/, /quota[_ -]?exceed/, /quota limit/, /rate limit/])) return "R4D_R1_QUOTA_CONFIRMED";
  if (explicitReadinessSignal(payload, [/insufficient[_ ]credit/, /credit[_ ]exhausted/, /credit limit/, /available\s*=\s*0/])) return "R4D_R1_CREDIT_LIMIT_CONFIRMED";
  const response = objectAt(result.sanitized_response);
  if (result.outcome_kind === "RETURNED_RESPONSE" && response?.function === "get-incident" && response.result === "DENIED") return "R4D_R1_READINESS_PASS";
  return "R4D_R1_OTHER_READINESS_FAILURE";
}

function requireResponse(value: unknown, functionName: string, result?: string): JsonObject {
  const response = parseObject(value);
  if (response.function !== functionName) throw new Error(`${functionName} returned an unexpected function label`);
  if (result !== undefined && response.result !== result) throw new Error(`${functionName} expected ${result}, got ${String(response.result)}`);
  return response;
}

function valueFromEnvFile(contents: string, name: string): string {
  const line = contents.split(/\r?\n/).find((entry) => entry.startsWith(`${name}=`));
  if (!line) throw new Error(`${name} missing from environment file`);
  return line.slice(name.length + 1).trim().replace(/^['"]|['"]$/g, "");
}

async function envFileValue(file: string, name: string): Promise<string> {
  return valueFromEnvFile(await readFile(path.join(root, file), "utf8"), name);
}

function safeGrant(grant: BoundGrant): JsonObject {
  return {
    grantee: grant.grantee,
    contract_id: grant.contract_id,
    functions: Array.isArray(grant.functions) ? [...grant.functions] : null,
    scopes: Array.isArray(grant.scopes) ? [...grant.scopes] : grant.scopes ?? null,
    allowed_hosts: Array.isArray(grant.allowed_hosts) ? [...grant.allowed_hosts] : grant.allowed_hosts ?? null,
    version_req: grant.version_req ?? null,
    window: grant.window ?? null,
  };
}

function sameFunctions(actual: unknown, expected: string[]): boolean {
  return Array.isArray(actual) && actual.length === expected.length && [...actual].sort().every((entry, index) => entry === [...expected].sort()[index]);
}

function emptyOrAbsent(value: unknown): boolean {
  return value === undefined || value === null || (Array.isArray(value) && value.length === 0);
}

function exactGrant(grant: JsonObject | undefined, did: string, functions: string[]): boolean {
  return Boolean(grant)
    && grant!.grantee === did
    && grant!.contract_id === CONTRACT_ID
    && sameFunctions(grant!.functions, functions)
    && emptyOrAbsent(grant!.scopes)
    && emptyOrAbsent(grant!.allowed_hosts)
    && grant!.version_req === CONTRACT_VERSION;
}

async function readGrant(t3n: Awaited<ReturnType<typeof connectTenant>>["t3n"], orgData: SessionOrgDataClient, did: string, functions: string[]): Promise<JsonObject> {
  const document = await t3n.getMemberDelegation();
  const matches = document.grants.filter((grant) => grant.grantee === did && grant.contract_id === CONTRACT_ID).map(safeGrant);
  const egress = await orgData.getAgentEgress({ orgDid: ORGANISATION_DID, agentDid: did, contractId: CONTRACT_ID });
  const egressSafe = egress.egress ? { contract_id: egress.egress.contract_id, functions: [...egress.egress.functions], allowed_hosts: [...egress.egress.allowed_hosts], version_req: egress.egress.version_req ?? null } : null;
  return {
    did,
    grants: matches,
    exact: matches.length === 1 && exactGrant(matches[0], did, functions) && egressSafe === null,
    separate_agent_egress: egressSafe,
  };
}

function childEnvironment(base: NodeJS.ProcessEnv, additions: Record<string, string>): NodeJS.ProcessEnv {
  const env = { ...base };
  for (const key of Object.keys(env)) {
    if (key === "T3N_API_KEY" || key === "AGENT_T3N_API_KEY" || key === "REPLACEMENT_AGENT_T3N_API_KEY" || key === "EFFECT_BROKER_T3N_API_KEY" || key === "GITHUB_PAT" || key.startsWith("GITHUB_")) delete env[key];
  }
  Object.assign(env, additions);
  return env;
}

function runChild(script: string, env: NodeJS.ProcessEnv): Promise<{ code: number; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--import", "tsx", script], { cwd: root, env, windowsHide: true, stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (chunk) => { stderr += String(chunk); });
    child.on("close", (code) => resolve({ code: code ?? 1, stderr }));
  });
}

async function waitFor(file: string, timeoutMs = 120_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!existsSync(file)) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${path.basename(file)}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

async function persist(file: string, value: unknown): Promise<JsonObject> {
  await writeAtomicJson(file, value);
  return readJsonFile<JsonObject>(file);
}

async function sha256File(file: string): Promise<string> {
  return createHash("sha256").update(await readFile(file)).digest("hex");
}

function relativeEvidence(file: string): string {
  return path.relative(root, file).replaceAll("\\", "/");
}

async function captureReadinessProbe(t3n: Awaited<ReturnType<typeof connectTenant>>["t3n"], operatorKey: string, probeDirectory: string, probeId: string, incidentId: string): Promise<{ context: JsonObject; result: JsonObject; classification: string; resultFile: string }> {
  const resultFile = path.join(probeDirectory, "01-readiness-result.json");
  const context = await persist(path.join(probeDirectory, "00-readiness-context.json"), {
    phase: "C1-R6B-R4D-R1-Q1 readiness observability",
    probe_id: probeId,
    incident_id: incidentId,
    starting_sha: STARTING_SHA,
    main_sha: MAIN_SHA,
    contract: CONTRACT_ID,
    version: CONTRACT_VERSION,
    numeric_id: CONTRACT_NUMERIC_ID,
    requested_function: "get-incident",
    request_sent: false,
    provider_counters: { github_api_calls: 0, installation_tokens: 0, deploy_key_creates: 0, deploy_key_deletes: 0, provider_mutations: 0 },
    started_at_unix_ms: Date.now(),
  });
  let result: JsonObject;
  try {
    const response = await invokeC1OperatorSession(t3n, CONTRACT_ID, "get-incident", { incident_id: incidentId });
    result = {
      phase: "C1-R6B-R4D-R1-Q1 readiness observability",
      probe_id: probeId,
      incident_id: incidentId,
      outcome_kind: "RETURNED_RESPONSE",
      request_sent: true,
      sanitized_response: sanitizeEvidence(response, [operatorKey]),
      completed_at_unix_ms: Date.now(),
    };
  } catch (error) {
    result = {
      phase: "C1-R6B-R4D-R1-Q1 readiness observability",
      probe_id: probeId,
      incident_id: incidentId,
      outcome_kind: "THROWN_ERROR",
      request_sent: true,
      ...safeThrownError(error, operatorKey),
      completed_at_unix_ms: Date.now(),
    };
  }
  const persistedResult = await persist(resultFile, result);
  const classification = classifyReadiness(persistedResult);
  return { context, result: persistedResult, classification, resultFile };
}

function safeAttempt(apiKey: string, nodeUrl: string, functionName: string, input: JsonObject): Promise<JsonObject> {
  return invokeC1(apiKey, nodeUrl, CONTRACT_ID, functionName, input)
    .then((value) => ({ ok: true, response: parseObject(value), function: functionName, input_keys: Object.keys(input) }))
    .catch((error) => ({ ok: false, function: functionName, input_keys: Object.keys(input), error: redact(error, [apiKey]) }));
}

function noProvider(value: unknown): boolean {
  const response = parseObject(value);
  const providerHttpAbsentOrZero = response.provider_http === undefined
    || (response.provider_http?.attempted === false && Number(response.provider_http?.count ?? 0) === 0);
  return providerHttpAbsentOrZero
    && Number(response.provider_operations ?? 0) === 0
    && response.token_minted !== true
    && Number(response.destructive_call_count ?? 0) === 0;
}

async function sleepPacing(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, PACING_MS));
}

async function main(): Promise<void> {
  if (Object.keys(process.env).some((key) => key.startsWith("GITHUB_") && Boolean(process.env[key])) || process.env.GITHUB_PAT) throw new Error("R4D-R1 refuses provider credentials");
  if (process.env.C1_OPERATOR_DID && process.env.C1_OPERATOR_DID !== OPERATOR_DID) throw new Error("operator DID override mismatch");
  if (new Set([OPERATOR_DID, REMEDIATION_DID, BROKER_DID]).size !== 3) throw new Error("C1 principals are not distinct");

  const registration = JSON.parse(await readFile(REGISTRATION_EVIDENCE, "utf8")) as JsonObject;
  const canonicalRegistration = JSON.parse(await readFile(CANONICAL_REGISTRATION, "utf8")) as JsonObject;
  const canonicalDelegation = JSON.parse(await readFile(CANONICAL_DELEGATION, "utf8")) as JsonObject;
  if (registration.registration?.name !== CONTRACT_ID || registration.registration?.version !== CONTRACT_VERSION || registration.registration?.contract_id !== CONTRACT_NUMERIC_ID || registration.local_artifact?.bytes !== WASM_BYTES || registration.local_artifact?.sha256 !== WASM_SHA256) throw new Error("retained registration evidence mismatch");
  if (canonicalRegistration.contract?.version !== CONTRACT_VERSION || canonicalRegistration.contract?.contract_id !== CONTRACT_NUMERIC_ID || canonicalRegistration.map?.private !== true || canonicalRegistration.map?.acl_contract_id !== CONTRACT_NUMERIC_ID) throw new Error("canonical registration evidence mismatch");
  if (canonicalDelegation.contract_version !== CONTRACT_VERSION || canonicalDelegation.contract_id !== CONTRACT_NUMERIC_ID) throw new Error("canonical delegation evidence mismatch");

  currentStage = "live configuration read";
  const operatorKey = requireValue("T3N_API_KEY");
  const { t3n, tenant, tenantDid, nodeUrl } = await connectTenant();
  if (tenantDid !== OPERATOR_DID) throw new Error("authenticated operator DID mismatch");
  const inventory = (await tenant.contracts.listDetailed()).contracts.find((item) => item.name === CONTRACT_ID && item.version === CONTRACT_VERSION);
  if (!inventory || inventory.status !== "active") throw new Error("2.0.4 contract is not active in live inventory");
  const mapStatus = await tenant.maps.getStatus(INCIDENT_MAP_TAIL);
  if (mapStatus !== "active") throw new Error(`winner-incidents map is not active: ${mapStatus}`);
  const orgData = new SessionOrgDataClient(t3n, nodeUrl);
  if (!(await orgData.amIAdmin({ orgDid: ORGANISATION_DID }))) throw new Error("operator is not admin of the expected organization");
  delete process.env.T3N_API_KEY;
  const remediationKey = await envFileValue(".env.replacement-agent", "REPLACEMENT_AGENT_T3N_API_KEY");
  const brokerKey = await envFileValue(".env.effect-broker", "EFFECT_BROKER_T3N_API_KEY");
  process.env.REPLACEMENT_AGENT_T3N_API_KEY = remediationKey;
  process.env.REPLACEMENT_AGENT_DID = REMEDIATION_DID;
  process.env.EFFECT_BROKER_T3N_API_KEY = brokerKey;
  process.env.EFFECT_BROKER_DID = BROKER_DID;
  const remediation = await connectC1Principal("REPLACEMENT_AGENT_T3N_API_KEY", "REPLACEMENT_AGENT_DID");
  const broker = await connectC1Principal("EFFECT_BROKER_T3N_API_KEY", "EFFECT_BROKER_DID");
  if (remediation.did !== REMEDIATION_DID || broker.did !== BROKER_DID) throw new Error("role credential DID mismatch");
  process.env.T3N_API_KEY = operatorKey;
  const remediationGrant = await readGrant(t3n, orgData, REMEDIATION_DID, [RESERVATION_FUNCTION]);
  const brokerGrant = await readGrant(t3n, orgData, BROKER_DID, [...BROKER_FUNCTIONS]);
  if (!remediationGrant.exact || !brokerGrant.exact) throw new Error("live delegation mismatch");

  currentStage = "quota readiness";
  const readinessProbeId = `q1-${Date.now()}-${randomBytes(6).toString("hex")}`;
  const readinessId = `C1-R6B-R4D-R1-Q1-${Date.now()}-${randomBytes(8).toString("hex")}`;
  const readinessDirectory = path.join(root, "winner", "evidence", `C1-R6B-R4D-R1-Q1-${readinessProbeId}`);
  await mkdir(readinessDirectory, { recursive: true });
  const readiness = await captureReadinessProbe(t3n, operatorKey, readinessDirectory, readinessProbeId, readinessId);
  const quotaReadiness: JsonObject = {
    probe_id: readinessProbeId,
    incident_id: readinessId,
    result_file: relativeEvidence(readiness.resultFile),
    outcome_kind: readiness.result.outcome_kind,
    classification: readiness.classification,
    success: readiness.classification === "R4D_R1_READINESS_PASS",
    quota_error: readiness.classification === "R4D_R1_QUOTA_CONFIRMED",
    response: readiness.result.sanitized_response ?? null,
    error: readiness.result.outcome_kind === "THROWN_ERROR" ? readiness.result : null,
  };
  if (readiness.classification !== "R4D_R1_READINESS_PASS") {
    readinessFailureWritten = true;
    await writeAtomicJson(path.join(root, "winner", "evidence", "C1-R6B-R4D-R1-Q1-READINESS-FAILURE.json"), {
      phase: "C1-R6B-R4D-R1-Q1 readiness observability",
      classification: readiness.classification,
      probe_id: readinessProbeId,
      probe_directory: relativeEvidence(readinessDirectory),
      readiness_result_file: relativeEvidence(readiness.resultFile),
      request_sent_count: 1,
      valid_incidents: 0,
      state_mutations: 0,
      provider_counters: { github_api_calls: 0, installation_tokens: 0, deploy_key_creates: 0, deploy_key_deletes: 0, provider_mutations: 0 },
      automatic_retry: false,
      historical_r4d_r1_failure_preserved: true,
      exact_readiness_result: readiness.result,
    });
    throw new Error(`readiness classification ${readiness.classification}`);
  }
  await sleepPacing();

  const runId = `r4d-r1-${Date.now()}-${randomBytes(6).toString("hex")}`;
  const incidentId = `C1-R6B-R4D-R1-${Date.now()}-${randomBytes(8).toString("hex")}`;
  activeRunDirectory = path.join(root, "winner", "evidence", `C1-R6B-R4D-R1-${runId}`);
  activeIncidentId = incidentId;
  await mkdir(activeRunDirectory, { recursive: true });
  const context = await persist(path.join(activeRunDirectory, "00-run-context.json"), {
    phase: "C1-R6B-R4D-R1 concurrent effect-start ownership",
    run_id: runId,
    incident_id: incidentId,
    starting_sha: STARTING_SHA,
    main_sha: MAIN_SHA,
    contract: CONTRACT_ID,
    version: CONTRACT_VERSION,
    numeric_id: CONTRACT_NUMERIC_ID,
    principals: { operator: OPERATOR_DID, remediation_agent: REMEDIATION_DID, effect_broker: BROKER_DID, organization: ORGANISATION_DID },
    map_acl: { private: true, contract_id: CONTRACT_NUMERIC_ID, source: "retained activation evidence; SDK exposes lifecycle status only" },
    provider_counters: { github_api_calls: 0, installation_tokens: 0, deploy_key_creates: 0, deploy_key_deletes: 0, provider_mutations: 0 },
    persisted_before_create: true,
    persisted_at_unix_ms: Date.now(),
  });

  currentStage = "create-incident";
  const create = requireResponse(await invokeC1OperatorSession(t3n, CONTRACT_ID, "create-incident", { incident_id: incidentId, remediation_agent_did: REMEDIATION_DID, effect_broker_did: BROKER_DID, deploy_key_id: 1, ttl_secs: 900 }), "create-incident", "WON");
  if (create.state !== "ACTIVE" || create.detail?.effect_attempts !== 0 || create.detail?.effect_claim_version !== 0 || create.detail?.reservation_id !== null || create.detail?.effect_claim_id !== null || create.detail?.effect_start_id !== null || create.detail?.max_effects !== 1) throw new Error("created state is not exact ACTIVE");
  const createFile = await persist(path.join(activeRunDirectory, "01-create.json"), create);
  currentStage = "initial active readback";
  const initial = requireResponse(await invokeC1OperatorSession(t3n, CONTRACT_ID, "get-incident", { incident_id: incidentId }), "get-incident", "FOUND");
  lastKnownAuthority = initial;
  if (initial.state !== "ACTIVE" || initial.detail?.effect_attempts !== 0 || initial.detail?.effect_claim_version !== 0 || initial.detail?.effect_claim_id !== null || initial.detail?.effect_start_id !== null) throw new Error("initial ACTIVE readback mismatch");
  const initialFile = await persist(path.join(activeRunDirectory, "02-initial-active-readback.json"), initial);

  currentStage = "reservation";
  const reserve = requireResponse(await invokeC1(remediation.apiKey, remediation.nodeUrl, CONTRACT_ID, RESERVATION_FUNCTION, { incident_id: incidentId }), RESERVATION_FUNCTION, "WON");
  if (reserve.state !== "RESERVED") throw new Error("reservation did not reach RESERVED");
  const reserveFile = await persist(path.join(activeRunDirectory, "03-reservation.json"), reserve);
  const reserved = requireResponse(await invokeC1OperatorSession(t3n, CONTRACT_ID, "get-incident", { incident_id: incidentId }), "get-incident", "FOUND");
  lastKnownAuthority = reserved;
  if (reserved.state !== "RESERVED" || reserved.detail?.reservation_version !== 1 || reserved.detail?.effect_attempts !== 0) throw new Error("reserved readback mismatch");
  const reservedFile = await persist(path.join(activeRunDirectory, "04-reserved-readback.json"), reserved);

  currentStage = "claim owner";
  const claimProposal = requireResponse(await invokeC1(broker.apiKey, broker.nodeUrl, CONTRACT_ID, "claim-effect", { incident_id: incidentId, expected_claim_version: 0, contender_nonce: randomBytes(16).toString("hex") }), "claim-effect", "PROPOSED");
  const claimId = String(claimProposal.detail?.claim_id ?? "");
  if (!/^claim-1-[0-9a-f]{32}$/.test(claimId) || claimProposal.detail?.claim_version !== 1) throw new Error("claim proposal identity mismatch");
  const claimProposalFile = await persist(path.join(activeRunDirectory, "05-claim-proposal.json"), claimProposal);
  const claimConfirmation = requireResponse(await invokeC1(broker.apiKey, broker.nodeUrl, CONTRACT_ID, "confirm-claim", { incident_id: incidentId, claim_id: claimId }), "confirm-claim", "CONFIRMED");
  if (claimConfirmation.detail?.claim_id !== claimId || claimConfirmation.detail?.claim_version !== 1 || claimConfirmation.detail?.github_owner !== "Ticoworld" || claimConfirmation.detail?.github_repo !== "t3n-breakglass-sandbox" || claimConfirmation.detail?.deploy_key_id !== 1) throw new Error("confirmed claim target mismatch");
  const claimConfirmationFile = await persist(path.join(activeRunDirectory, "06-claim-confirmation.json"), claimConfirmation);
  const claimReadback = requireResponse(await invokeC1OperatorSession(t3n, CONTRACT_ID, "get-incident", { incident_id: incidentId }), "get-incident", "FOUND");
  lastKnownAuthority = claimReadback;
  if (claimReadback.state !== "EFFECT_CLAIMED" || claimReadback.detail?.effect_claim_version !== 1 || claimReadback.detail?.effect_claim_id !== claimId || claimReadback.detail?.effect_attempts !== 0 || claimReadback.detail?.effect_start_id !== null) throw new Error("claim readback mismatch");
  const claimReadbackFile = await persist(path.join(activeRunDirectory, "07-claim-readback.json"), claimReadback);

  currentStage = "start contenders";
  const barrierPlan = path.join(activeRunDirectory, "start-barrier.json");
  const releaseSignal = path.join(activeRunDirectory, "start-release.signal.json");
  const childScript = path.join(root, "winner", "scripts", "c1-r6b-r4d-r1-start-contender.ts");
  const children = (["broker-a", "broker-b"] as const).map((label) => ({
    label,
    ready: path.join(activeRunDirectory!, `${label}.ready.json`),
    result: path.join(activeRunDirectory!, `${label}.result.json`),
  }));
  const childPromises = children.map((child) => runChild(childScript, childEnvironment(process.env, {
    EFFECT_BROKER_T3N_API_KEY: broker.apiKey,
    EFFECT_BROKER_DID: BROKER_DID,
    C1_OPERATOR_DID: OPERATOR_DID,
    C1_R4D_R1_INCIDENT_ID: incidentId,
    C1_R4D_R1_CLAIM_ID: claimId,
    C1_R4D_R1_CONTENDER: child.label,
    C1_R4D_R1_BARRIER_FILE: releaseSignal,
    C1_R4D_R1_READY_FILE: child.ready,
    C1_R4D_R1_RESULT_FILE: child.result,
  })));
  await Promise.all(children.map((child) => waitFor(child.ready)));
  const readyDocs = await Promise.all(children.map((child) => readJsonFile<JsonObject>(child.ready)));
  const pids = readyDocs.map((doc) => doc.pid);
  const nonces = readyDocs.map((doc) => doc.start_nonce);
  const validIdentities = readyDocs.every((doc, index) => doc.incident_id === incidentId && doc.claim_id === claimId && doc.contender === children[index].label && Number.isSafeInteger(doc.pid) && doc.pid > 0 && typeof doc.start_nonce === "string" && /^[0-9a-f]{32}$/.test(doc.start_nonce)) && new Set(pids).size === 2 && new Set(nonces).size === 2;
  if (!validIdentities) {
    await persist(releaseSignal, { abort: true, incident_id: incidentId, reason: "invalid_or_duplicate_start_identity" });
    await Promise.all(childPromises);
    throw new Error("start contender identity barrier failed; begin calls were not released");
  }
  await persist(barrierPlan, { phase: "start contender barrier", incident_id: incidentId, claim_id: claimId, both_ready: true, identities_valid: true, ready_file_hash_a: await sha256File(children[0].ready), ready_file_hash_b: await sha256File(children[1].ready), pids, nonces, released_once: false });
  const releasedAt = Date.now();
  await persist(releaseSignal, { release: true, incident_id: incidentId, claim_id: claimId, released_at_unix_ms: releasedAt });
  await persist(barrierPlan, { phase: "start contender barrier", incident_id: incidentId, claim_id: claimId, both_ready: true, identities_valid: true, ready_file_hash_a: await sha256File(children[0].ready), ready_file_hash_b: await sha256File(children[1].ready), pids, nonces, released_once: true, released_at_unix_ms: releasedAt });
  await Promise.all(children.map((child) => waitFor(child.result)));
  const childStatuses = await Promise.all(childPromises);
  if (childStatuses.some((status) => status.code !== 0)) throw new Error(`start contender process failed: ${childStatuses.map((status) => status.stderr.slice(0, 300)).join(" | ")}`);
  const childResults = await Promise.all(children.map((child) => readJsonFile<JsonObject>(child.result)));
  if (childResults.some((result) => !noProvider(result))) throw new Error("start contender reported provider activity");
  const startContenders = children.map((child, index) => ({ label: child.label, ready: readyDocs[index], result: { ...childResults[index], result_file_hash: "" } }));
  for (let index = 0; index < children.length; index += 1) startContenders[index].result.result_file_hash = await sha256File(children[index].result);
  const startComplete = await persist(path.join(activeRunDirectory, "start-proposals-complete.json"), {
    phase: "both begin-effect proposals complete",
    incident_id: incidentId,
    claim_id: claimId,
    pids,
    nonces,
    result_file_hashes: startContenders.map((entry) => entry.result.result_file_hash),
    raw_begin_results: startContenders.map((entry) => entry.result.response ?? null),
    all_completed: true,
    confirmations_allowed_after_marker: true,
    completed_at_unix_ms: Date.now(),
  });

  currentStage = "confirm start owners";
  const startConfirmations: JsonObject[] = [];
  for (const contender of startContenders) {
    const expectedStartId = `start-1-${contender.ready.start_nonce}`;
    const confirmation = requireResponse(await invokeC1(broker.apiKey, broker.nodeUrl, CONTRACT_ID, "confirm-effect-start", { incident_id: incidentId, claim_id: claimId, effect_start_id: expectedStartId }), "confirm-effect-start");
    const saved = await persist(path.join(activeRunDirectory, `${contender.label}.confirmation.json`), { label: contender.label, effect_start_id: expectedStartId, called_after_complete_marker: true, response: confirmation });
    startConfirmations.push(saved);
  }
  const confirmedStarts = startConfirmations.filter((entry) => entry.response?.result === "CONFIRMED");
  if (confirmedStarts.length !== 1 || startConfirmations.some((entry) => entry.response?.result === "CONFIRMED" && entry.response?.function !== "confirm-effect-start")) throw new Error("start confirmation did not produce exactly one owner");
  const confirmedStartId = String(confirmedStarts[0].effect_start_id);

  currentStage = "effect-start readback";
  const effectStarted = requireResponse(await invokeC1OperatorSession(t3n, CONTRACT_ID, "get-incident", { incident_id: incidentId }), "get-incident", "FOUND");
  lastKnownAuthority = effectStarted;
  if (effectStarted.state !== "EFFECT_STARTED" || effectStarted.detail?.effect_attempts !== 1 || effectStarted.detail?.max_effects !== 1 || effectStarted.detail?.effect_claim_version !== 1 || effectStarted.detail?.effect_claim_id !== claimId || effectStarted.detail?.effect_start_id !== confirmedStartId || effectStarted.detail?.final_result_classification !== null) throw new Error("EFFECT_STARTED readback mismatch");
  const effectStartedFile = await persist(path.join(activeRunDirectory, "10-effect-started-readback.json"), effectStarted);
  const independent = requireResponse(await invokeC1OperatorSession((await connectTenant()).t3n, CONTRACT_ID, "get-incident", { incident_id: incidentId }), "get-incident", "FOUND");
  if (independent.state !== "EFFECT_STARTED" || independent.detail?.effect_attempts !== 1 || independent.detail?.effect_claim_id !== claimId || independent.detail?.effect_start_id !== confirmedStartId) throw new Error("independent EFFECT_STARTED readback mismatch");
  const independentFile = await persist(path.join(activeRunDirectory, "11-independent-readback.json"), independent);

  currentStage = "post-start non-reopen checks";
  const releaseAfter = await safeAttempt(broker.apiKey, broker.nodeUrl, "release-not-attempted", { incident_id: incidentId, claim_id: claimId });
  if (releaseAfter.ok && releaseAfter.response.result === "WON") throw new Error("release reopened effect authority");
  const releaseFile = await persist(path.join(activeRunDirectory, "12-release-after-start.json"), releaseAfter);
  const thirdNonce = randomBytes(16).toString("hex");
  const newBegin = await safeAttempt(broker.apiKey, broker.nodeUrl, "begin-effect", { incident_id: incidentId, claim_id: claimId, start_nonce: thirdNonce });
  if (newBegin.ok && newBegin.response.result === "WON") throw new Error("second begin established another effect start");
  let newBeginConfirmation: JsonObject | null = null;
  if (newBegin.ok && newBegin.response.detail?.effect_start_id) {
    newBeginConfirmation = await persist(path.join(activeRunDirectory, "14-new-begin-confirmation.json"), { effect_start_id: `start-1-${thirdNonce}`, called_after_complete_marker: true, response: requireResponse(await invokeC1(broker.apiKey, broker.nodeUrl, CONTRACT_ID, "confirm-effect-start", { incident_id: incidentId, claim_id: claimId, effect_start_id: `start-1-${thirdNonce}` }), "confirm-effect-start") });
    if (newBeginConfirmation.response.result === "CONFIRMED") throw new Error("second begin confirmed another owner");
  }
  const newBeginFile = await persist(path.join(activeRunDirectory, "13-new-begin.json"), newBegin);
  const freshClaimNonce = randomBytes(16).toString("hex");
  const freshClaim = await safeAttempt(broker.apiKey, broker.nodeUrl, "claim-effect", { incident_id: incidentId, expected_claim_version: 1, contender_nonce: freshClaimNonce });
  let freshClaimConfirmation: JsonObject | null = null;
  if (freshClaim.ok && freshClaim.response.result === "PROPOSED") {
    const freshClaimId = String(freshClaim.response.detail?.claim_id ?? "");
    freshClaimConfirmation = await persist(path.join(activeRunDirectory, "16-fresh-claim-confirmation.json"), { claim_id: freshClaimId, called_after_complete_marker: true, response: requireResponse(await invokeC1(broker.apiKey, broker.nodeUrl, CONTRACT_ID, "confirm-claim", { incident_id: incidentId, claim_id: freshClaimId }), "confirm-claim") });
    if (freshClaimConfirmation.response.result === "CONFIRMED") throw new Error("fresh claim confirmed another owner");
  }
  const freshClaimFile = await persist(path.join(activeRunDirectory, "15-fresh-claim.json"), freshClaim);
  const reserveAfter = await safeAttempt(remediation.apiKey, remediation.nodeUrl, RESERVATION_FUNCTION, { incident_id: incidentId });
  if (reserveAfter.ok && reserveAfter.response.result === "WON") throw new Error("reserve restored effect eligibility");
  const reserveAfterFile = await persist(path.join(activeRunDirectory, "17-reserve-after-start.json"), reserveAfter);
  const finalReadback = requireResponse(await invokeC1OperatorSession(t3n, CONTRACT_ID, "get-incident", { incident_id: incidentId }), "get-incident", "FOUND");
  lastKnownAuthority = finalReadback;
  if (finalReadback.state !== "EFFECT_STARTED" || finalReadback.detail?.effect_attempts !== 1 || finalReadback.detail?.effect_claim_id !== claimId || finalReadback.detail?.effect_start_id !== confirmedStartId || finalReadback.detail?.final_result_classification !== null) throw new Error("post-start final readback changed authority");
  const finalFile = await persist(path.join(activeRunDirectory, "18-final-readback.json"), finalReadback);

  currentStage = "role separation";
  const remediationConfirm = await safeAttempt(remediation.apiKey, remediation.nodeUrl, "confirm-effect-start", { incident_id: incidentId, claim_id: claimId, effect_start_id: confirmedStartId });
  if (remediationConfirm.ok && remediationConfirm.response.result === "CONFIRMED") throw new Error("remediation confirmed effect-start ownership");
  const remediationConfirmFile = await persist(path.join(activeRunDirectory, "19-remediation-confirm-start.json"), remediationConfirm);

  currentStage = "activity read";
  let activity: unknown = { classification: "HOST_ACTIVITY_SUPPORTING_METADATA", read_failed: true };
  try {
    const raw = await t3n.getActivityLog({ contract: CONTRACT_ID, limit: 200 });
    const rows = Array.isArray(raw) ? raw : objectAt(raw)?.entries;
    activity = { classification: "HOST_ACTIVITY_SUPPORTING_METADATA", entries: Array.isArray(rows) ? rows.map((entry: unknown) => { const row = objectAt(entry) ?? {}; const safe: JsonObject = {}; for (const key of ["seq_no", "sequence", "hash", "timestamp", "timestamp_ms", "actor", "caller", "on_behalf_of", "org", "contract", "function", "function_name", "outcome", "result"]) if (row[key] !== undefined) safe[key] = row[key]; return safe; }) : [] };
  } catch (error) {
    activity = { classification: "HOST_ACTIVITY_SUPPORTING_METADATA", read_failed: true, error: redact(error) };
  }
  const activityFile = await persist(path.join(activeRunDirectory, "20-host-activity.json"), activity);

  const bundle: JsonObject = {
    kind: "C1_R6B_R4D_R1_STATE_BUNDLE",
    phase: "C1-R6B-R4D-R1 live concurrent effect-start confirmed-owner proof",
    run_context: context,
    active_contract: { name: CONTRACT_ID, version: CONTRACT_VERSION, numeric_id: CONTRACT_NUMERIC_ID, status: inventory.status, wasm_bytes: WASM_BYTES, wasm_sha256: WASM_SHA256 },
    principals: { operator: OPERATOR_DID, remediation_agent: REMEDIATION_DID, effect_broker: BROKER_DID, organization: ORGANISATION_DID, all_distinct: true },
    configuration: { map_acl: { private: true, contract_id: CONTRACT_NUMERIC_ID, lifecycle_status: mapStatus, acl_metadata_exposed_by_sdk: false, acl_basis: "retained activation evidence" }, delegations: { remediation: { did: REMEDIATION_DID, functions: [RESERVATION_FUNCTION], scopes: [], allowed_hosts: [], version_req: CONTRACT_VERSION }, broker: { did: BROKER_DID, functions: [...BROKER_FUNCTIONS], scopes: [], allowed_hosts: [], version_req: CONTRACT_VERSION } } },
    quota_readiness: { ...quotaReadiness, wait_before_state_run: true, pacing_wait_ms: PACING_MS },
    create: createFile,
    initial_active_readback: initialFile,
    reservation: { response: reserveFile, readback: reservedFile },
    claim_owner: { proposal: claimProposalFile, confirmation: claimConfirmationFile, readback: claimReadbackFile },
    start_barrier: await readJsonFile<JsonObject>(barrierPlan),
    start_contenders: startContenders,
    start_proposals_complete: startComplete,
    start_confirmations: startConfirmations,
    effect_started_readback: effectStartedFile,
    independent_readback: independentFile,
    post_start: { release: releaseFile, new_begin: newBeginFile, new_begin_confirmation: newBeginConfirmation, fresh_claim: freshClaimFile, fresh_claim_confirmation: freshClaimConfirmation, reserve_after: reserveAfterFile, final_readback: finalFile },
    role_separation: { remediation_confirm_start: remediationConfirmFile },
    activity: activityFile,
    provider_helpers_imported: false,
    provider_counters: { github_api_calls: 0, installation_tokens: 0, deploy_key_creates: 0, deploy_key_deletes: 0, provider_mutations: 0 },
    historical_incidents_untouched: true,
    limitations: ["This is a state-only proof; no GitHub/provider operation was attempted.", "Host activity is supporting metadata only and does not prove request-body binding or a Merkle receipt.", "The provider-backed C1 effect remains a separate gate."],
  };
  const bundleFile = await persist(path.join(activeRunDirectory, "bundle.json"), bundle);
  const verdict = verifyBundle(bundleFile);
  await persist(path.join(activeRunDirectory, "offline-verifier.json"), verdict);
  if (!verdict.ok) throw new Error(`offline verifier rejected live bundle: ${verdict.errors.join("; ")}`);
  const passArtifact = { ...bundleFile, status: "C1_R6B_R4D_R1_CONCURRENT_EFFECT_START_PASS", classification: "LIVE_TWO_PROCESS_CONFIRMED_EFFECT_START_OWNER_PASS", readiness_probe_id: readinessProbeId, readiness_result_file: relativeEvidence(readiness.resultFile), readiness_classification: "R4D_R1_READINESS_PASS", source: { r4d: "single-start live proof", r4d_r1: "two-physical-contender concurrency proof" }, new_live_calls: { t3n_reads: "recorded in this proof", t3n_writes: "recorded in this proof", provider_operations: 0 }, credential_safety: { t3n_api_keys: false, github_tokens: false, jwt: false, authorization_headers: false, private_keys: false }, next_gate: "C1-R6B-R4E-R1 — FRESH TARGET + PROVIDER-BACKED V2.0.4 CONFIRMED-OWNER EXECUTION" };
  await writeAtomicJson(path.join(root, "winner", "evidence", "C1-R6B-R4D-R1-CONCURRENT-EFFECT-START-PROOF.json"), passArtifact);
  console.log(JSON.stringify({ status: passArtifact.status, classification: passArtifact.classification, run_id: runId, incident_id: incidentId, confirmed_start_id: confirmedStartId, provider_operations: 0 }, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(async (error) => {
    const failure = { phase: "C1-R6B-R4D-R1 live concurrent effect-start proof", status: "C1_R6B_R4D_R1_FAILURE", stage: currentStage, incident_id: activeIncidentId, run_directory: activeRunDirectory ? path.relative(root, activeRunDirectory).replaceAll("\\", "/") : null, state_changing_request_may_have_been_sent: activeIncidentId !== null, last_known_authority: lastKnownAuthority, error: redact(error), no_automatic_retry: true, provider_counters: { github_api_calls: 0, installation_tokens: 0, deploy_key_creates: 0, deploy_key_deletes: 0, provider_mutations: 0 }, historical_incidents_untouched: true };
    if (!readinessFailureWritten) await writeAtomicJson(path.join(root, "winner", "evidence", "C1-R6B-R4D-R1-Q1-STATE-FAILURE.json"), failure);
    console.error(JSON.stringify({ status: failure.status, stage: failure.stage, incident_id: failure.incident_id, error: failure.error }, null, 2));
    process.exitCode = 1;
  });
}
