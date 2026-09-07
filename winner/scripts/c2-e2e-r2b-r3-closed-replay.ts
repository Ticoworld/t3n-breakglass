import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { execFile as execFileCallback, spawn } from "node:child_process";
import { promisify } from "node:util";
import os from "node:os";
import path from "node:path";
import { adjudicateClosedReplayBrokerResult, closedTerminalAuthorityProjection, closedTerminalAuthorityUnchanged } from "../c2/closed-replay-adjudication.js";
import { connectTenant } from "../../scripts/lib.js";
import { invokeC1, invokeC1OperatorSession, connectC1Principal, redact } from "./t3n.js";
import { CONTRACT_VERSION, RESERVATION_FUNCTION, contractName } from "./constants.js";
import { writeAtomicJson } from "./result-file.js";

const execFile = promisify(execFileCallback);
const root = path.resolve(import.meta.dirname, "../..");
const EXPECTED_MAIN_SHA = "4a077035474337b7a1ad16204820e68ed3020477";
const EXPECTED_OPERATOR_DID = "did:t3n:adb9365ee986cc6d0cb4006580782fe6fc7a431f";
const EXPECTED_REMEDIATION_DID = "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019";
const EXPECTED_BROKER_DID = "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57";
const HISTORICAL_POLICY_ID = "c2-policy:github-push-c2-e2e-r2-1788774247501-aac76008bd86";
const HISTORICAL_INCIDENT_ID = "C2-c2-policy:github-push-c2-e2e-r2-1788774247501-aac76008bd86-a342e0161cb466d736e34bb3";
const HISTORICAL_TARGET_ID = 162525303;
const R2B_R2_FAILURE = "winner/evidence/C2-E2E-R2B-R2-FAILURE.json";
const R2B_R1_FAILURE = "winner/evidence/C2-E2E-R2B-R1-FAILURE.json";
const R2_POLICY_RETIREMENT = "winner/evidence/C2-E2E-R2-POLICY-RETIREMENT.json";
const R2A_ADJUDICATION = "winner/evidence/C2-E2E-R2A-HISTORICAL-ADJUDICATION.json";
const OUTPUT_EVIDENCE = "winner/evidence/C2-E2E-R2B-R3-CLOSED-REPLAY.json";
const SHA_RE = /^[0-9a-f]{40}$/i;

type JsonObject = Record<string, any>;
type ChildResult = { code: number; stderr: string };

function object(value: unknown): JsonObject {
  return value && typeof value === "object" && !Array.isArray(value) ? value as JsonObject : {};
}

function requireCondition(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function parseJson<T = unknown>(value: string): T {
  return JSON.parse(value) as T;
}

function envLine(contents: string, name: string): string {
  const line = contents.split(/\r?\n/).find((entry) => entry.startsWith(`${name}=`));
  requireCondition(line, `${name} is missing from environment file`);
  const value = line.slice(name.length + 1).trim().replace(/^['"]|['"]$/g, "");
  requireCondition(value, `${name} is empty in environment file`);
  return value;
}

async function envFileValue(file: string, name: string): Promise<string> {
  return envLine(await readFile(path.join(root, file), "utf8"), name);
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

async function waitFor(file: string, timeoutMs = 120_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!existsSync(file)) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${path.basename(file)}`);
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
}

function runChild(script: string, args: string[], environment: NodeJS.ProcessEnv): Promise<ChildResult> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--import", "tsx", script, ...args], { cwd: root, env: environment, windowsHide: true, stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (chunk) => { stderr += String(chunk); });
    child.on("close", (code) => resolve({ code: code ?? 1, stderr }));
  });
}

async function getClosedIncident(operator: Awaited<ReturnType<typeof connectTenant>>): Promise<JsonObject> {
  const response = object(await invokeC1OperatorSession(operator.t3n, contractName(operator.tenantDid), "get-incident", { incident_id: HISTORICAL_INCIDENT_ID }));
  const detail = object(response.detail);
  requireCondition(response.result === "FOUND" && response.state === "CLOSED" && (response.effect_attempts ?? detail.effect_attempts) === 1 && (response.final_result_classification ?? detail.final_result_classification) === "VERIFIED_ABSENT" && (response.deploy_key_id ?? detail.deploy_key_id) === HISTORICAL_TARGET_ID, "historical incident is not CLOSED/VERIFIED_ABSENT with the expected target");
  requireCondition(adjudicateClosedReplayBrokerResult(response, { contender: "precondition-only", claim_outcome: "CLAIM_DENIED", claim: { result: "DENIED", function: "claim-effect", state: "CLOSED", detail: {}, note: "incident expired according to cluster time" }, token_minted: false, provider_credential_mint_count: 0, destructive_call_count: 0, delete_attempted: false, provider_calls_after_ownership_loss: 0 }).reason === "incident expired according to cluster time", "terminal-before did not satisfy the canonical CLOSED replay precondition");
  return response;
}

async function main(): Promise<void> {
  const liveStart = process.env.C2_E2E_R2B_R3_LIVE_START_SHA;
  requireCondition(liveStart && SHA_RE.test(liveStart), "C2_E2E_R2B_R3_LIVE_START_SHA must be supplied after the repair freeze commit");
  const currentHead = (await execFile("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" })).stdout.trim();
  const originHead = (await execFile("git", ["rev-parse", "origin/winner-v2-core"], { cwd: root, encoding: "utf8" })).stdout.trim();
  const mainSha = (await execFile("git", ["rev-parse", "origin/main"], { cwd: root, encoding: "utf8" })).stdout.trim();
  requireCondition(currentHead === liveStart && originHead === liveStart, "R2B-R3 live-start checkpoint is not equal to local and origin winner-v2-core");
  requireCondition(mainSha === EXPECTED_MAIN_SHA, "origin/main changed");
  requireCondition((await execFile("git", ["status", "--porcelain"], { cwd: root, encoding: "utf8" })).stdout.trim() === "", "R2B-R3 live-start worktree is not clean");

  const r2bR1 = parseJson<JsonObject>(await readFile(path.join(root, R2B_R1_FAILURE), "utf8"));
  const r2bR2 = parseJson<JsonObject>(await readFile(path.join(root, R2B_R2_FAILURE), "utf8"));
  const retirement = parseJson<JsonObject>(await readFile(path.join(root, R2_POLICY_RETIREMENT), "utf8"));
  const r2a = parseJson<JsonObject>(await readFile(path.join(root, R2A_ADJUDICATION), "utf8"));
  requireCondition(r2bR1.classification === "C2_E2E_R2B_R1_REDELIVERY_REQUEST_FAILED_HTTP_404" && r2bR2.classification === "C2_E2E_R2B_R2_FAIL_CLOSED_REPLAY_BROKER_ADJUDICATION_INDETERMINATE", "historical R2B failure artifacts are not preserved");
  requireCondition(retirement.policy_id === HISTORICAL_POLICY_ID && retirement.policy_version === 2 && retirement.deploy_key_id === HISTORICAL_TARGET_ID && retirement.retired === true, "historical R2 policy is not proven retired");
  requireCondition(r2a.classification === "C2_E2E_R2A_HISTORICAL_CORE_ADJUDICATION_PASS" && r2a.historical_r2?.policy_retired === true, "historical R2A adjudication is not preserved");

  const operatorKey = await envFileValue(".env.bootstrap", "T3N_API_KEY");
  const remediationKey = await envFileValue(".env.replacement-agent", "REPLACEMENT_AGENT_T3N_API_KEY");
  const brokerKey = await envFileValue(".env.effect-broker", "EFFECT_BROKER_T3N_API_KEY");
  process.env.T3N_API_KEY = operatorKey;
  let brokerDirectory: string | undefined;
  try {
    const operator = await connectTenant();
    requireCondition(operator.tenantDid === EXPECTED_OPERATOR_DID, "operator DID mismatch");
    const terminalBefore = await getClosedIncident(operator);
    // The principal guard must never see the operator credential while the
    // remediation principal is being authenticated.  The operator client is
    // already connected and retains its own session/signing state.
    delete process.env.T3N_API_KEY;

    process.env.REPLACEMENT_AGENT_T3N_API_KEY = remediationKey;
    process.env.REMEDIATION_DID = EXPECTED_REMEDIATION_DID;
    const remediation = await connectC1Principal("REPLACEMENT_AGENT_T3N_API_KEY", "REMEDIATION_DID");
    const reserve = object(await invokeC1(remediation.apiKey, remediation.nodeUrl, contractName(operator.tenantDid), RESERVATION_FUNCTION, { incident_id: HISTORICAL_INCIDENT_ID }));
    requireCondition(reserve.result !== "WON", "closed incident reserve replay unexpectedly won");
    delete process.env.REPLACEMENT_AGENT_T3N_API_KEY;
    delete process.env.REMEDIATION_DID;
    delete process.env.T3N_API_KEY;

    brokerDirectory = await mkdtemp(path.join(os.tmpdir(), "t3n-c2-e2e-r2b-r3-broker-"));
    const barrier = path.join(brokerDirectory, "claim-release.json");
    const proposals = path.join(brokerDirectory, "proposals-complete.json");
    const ready = path.join(brokerDirectory, "ready.json");
    const resultFile = path.join(brokerDirectory, "result.json");
    await writeFile(proposals, JSON.stringify({ incident_id: HISTORICAL_INCIDENT_ID, replay_only: true }));

    const environment: NodeJS.ProcessEnv = { ...process.env };
    for (const key of Object.keys(environment)) {
      if (key.startsWith("GITHUB_") || key === "T3N_API_KEY" || key === "REPLACEMENT_AGENT_T3N_API_KEY" || key === "C2_WEBHOOK_SECRET") delete environment[key];
    }
    Object.assign(environment, {
      EFFECT_BROKER_T3N_API_KEY: brokerKey,
      EFFECT_BROKER_DID: EXPECTED_BROKER_DID,
      C1_OPERATOR_DID: EXPECTED_OPERATOR_DID,
      C1_EXPECTED_CLAIM_VERSION: String(object(terminalBefore.detail).effect_claim_version ?? terminalBefore.effect_claim_version ?? 1),
      C1_BARRIER_FILE: barrier,
      C1_PROPOSALS_COMPLETE_FILE: proposals,
      C1_READY_FILE: ready,
      C1_RESULT_FILE: resultFile,
      C1_CONTENDER_ID: "r2b-r3-closed-replay",
      C1_EFFECT_START_READY_FILE: "",
      C1_PRE_DELETE_RELEASE_FILE: "",
    });
    const childPromise = runChild(path.join(root, "winner/broker/run.ts"), [HISTORICAL_INCIDENT_ID], environment);
    await waitFor(ready);
    await writeFile(barrier, JSON.stringify({ incident_id: HISTORICAL_INCIDENT_ID, released_once: true }));
    await waitFor(resultFile);
    const child = await childPromise;
    const broker = parseJson<JsonObject>(await readFile(resultFile, "utf8"));
    requireCondition(child.code === 0, `closed replay broker failed: ${redact(child.stderr, [brokerKey])}`);
    const adjudication = adjudicateClosedReplayBrokerResult(terminalBefore, broker);
    requireCondition(adjudication.valid && adjudication.state === "SAFE_CLOSED_REPLAY_DENIED", `closed replay broker adjudication failed: ${adjudication.reason}`);

    process.env.T3N_API_KEY = operatorKey;
    const terminalAfter = await getClosedIncident(operator);
    delete process.env.T3N_API_KEY;
    requireCondition(closedTerminalAuthorityUnchanged(terminalBefore, terminalAfter), "closed incident terminal authority changed during replay");

    const evidence = {
      classification: "C2_E2E_R2B_R3_CLOSED_REPLAY_PASS",
      live_start_sha: liveStart,
      main_sha: mainSha,
      historical_r2: { incident_id: HISTORICAL_INCIDENT_ID, policy_id: HISTORICAL_POLICY_ID, target_id: HISTORICAL_TARGET_ID, classification: "C2_E2E_R2_FAIL_BROKER_OWNER_EVIDENCE_ADJUDICATION" },
      historical_r2b: { r2b_r1_failure: R2B_R1_FAILURE, r2b_r2_failure: R2B_R2_FAILURE, r2b_r2_classification: r2bR2.classification },
      retired_policy_evidence: { policy_retirement: R2_POLICY_RETIREMENT, r2a_adjudication: R2A_ADJUDICATION, policy_id: HISTORICAL_POLICY_ID, policy_version: 2, retired: true },
      terminal_before: sanitize(terminalBefore, [operatorKey, remediationKey, brokerKey]),
      remediation_reserve_replay: sanitize(reserve, [operatorKey, remediationKey, brokerKey]),
      production_broker: sanitize(broker, [operatorKey, remediationKey, brokerKey]),
      broker_claim_outcome: broker.claim_outcome ?? null,
      raw_claim: sanitize(broker.claim, [operatorKey, remediationKey, brokerKey]),
      closed_replay_adjudication: adjudication,
      provider_boundary_counters: { token_minted: broker.token_minted, provider_credential_mint_count: broker.provider_credential_mint_count, destructive_call_count: broker.destructive_call_count, delete_count: broker.delete_count ?? 0, delete_attempted: broker.delete_attempted, provider_calls_after_ownership_loss: broker.provider_calls_after_ownership_loss, effect_token_present: Object.prototype.hasOwnProperty.call(broker, "effect_token"), github_calls: 0, webhook_redelivery_posts: 0, provider_token_mints: 0, provider_mutations: 0, deletes: 0 },
      terminal_after: sanitize(terminalAfter, [operatorKey, remediationKey, brokerKey]),
      terminal_projection_before: closedTerminalAuthorityProjection(terminalBefore),
      terminal_projection_after: closedTerminalAuthorityProjection(terminalAfter),
      terminal_unchanged: true,
      t3n_contract_calls: 4,
      github_webhook_redelivery_posts: 0,
      sensitive_value_hygiene: { broker_result_sanitized: true, credentials_in_evidence: false, github_calls: 0, raw_webhook_body: false, webhook_secret: false, provider_token: false },
      tests: { closed_replay_adjudication: "PASS", terminal_before: "PASS", terminal_after_unchanged: "PASS", provider_boundary: "PASS", normal_race_denied_strictness: "PASS" },
      claims_earned: ["an independently read CLOSED/VERIFIED_ABSENT incident rejected remediation replay", "the elapsed CLOSED claim denial was distinguished from normal race ownership loss", "the replay broker minted zero provider credentials and performed zero provider mutation", "terminal authority remained unchanged"],
      claims_forbidden: ["R2 PASS", "R2B-R2 PASS", "another GitHub redelivery", "new causal event or authority", "GitHub exactly-once", "T3N/GitHub atomicity", "submission readiness"],
    };
    await writeAtomicJson(path.join(root, OUTPUT_EVIDENCE), evidence);
    await rm(brokerDirectory, { recursive: true, force: true });
    brokerDirectory = undefined;
    process.stdout.write(`${JSON.stringify({ classification: evidence.classification, live_start_sha: liveStart, incident_id: HISTORICAL_INCIDENT_ID, closed_replay_state: adjudication.state, terminal_unchanged: true, github_webhook_redelivery_posts: 0, provider_mutations: 0, evidence: OUTPUT_EVIDENCE })}\n`);
  } finally {
    delete process.env.T3N_API_KEY;
    delete process.env.REPLACEMENT_AGENT_T3N_API_KEY;
    delete process.env.REMEDIATION_DID;
    if (brokerDirectory) process.stderr.write(`R2B-R3 broker result retained in OS_TEMP replay directory after stop: ${path.basename(brokerDirectory)}\n`);
  }
}

main().catch((error) => {
  process.stderr.write(`C2-E2E-R2B-R3 closed replay stopped: ${redact(error)}\n`);
  process.exitCode = 1;
});
