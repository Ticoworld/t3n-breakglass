import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { execFile as execFileCallback, spawn } from "node:child_process";
import { promisify } from "node:util";
import os from "node:os";
import path from "node:path";
import { appConfigFromEnvironment, appJwt } from "../broker/github-app.js";
import { adjudicateBrokerResult } from "../c2/broker-adjudication.js";
import { parseGithubDeliveryList, parseGithubDeliveryObject, selectOriginalDelivery, selectRedelivery, unsafeNumberRoundtripChangesId, type LosslessGithubDelivery } from "../c2/github-delivery-json.js";
import { evaluateGithubAppWebhookReadiness, type GithubAppWebhookReadinessFacts } from "../c2/github-app-webhook-readiness.js";
import { processPushWebhook } from "../c2/push-ingress.js";
import { createR2BReplayWebhookServer, type R2BReplayCapture, type R2BReplayServerHandle } from "../c2/replay-webhook-server.js";
import { connectTenant } from "../../scripts/lib.js";
import { invokeC1, invokeC1OperatorSession, connectC1Principal, redact } from "./t3n.js";
import { CONTRACT_VERSION, RESERVATION_FUNCTION, contractName } from "./constants.js";
import { writeAtomicJson } from "./result-file.js";

const execFile = promisify(execFileCallback);
const root = path.resolve(import.meta.dirname, "../..");
const API = "https://api.github.com";
const API_VERSION = "2022-11-28";
const APP_ID = 4793116;
const INSTALLATION_ID = 158227303;
const SANDBOX_OWNER = "Ticoworld";
const SANDBOX_REPOSITORY = "t3n-breakglass-sandbox";
const SANDBOX_REPOSITORY_ID = 1350596128;
const SANDBOX_REF = "refs/heads/c2-breakglass-demo";
const HISTORICAL_DELIVERY_ID = "c1278f3a-aaa0-11f1-9f5f-1f10261aa34b";
const HISTORICAL_RAW_BODY_SHA256 = "e542fbd83a0ed290440e626eba03abf03b29ea5567ee2c30c8fc6b8d369ba6c7";
const HISTORICAL_BEFORE = "d0338f9f4b9ab0c2823b1d59c59a5caa40968fa5";
const HISTORICAL_AFTER = "f4fbebf7349821b857ab1ffa83b6f9637dcba35e";
const HISTORICAL_POLICY_ID = "c2-policy:github-push-c2-e2e-r2-1788774247501-aac76008bd86";
const HISTORICAL_INCIDENT_ID = "C2-c2-policy:github-push-c2-e2e-r2-1788774247501-aac76008bd86-a342e0161cb466d736e34bb3";
const HISTORICAL_TARGET_ID = 162525303;
const R2_STARTING_SHA = "3a0d7aa601920bdd7be716dbe8acd31714b32f0c";
const REQUIRED_LIVE_START_ENV = "C2_E2E_R2B_LIVE_START_SHA";
const WEBHOOK_ROUTE = "/c2-b0/github-push";
const EXPECTED_B0_EVIDENCE = "winner/evidence/C2-B0-LIVE-INGRESS-DELIVERY.json";
const FAILURE_EVIDENCE = "winner/evidence/C2-E2E-R2-FAILURE.json";
const RETIREMENT_EVIDENCE = "winner/evidence/C2-E2E-R2-POLICY-RETIREMENT.json";
const R2A_EVIDENCE = "winner/evidence/C2-E2E-R2A-HISTORICAL-ADJUDICATION.json";
const OUTPUT_EVIDENCE = "winner/evidence/C2-E2E-R2B-SAME-EVENT-REPLAY.json";
const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SHA_RE = /^[0-9a-f]{40}$/i;

type JsonObject = Record<string, any>;
type ApiResult = { status: number; text: string; body: unknown; headers: Record<string, string> };
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

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function safeBodyMetadata(value: unknown): JsonObject | null {
  const body = object(value);
  if (Object.keys(body).length === 0) return null;
  const output: JsonObject = {};
  for (const key of ["id", "slug", "name", "repository_selection", "permissions", "events", "active", "url", "content_type", "insecure_ssl", "guid", "event", "delivered_at", "installation_id", "repository_id", "redelivery", "status", "status_code", "duration", "response_code"]) {
    if (body[key] !== undefined) output[key] = body[key];
  }
  return output;
}

function safeApiResponse(response: ApiResult): JsonObject {
  return { http_status: response.status, response_headers: response.headers, body_metadata: safeBodyMetadata(response.body) };
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

async function githubRequest(token: string, route: string, init: RequestInit = {}): Promise<ApiResult> {
  const response = await fetch(`${API}${route}`, {
    ...init,
    redirect: "error",
    signal: AbortSignal.timeout(60_000),
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": API_VERSION,
      "User-Agent": "t3n-breakglass-c2-e2e-r2b-replay",
      ...(init.headers ?? {}),
    },
  });
  const text = await response.text();
  let body: unknown = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = null; }
  const headers: Record<string, string> = {};
  for (const name of ["date", "etag", "x-github-request-id", "x-ratelimit-remaining"]) {
    const value = response.headers.get(name);
    if (value) headers[name] = value;
  }
  return { status: response.status, text, body, headers };
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

function listen(server: R2BReplayServerHandle["server"], port: number, host: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const onError = (error: Error) => { server.off("listening", onListening); reject(error); };
    const onListening = () => { server.off("error", onError); resolve(); };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, host);
  });
}

function terminalProjection(response: JsonObject): JsonObject {
  const detail = object(response.detail);
  const fields = ["action", "github_owner", "github_repo", "deploy_key_id", "remediation_agent_did", "effect_broker_did", "effect_attempts", "effect_claim_id", "effect_claim_version", "effect_start_id", "final_result_classification", "claim_id", "claim_version"];
  const projected: JsonObject = { function: response.function ?? null, result: response.result ?? null, state: response.state ?? null };
  for (const key of fields) if (response[key] !== undefined) projected[key] = response[key];
  projected.detail = {};
  for (const key of fields) if (detail[key] !== undefined) projected.detail[key] = detail[key];
  return projected;
}

async function hashFile(file: string): Promise<string> {
  return sha256(await readFile(file));
}

async function findDurableReceipt(): Promise<{ file: string; record: JsonObject; sha256: string }> {
  const rootTemp = os.tmpdir();
  const candidates: Array<{ file: string; record: JsonObject }> = [];
  const runDirectories = (await readdir(rootTemp, { withFileTypes: true })).filter((entry) => entry.isDirectory() && entry.name.startsWith("t3n-c2-e2e-r2-run-"));
  for (const runDirectory of runDirectories) {
    const dedupeDirectory = path.join(rootTemp, runDirectory.name, "dedupe");
    let files: string[] = [];
    try { files = (await readdir(dedupeDirectory)).filter((name) => name.endsWith(".json")); } catch { continue; }
    for (const fileName of files) {
      const file = path.join(dedupeDirectory, fileName);
      try {
        const record = parseJson<JsonObject>(await readFile(file, "utf8"));
        const identity = object(record.event_identity);
        if (record.state === "ACCEPTED" && record.decision === "C2_PUSH_SELECTED" && record.source_event_digest === HISTORICAL_RAW_BODY_SHA256 && record.source_event_id === `${HISTORICAL_DELIVERY_ID}:push:${SANDBOX_REPOSITORY_ID}:${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}` && identity.delivery_id === HISTORICAL_DELIVERY_ID && identity.event_type === "push" && identity.repository_full_name === `${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}` && record.policy_id === HISTORICAL_POLICY_ID && record.policy_version === 2 && record.derived_incident_id === HISTORICAL_INCIDENT_ID) {
          candidates.push({ file, record });
        }
      } catch { /* ignore unrelated or incomplete temp records */ }
    }
  }
  requireCondition(candidates.length === 1, `expected exactly one matching durable R2 receipt, found ${candidates.length}`);
  const found = candidates[0];
  const request = object(found.record.create_request);
  requireCondition(Object.keys(request).sort().join(",") === "deploy_key_id,effect_broker_did,incident_id,remediation_agent_did,ttl_secs", "historical receipt create_request schema is not exact");
  requireCondition(request.incident_id === HISTORICAL_INCIDENT_ID && request.deploy_key_id === HISTORICAL_TARGET_ID && request.ttl_secs === 900, "historical receipt create_request identity is not exact");
  return { ...found, sha256: await hashFile(found.file) };
}

async function readAppConfiguration(jwt: string, expectedWebhookUrl: string): Promise<{ facts: Omit<GithubAppWebhookReadinessFacts, "tunnel" | "receiver">; evidence: JsonObject }> {
  const app = await githubRequest(jwt, "/app");
  const installation = await githubRequest(jwt, `/app/installations/${INSTALLATION_ID}`);
  const hook = await githubRequest(jwt, "/app/hook/config");
  const appBody = object(app.body);
  const installBody = object(installation.body);
  const appPermissions = object(appBody.permissions);
  const installPermissions = object(installBody.permissions);
  const events = Array.isArray(appBody.events) ? appBody.events : [];
  const hookBody = object(hook.body);
  return {
    facts: {
      expected_url: expectedWebhookUrl,
      app: { http_status: app.status, id: Number.isSafeInteger(Number(appBody.id)) ? Number(appBody.id) : null, slug: typeof appBody.slug === "string" ? appBody.slug : null, permissions: appPermissions, events },
      installation: { http_status: installation.status, id: Number.isSafeInteger(Number(installBody.id)) ? Number(installBody.id) : null, repository_selection: typeof installBody.repository_selection === "string" ? installBody.repository_selection : null, permissions: installPermissions },
      hook: { http_status: hook.status, url: typeof hookBody.url === "string" ? hookBody.url : null, content_type: typeof hookBody.content_type === "string" ? hookBody.content_type : null, insecure_ssl: typeof hookBody.insecure_ssl === "string" || typeof hookBody.insecure_ssl === "number" ? hookBody.insecure_ssl : null },
    },
    evidence: {
    app: safeApiResponse(app),
    installation: safeApiResponse(installation),
    hook: { http_status: hook.status, configured: hook.status === 200, url_origin: typeof hookBody.url === "string" ? new URL(hookBody.url).origin : null, route: typeof hookBody.url === "string" ? new URL(hookBody.url).pathname : null, content_type: hookBody.content_type ?? null, insecure_ssl: hookBody.insecure_ssl ?? null, secret_persisted: false },
    permissions: { app: appPermissions, installation: installPermissions },
    events,
    repository_selection: installBody.repository_selection,
    },
  };
}

async function tunnelReadiness(expectedOrigin: string): Promise<GithubAppWebhookReadinessFacts["tunnel"]> {
  let apiStatus: number | null = null;
  let publicOrigin: string | null = null;
  let forwardingAddress: string | null = null;
  let publicProbeStatus: number | null = null;
  try {
    const response = await fetch("http://127.0.0.1:4040/api/tunnels", { signal: AbortSignal.timeout(15_000) });
    apiStatus = response.status;
    const body = object(await response.json());
    const tunnels = Array.isArray(body.tunnels) ? body.tunnels.map((entry) => object(entry)) : [];
    const tunnel = tunnels.find((entry) => entry.public_url === expectedOrigin || String(entry.public_url ?? "").replace(/\/$/, "") === expectedOrigin);
    if (tunnel) {
      publicOrigin = typeof tunnel.public_url === "string" ? tunnel.public_url.replace(/\/$/, "") : null;
      forwardingAddress = typeof object(tunnel.config).addr === "string" ? object(tunnel.config).addr : null;
      try { publicProbeStatus = (await fetch(`${expectedOrigin}${WEBHOOK_ROUTE}`, { method: "GET", signal: AbortSignal.timeout(30_000) })).status; } catch { publicProbeStatus = null; }
    }
  } catch { /* readiness helper returns an endpoint-unreachable classification */ }
  return { ngrok_api_http_status: apiStatus, public_origin: publicOrigin, forwarding_address: forwardingAddress, public_route_probe_http_status: publicProbeStatus };
}

const HISTORICAL_DELIVERY_QUERY = {
  guid: HISTORICAL_DELIVERY_ID,
  event: "push",
  installation_id: INSTALLATION_ID,
  repository_id: SANDBOX_REPOSITORY_ID,
} as const;

function deliverySucceeded(row: LosslessGithubDelivery): boolean {
  return String(row.status ?? "").toUpperCase() === "OK" && [200, 202].includes(row.status_code ?? row.response_code ?? -1);
}

function requireDeliveryIdentity(row: LosslessGithubDelivery, expectedRedelivery: boolean): void {
  requireCondition(row.guid === HISTORICAL_DELIVERY_ID && row.event === "push", "delivery history identity does not match the historical event");
  requireCondition(row.installation_id === INSTALLATION_ID && row.repository_id === SANDBOX_REPOSITORY_ID, "delivery history repository/installation identity is not exact");
  requireCondition(row.redelivery === expectedRedelivery, "delivery history redelivery flag is not exact");
}

async function originalDelivery(jwt: string): Promise<JsonObject> {
  const response = await githubRequest(jwt, "/app/hook/deliveries?per_page=100");
  requireCondition(response.status === 200, `historical original delivery list failed HTTP ${response.status}`);
  const rows = parseGithubDeliveryList(response.text);
  const row = selectOriginalDelivery(rows, HISTORICAL_DELIVERY_QUERY);
  requireDeliveryIdentity(row, false);
  requireCondition(typeof row.id === "string" && /^[0-9]+$/.test(row.id), "historical original delivery ID is not an exact decimal string");

  const detail = await githubRequest(jwt, `/app/hook/deliveries/${encodeURIComponent(row.id)}`);
  requireCondition(detail.status === 200, `exact historical delivery GET failed HTTP ${detail.status}`);
  const detailRow = parseGithubDeliveryObject(detail.text);
  requireDeliveryIdentity(detailRow, false);
  requireCondition(detailRow.id === row.id, "historical detail delivery ID does not equal the lossless list delivery ID");
  requireCondition(deliverySucceeded(row) && deliverySucceeded(detailRow), "historical original delivery was not a successful receiver delivery");
  return {
    list_http_status: response.status,
    detail_http_status: detail.status,
    original_delivery_id_exact: row.id,
    guid: row.guid,
    event: row.event,
    repository_id: row.repository_id,
    installation_id: row.installation_id,
    delivered_at: row.delivered_at ?? detailRow.delivered_at ?? null,
    status: row.status ?? detailRow.status ?? null,
    status_code: row.status_code ?? row.response_code ?? detailRow.status_code ?? detailRow.response_code ?? null,
    redelivery: false,
  };
}

async function waitForRedeliveryHistory(jwt: string, originalDeliveryIdExact: string): Promise<JsonObject> {
  const deadline = Date.now() + 120_000;
  while (Date.now() <= deadline) {
    const response = await githubRequest(jwt, "/app/hook/deliveries?per_page=100");
    if (response.status !== 200) {
      await new Promise((resolve) => setTimeout(resolve, 1_000));
      continue;
    }
    const rows = parseGithubDeliveryList(response.text);
    const matching = rows.filter((row) => row.guid === HISTORICAL_DELIVERY_ID && row.event === "push" && row.installation_id === INSTALLATION_ID && row.repository_id === SANDBOX_REPOSITORY_ID && row.redelivery === true && row.id !== originalDeliveryIdExact);
    if (matching.length > 0) {
      const row = selectRedelivery(rows, HISTORICAL_DELIVERY_QUERY, originalDeliveryIdExact);
      requireDeliveryIdentity(row, true);
      requireCondition(typeof row.id === "string" && /^[0-9]+$/.test(row.id), "redelivery ID is not an exact decimal string");
      const detail = await githubRequest(jwt, `/app/hook/deliveries/${encodeURIComponent(row.id)}`);
      requireCondition(detail.status === 200, `exact redelivery history GET failed HTTP ${detail.status}`);
      const detailRow = parseGithubDeliveryObject(detail.text);
      requireDeliveryIdentity(detailRow, true);
      requireCondition(detailRow.id === row.id, "redelivery detail ID does not equal the lossless list delivery ID");
      requireCondition(deliverySucceeded(row) && deliverySucceeded(detailRow), "redelivery history was not successful");
      return { list_http_status: response.status, detail_http_status: detail.status, redelivery_delivery_id_exact: row.id, guid: row.guid, event: row.event, repository_id: row.repository_id, installation_id: row.installation_id, delivered_at: row.delivered_at ?? detailRow.delivered_at ?? null, status: row.status ?? detailRow.status ?? null, status_code: row.status_code ?? row.response_code ?? detailRow.status_code ?? detailRow.response_code ?? null, redelivery: true, original_delivery_id_exact: originalDeliveryIdExact };
    }
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  throw new Error("timed out waiting for GitHub redelivery history");
}

async function closedIncidentReplay(): Promise<{ before: JsonObject; reserve: JsonObject; broker: JsonObject; adjudication: JsonObject; after: JsonObject; t3n_calls: number }> {
  const operatorKey = await envFileValue(".env.bootstrap", "T3N_API_KEY");
  process.env.T3N_API_KEY = operatorKey;
  const connected = await connectTenant();
  requireCondition(connected.tenantDid === "did:t3n:adb9365ee986cc6d0cb4006580782fe6fc7a431f", "operator DID mismatch");
  const getIncident = async (): Promise<JsonObject> => {
    const response = object(await invokeC1OperatorSession(connected.t3n, contractName(connected.tenantDid), "get-incident", { incident_id: HISTORICAL_INCIDENT_ID }));
    const detail = object(response.detail);
    requireCondition(response.result === "FOUND" && response.state === "CLOSED" && (response.effect_attempts ?? detail.effect_attempts) === 1 && (response.final_result_classification ?? detail.final_result_classification) === "VERIFIED_ABSENT" && (response.deploy_key_id ?? detail.deploy_key_id) === HISTORICAL_TARGET_ID, "historical incident is not the expected CLOSED/VERIFIED_ABSENT record");
    return response;
  };
  const before = await getIncident();
  delete process.env.T3N_API_KEY;

  const remediationKey = await envFileValue(".env.replacement-agent", "REPLACEMENT_AGENT_T3N_API_KEY");
  process.env.REPLACEMENT_AGENT_T3N_API_KEY = remediationKey;
  process.env.REMEDIATION_DID = "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019";
  const remediation = await connectC1Principal("REPLACEMENT_AGENT_T3N_API_KEY", "REMEDIATION_DID");
  const reserve = object(await invokeC1(remediation.apiKey, remediation.nodeUrl, contractName(connected.tenantDid), RESERVATION_FUNCTION, { incident_id: HISTORICAL_INCIDENT_ID }));
  requireCondition(reserve.result !== "WON", "closed incident replay returned a winning reservation");
  delete process.env.REPLACEMENT_AGENT_T3N_API_KEY;
  delete process.env.REMEDIATION_DID;

  const brokerKey = await envFileValue(".env.effect-broker", "EFFECT_BROKER_T3N_API_KEY");
  const replayDirectory = await mkdtemp(path.join(os.tmpdir(), "t3n-c2-e2e-r2b-broker-"));
  const barrier = path.join(replayDirectory, "claim-release.json");
  const proposals = path.join(replayDirectory, "proposals-complete.json");
  const ready = path.join(replayDirectory, "ready.json");
  const resultFile = path.join(replayDirectory, "result.json");
  try {
    await writeFile(proposals, JSON.stringify({ incident_id: HISTORICAL_INCIDENT_ID, replay_only: true }));
    const environment: NodeJS.ProcessEnv = { ...process.env };
    for (const key of Object.keys(environment)) if (key === "GITHUB_PAT" || key === "T3N_API_KEY" || key.startsWith("GITHUB_") || key === "AGENT_T3N_API_KEY" || key === "REPLACEMENT_AGENT_T3N_API_KEY") delete environment[key];
    Object.assign(environment, {
      EFFECT_BROKER_T3N_API_KEY: brokerKey,
      EFFECT_BROKER_DID: "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57",
      C1_OPERATOR_DID: connected.tenantDid,
      C1_EXPECTED_CLAIM_VERSION: String(object(before.detail).effect_claim_version ?? 1),
      C1_BARRIER_FILE: barrier,
      C1_PROPOSALS_COMPLETE_FILE: proposals,
      C1_READY_FILE: ready,
      C1_RESULT_FILE: resultFile,
      C1_CONTENDER_ID: "r2b-closed-replay",
      C1_EFFECT_START_READY_FILE: "",
      C1_PRE_DELETE_RELEASE_FILE: "",
    });
    const childPromise = runChild(path.join(root, "winner/broker/run.ts"), [HISTORICAL_INCIDENT_ID], environment);
    await waitFor(ready, 120_000);
    await writeFile(barrier, JSON.stringify({ incident_id: HISTORICAL_INCIDENT_ID, released_once: true }));
    await waitFor(resultFile, 120_000);
    const child = await childPromise;
    const broker = parseJson<JsonObject>(await readFile(resultFile, "utf8"));
    requireCondition(child.code === 0, `closed replay broker failed: ${redact(child.stderr, [brokerKey])}`);
    requireCondition(broker.token_minted === false && broker.provider_credential_mint_count === 0 && broker.destructive_call_count === 0 && broker.delete_attempted === false && broker.provider_calls_after_ownership_loss === 0 && !Object.prototype.hasOwnProperty.call(broker, "effect_token"), "closed replay broker crossed the provider boundary");
    const adjudication = adjudicateBrokerResult(broker);
    requireCondition(["NON_OWNER_EARLY_CLAIM_LOST", "NON_OWNER_CONFIRM_REJECTED"].includes(adjudication.state), `closed replay broker adjudication was not a safe non-owner result: ${adjudication.reason}`);
    const after = await getIncident();
    requireCondition(JSON.stringify(terminalProjection(before)) === JSON.stringify(terminalProjection(after)), "closed incident terminal authority changed during replay");
    return { before: sanitize(before, [operatorKey, remediationKey, brokerKey]) as JsonObject, reserve: sanitize(reserve, [operatorKey, remediationKey, brokerKey]) as JsonObject, broker: sanitize(broker, [operatorKey, remediationKey, brokerKey]) as JsonObject, adjudication, after: sanitize(after, [operatorKey, remediationKey, brokerKey]) as JsonObject, t3n_calls: 4 };
  } finally {
    await rm(replayDirectory, { recursive: true, force: true });
  }
}

async function main(): Promise<void> {
  requireCondition(process.env[REQUIRED_LIVE_START_ENV], `${REQUIRED_LIVE_START_ENV} must be supplied after the implementation freeze commit`);
  const liveStart = process.env[REQUIRED_LIVE_START_ENV]!;
  requireCondition(SHA_RE.test(liveStart), "R2B live-start SHA is invalid");
  const currentHead = (await execFile("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" })).stdout.trim();
  const originHead = (await execFile("git", ["rev-parse", "origin/winner-v2-core"], { cwd: root, encoding: "utf8" })).stdout.trim();
  const mainSha = (await execFile("git", ["rev-parse", "origin/main"], { cwd: root, encoding: "utf8" })).stdout.trim();
  requireCondition(currentHead === liveStart && originHead === liveStart, "R2B live-start checkpoint is not equal to local and origin winner-v2-core");
  requireCondition(mainSha === "4a077035474337b7a1ad16204820e68ed3020477", "origin/main changed");
  requireCondition((await execFile("git", ["status", "--porcelain"], { cwd: root, encoding: "utf8" })).stdout.trim() === "", "R2B live-start worktree is not clean");
  requireCondition(liveStart !== R2_STARTING_SHA, "R2B must not reuse the historical R2 execution start as its live checkpoint");

  const failure = parseJson<JsonObject>(await readFile(path.join(root, FAILURE_EVIDENCE), "utf8"));
  const retirement = parseJson<JsonObject>(await readFile(path.join(root, RETIREMENT_EVIDENCE), "utf8"));
  const r2a = parseJson<JsonObject>(await readFile(path.join(root, R2A_EVIDENCE), "utf8"));
  requireCondition(failure.classification === "C2_E2E_R2_FAIL_BROKER_OWNER_EVIDENCE_ADJUDICATION" && retirement.policy_id === HISTORICAL_POLICY_ID && retirement.retired === true && r2a.classification === "C2_E2E_R2A_HISTORICAL_CORE_ADJUDICATION_PASS", "historical R2 retirement facts are not intact");

  const receipt = await findDurableReceipt();
  const b0Evidence = parseJson<JsonObject>(await readFile(path.join(root, EXPECTED_B0_EVIDENCE), "utf8"));
  const webhookUrl = String(object(b0Evidence.webhook).url ?? "");
  requireCondition(webhookUrl.startsWith("https://") && new URL(webhookUrl).pathname === WEBHOOK_ROUTE, "B0 evidence does not provide a usable frozen webhook route");
  const webhookSecret = await envFileValue(".env.c2-b0-live", "C2_WEBHOOK_SECRET");
  const appEnv = await readFile(path.join(root, ".env.c0r-github-app"), "utf8");
  const appConfig = appConfigFromEnvironment({ GITHUB_APP_ID: envLine(appEnv, "GITHUB_APP_ID"), GITHUB_APP_INSTALLATION_ID: envLine(appEnv, "GITHUB_APP_INSTALLATION_ID"), GITHUB_APP_PRIVATE_KEY_PATH: envLine(appEnv, "GITHUB_APP_PRIVATE_KEY_PATH"), GITHUB_OWNER: SANDBOX_OWNER, GITHUB_REPO: SANDBOX_REPOSITORY });
  const jwt = await appJwt(appConfig);
  const appReadback = await readAppConfiguration(jwt, webhookUrl);

  const captureFile = path.join(os.tmpdir(), `t3n-c2-e2e-r2b-capture-${process.pid}.json`);
  const receiver = createR2BReplayWebhookServer({ webhookSecret, capturePath: captureFile, expectedDeliveryId: HISTORICAL_DELIVERY_ID, expectedBefore: HISTORICAL_BEFORE, expectedAfter: HISTORICAL_AFTER, route: WEBHOOK_ROUTE });
  let serverClosed = false;
  try {
    await listen(receiver.server, 8787, "127.0.0.1");
    const tunnel = await tunnelReadiness(new URL(webhookUrl).origin);
    const readiness = evaluateGithubAppWebhookReadiness({ ...appReadback.facts, tunnel, receiver: { listening_locally: true } });
    requireCondition(readiness.valid && readiness.classification === "WEBHOOK_CONFIGURED_AND_REACHABLE", `webhook readiness failed: ${readiness.reasons.join("; ")}`);
    const original = await originalDelivery(jwt);
    const exactDeliveryId = String(original.original_delivery_id_exact ?? "");
    requireCondition(/^[0-9]+$/.test(exactDeliveryId), "lossless original delivery ID is unavailable");
    const priorDisplayedId = "3841363528254497000";
    const unsafeRoundtripChangesId = unsafeNumberRoundtripChangesId(exactDeliveryId);
    requireCondition(exactDeliveryId !== priorDisplayedId, "exact delivery ID equals the prior unsafe display value; root cause remains unresolved");
    let priorRoundedGet: JsonObject | null = null;
    let rootCause = "UNRESOLVED";
    if (unsafeRoundtripChangesId) {
      const rounded = await githubRequest(jwt, `/app/hook/deliveries/${encodeURIComponent(priorDisplayedId)}`);
      priorRoundedGet = { http_status: rounded.status };
      if (rounded.status === 404) rootCause = "R2B_R1_ROOT_CAUSE_CONFIRMED_UNSAFE_DELIVERY_ID_ROUNDING";
    }
    const redeliveryResponse = await githubRequest(jwt, `/app/hook/deliveries/${encodeURIComponent(exactDeliveryId)}/attempts`, { method: "POST" });
    requireCondition(redeliveryResponse.status === 202, `GitHub redelivery request failed HTTP ${redeliveryResponse.status}`);
    const redelivery = { post_http_status: redeliveryResponse.status, history: await waitForRedeliveryHistory(jwt, exactDeliveryId) };
    await waitFor(captureFile, 120_000);
    const captured = receiver.getCapture();
    requireCondition(captured, "dedicated replay receiver did not retain the redelivery in memory");
    const capture: R2BReplayCapture = captured.evidence;
    requireCondition(capture.delivery_id === HISTORICAL_DELIVERY_ID && capture.repository_id === SANDBOX_REPOSITORY_ID && capture.repository_full_name === `${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}` && capture.ref === SANDBOX_REF && capture.before === HISTORICAL_BEFORE && capture.after === HISTORICAL_AFTER && capture.created === false && capture.forced === false && capture.deleted === false && capture.signature_verified === true && capture.raw_body_persisted === false && capture.webhook_secret_persisted === false && capture.authority_processing_attempted === false && capture.source_reader_calls === 0 && capture.c1_request_created === false && capture.raw_body_sha256 === HISTORICAL_RAW_BODY_SHA256, "redelivery did not match the exact authenticated historical event");
    const receiptBeforeReplay = await hashFile(receipt.file);
    requireCondition(receiptBeforeReplay === receipt.sha256, "durable receipt changed before replay");
    let observationAccesses = 0;
    const poisonObservations = {
      get before(): never { observationAccesses += 1; throw new Error("receipt replay must not inspect source observations"); },
      get after(): never { observationAccesses += 1; throw new Error("receipt replay must not inspect source observations"); },
    };
    const c2Replay = await processPushWebhook(captured.request, webhookSecret, path.dirname(receipt.file), [], poisonObservations, { retiredPolicyIds: new Set([HISTORICAL_POLICY_ID]) });
    requireCondition(c2Replay.classification === "C2_PUSH_SELECTED" && c2Replay.dedupe.status === "DUPLICATE_SAME" && c2Replay.replayed === true && c2Replay.receipt_replay === true && c2Replay.authority_rederived === false && c2Replay.source_reads === 0 && observationAccesses === 0 && c2Replay.incident_id === HISTORICAL_INCIDENT_ID, "production C2 receipt replay did not return the exact durable accepted result");
    requireCondition(JSON.stringify(c2Replay.create_request) === JSON.stringify(receipt.record.create_request), "C2 replay create_request differs from the durable receipt");
    const receiptAfterReplay = await hashFile(receipt.file);
    requireCondition(receiptAfterReplay === receiptBeforeReplay, "C2 replay rewrote the durable accepted receipt");
    const c1 = await closedIncidentReplay();
    const evidence = {
      classification: "C2_E2E_R2B_SAME_EVENT_REPLAY_PASS",
      r2b_live_start_sha: liveStart,
      main_sha: mainSha,
      historical_r2: { classification: failure.classification, actual_execution_start: R2_STARTING_SHA, policy_id: HISTORICAL_POLICY_ID, policy_version: 2, target_id: HISTORICAL_TARGET_ID, incident_id: HISTORICAL_INCIDENT_ID, delivery_guid: HISTORICAL_DELIVERY_ID, r2a_adjudication_artifact: R2A_EVIDENCE },
      durable_receipt: { path_class: "OS_TEMP/t3n-c2-e2e-r2-run-*/dedupe/<dedupe-key>.json", receipt_sha256_before: receiptBeforeReplay, receipt_sha256_after: receiptAfterReplay, receipt_unchanged: receiptBeforeReplay === receiptAfterReplay, state: receipt.record.state, decision: receipt.record.decision, policy_id: receipt.record.policy_id, policy_version: receipt.record.policy_version, incident_id: receipt.record.derived_incident_id, create_request: receipt.record.create_request },
      original_github_delivery: { ...original, github_delivery_id_handling: { canonical_type: "decimal_string", exact_original_delivery_id: exactDeliveryId, prior_unsafe_display_value: priorDisplayedId, number_max_safe_integer: "9007199254740991", unsafe_number_roundtrip_changes_id: unsafeRoundtripChangesId, exact_detail_get_http_status: original.detail_http_status, prior_rounded_get: priorRoundedGet, root_cause: rootCause } },
      redelivery: { post_http_status: redelivery.post_http_status, ...redelivery.history },
      authenticated_event: { guid: capture.delivery_id, event: capture.event, repository_id: capture.repository_id, repository_full_name: capture.repository_full_name, ref: capture.ref, before: capture.before, after: capture.after, created: capture.created, forced: capture.forced, deleted: capture.deleted, raw_body_sha256: capture.raw_body_sha256, hmac_valid: capture.signature_verified, raw_body_persisted: false },
      c2_replay: { classification: c2Replay.classification, dedupe_status: c2Replay.dedupe.status, receipt_replay: c2Replay.receipt_replay === true, authority_rederived: c2Replay.authority_rederived, source_reads: c2Replay.source_reads, source_observation_accesses: observationAccesses, active_policy_candidates_for_replay: 0, policy_selection_count: 0, incident_id: c2Replay.incident_id, incident_id_equal: c2Replay.incident_id === receipt.record.derived_incident_id, create_request_equal: JSON.stringify(c2Replay.create_request) === JSON.stringify(receipt.record.create_request), provider_authority: 0, t3n_calls: 0 },
      c1_closed_replay: { terminal_before: c1.before, remediation_reserve: c1.reserve, broker: c1.broker, broker_adjudication: c1.adjudication, terminal_after: c1.after, terminal_unchanged: JSON.stringify(terminalProjection(c1.before)) === JSON.stringify(terminalProjection(c1.after)), t3n_calls: c1.t3n_calls, new_incidents: 0, new_effect_starts: 0, provider_token_mints: 0, provider_deletes: 0 },
      webhook_readiness: readiness.classification,
      github_app_hook_active_field_required: false,
      github_app_hook_active_state_claimed: false,
      readiness: { app: appReadback.evidence, evaluation: readiness, tunnel, active_policy_candidates_for_replay: 0 },
      mutation_counters: { c2_replay: { github_webhook_redelivery_calls: 1, github_repository_reads: 0, github_repository_mutations: 0, source_reader_token_mints: 0, effect_token_mints: 0, verifier_token_mints: 0, immutable_source_reads: 0, policy_selections: 0, authority_rederivations: 0, t3n_calls: 0, c1_create_calls: 0, provider_mutations: 0, deploy_key_deletes: 0 }, c1_closed_replay: { t3n_calls: c1.t3n_calls, incident_creates: 0, effect_starts: 0, provider_effect_token_mints: 0, provider_mutations: 0, deploy_key_deletes: 0 }, total_mutations: 0 },
      sensitive_value_hygiene: { raw_webhook_body_persisted: false, raw_webhook_body_in_evidence: false, webhook_secret_in_evidence: false, app_jwt_in_evidence: false, installation_token_in_evidence: false, t3n_credentials_in_evidence: false, private_ssh_material_in_evidence: false },
      tests: { c2_replay: "PASS", poison_source_observations: "PASS", receipt_unchanged: "PASS", closed_incident_replay: "PASS", broker_adjudication: "PASS", exact_digest: "PASS" },
      claims_earned: ["GitHub redelivered the original event with the same GUID and authenticated payload digest", "the surviving ACCEPTED durable receipt replayed without policy re-selection, source reads, or authority rederivation", "receipt replay did not rewrite the durable record", "the already CLOSED incident rejected remediation replay", "the closed-incident broker replay obtained zero provider authority", "terminal C1 state remained unchanged with one historical effect attempt"],
      claims_forbidden: ["historical R2 is a PASS", "R2 was uninterrupted", "a new causal event or remediation was executed", "GitHub globally guarantees exactly-once", "T3N/GitHub atomicity", "zero-standing GitHub trust root", "submission readiness"],
    };
    await writeAtomicJson(path.join(root, OUTPUT_EVIDENCE), evidence);
    process.stdout.write(`${JSON.stringify({ classification: evidence.classification, final_sha: currentHead, receipt_sha256: receiptBeforeReplay, delivery_guid: HISTORICAL_DELIVERY_ID, redelivery_http_status: redelivery.post_http_status, c2_replayed: true, c1_terminal_unchanged: true, evidence: OUTPUT_EVIDENCE })}\n`);
  } finally {
    if (!serverClosed) {
      await receiver.close().catch(() => undefined);
      serverClosed = true;
    }
    await rm(captureFile, { force: true }).catch(() => undefined);
  }
}

main().catch((error) => {
  process.stderr.write(`C2-E2E-R2B replay stopped: ${redact(error)}\n`);
  process.exitCode = 1;
});
