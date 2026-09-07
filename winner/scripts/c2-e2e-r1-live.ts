import { createHash, randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { access, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import os from "node:os";
import path from "node:path";
import { connectTenant } from "../../scripts/lib.js";
import { SessionOrgDataClient } from "@terminal3/t3n-sdk";
import { appConfigFromEnvironment, appJwt } from "../broker/github-app.js";
import { invokeC1, invokeC1OperatorSession, redact, requireValue } from "./t3n.js";
import { ACTION, BROKER_FUNCTIONS, CONTRACT_VERSION, INCIDENT_MAP_TAIL, ORGANISATION_DID, RESERVATION_FUNCTION, contractName } from "./constants.js";
import { buildC2PushPolicyV2, lookupPreExistingPushPolicy, retiredPolicyIdSet, type C2PushPolicyV2 } from "../c2/push-policy.js";
import { processPushWebhook } from "../c2/push-ingress.js";
import { normalizeVerifiedPushEvent } from "../c2/push-source.js";
import { createImmutablePushReadPlan } from "../c2/push-read-plan.js";
import { verifyPushSecretTransition, type ImmutablePathObservation } from "../c2/push-transition.js";
import { verifyB1Evidence, type B1VerificationContext } from "../c2/b1-verifier.js";
import { buildB1Evidence } from "../c2/b1-evidence.js";
import { verifyE2EBundle, type E2EVerificationContext } from "../c2/e2e-verifier.js";
import { adjudicateBrokerResults } from "../c2/broker-adjudication.js";
import { freezeLiveExecutionCheckpoint } from "../c2/execution-checkpoint.js";
import { reserveDedupe } from "../c2/dedupe.js";
import { writeAtomicJson } from "./result-file.js";

const execFileAsync = promisify(execFile);
const root = path.resolve(import.meta.dirname, "../..");
const API = "https://api.github.com";
const API_VERSION = "2022-11-28";
const CODE_BRANCH = "winner-v2-core";
const CODE_REPOSITORY = "Ticoworld/t3n-breakglass";
const SANDBOX_OWNER = "Ticoworld";
const SANDBOX_REPOSITORY = "t3n-breakglass-sandbox";
const SANDBOX_REPOSITORY_ID = 1350596128;
const SANDBOX_BRANCH = "c2-breakglass-demo";
const SANDBOX_REF = "refs/heads/c2-breakglass-demo";
const SECRET_PATH = ".breakglass-c2/exposed-deploy-key";
const PING_PATH = ".breakglass-c2/ping.txt";
const INSTALLATION_ID = "158227303";
const APP_SLUG = "breakglass-c0r-jit-probe";
const EXPECTED_PUBLIC_URL = "https://dde7-197-210-70-114.ngrok-free.app";
const WEBHOOK_ROUTE = "/c2-b0/github-push";
// Resolved at launch.  Empty values are intentionally invalid until the
// current execution checkpoint has been captured and verified.
let STARTING_SHA = "";
let MAIN_SHA = "";
let BEFORE_SHA = "";
const OPERATOR_DID = "did:t3n:adb9365ee986cc6d0cb4006580782fe6fc7a431f";
const REMEDIATION_DID = "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019";
const BROKER_DID = "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57";
const CONTRACT_ID = contractName(OPERATOR_DID);
const CONTRACT = { name: CONTRACT_ID, version: "2.0.4", numeric_id: 878, wasm_bytes: 227011, wasm_sha256: "ca7032b112b837b06e4334c10bca8820447f6ea1756b74db9bccd3181ad4d5d0" };
const POLICY_FILE = "winner/evidence/C2-E2E-R2-LIVE-POLICY.json";
const MARKER_FILE = "winner/evidence/C2-E2E-R2-POLICY-FROZEN-AND-REMOTE-CONFIRMED.json";
const FINAL_FILE = "winner/evidence/C2-E2E-R2-FULL-CAUSAL-REMEDIATION.json";
const RETIREMENT_FILE = "winner/evidence/C2-E2E-R2-POLICY-RETIREMENT.json";
const HISTORICAL_B1_POLICY_FILE = "winner/evidence/C2-B1-LIVE-POLICY.json";
const HISTORICAL_B1_RETIREMENT_FILE = "winner/evidence/C2-B1-R1-HISTORICAL-POLICY-RETIREMENT.json";
const HISTORICAL_R1_POLICY_FILE = "winner/evidence/C2-E2E-R1-LIVE-POLICY.json";
const HISTORICAL_R1_RETIREMENT_FILE = "winner/evidence/C2-E2E-R1-FAILED-POLICY-RETIREMENT.json";

type JsonObject = Record<string, any>;
type ApiResult = { status: number; body: unknown; headers: Record<string, string> };
type ChildResult = { code: number; stderr: string };

let appConfig: ReturnType<typeof appConfigFromEnvironment> | null = null;
let appJwtValue: string | null = null;
let setupToken: string | null = null;
let targetId: number | null = null;
let secretPushIssued = false;
let incidentCreated = false;
let effectStartConfirmed = false;
let receiver: { server: Server; getRaw: () => Buffer | null; getHeaders: () => Record<string, string | undefined>; close: () => Promise<void> } | null = null;
let tempRunDirectory: string | null = null;
let tempKeyDirectory: string | null = null;
let stagingDirectory: string | null = null;
let triggerDirectory: string | null = null;
let privateBytes: Buffer | null = null;
let stagedBytes: Buffer | null = null;

function object(value: unknown): JsonObject {
  return value && typeof value === "object" && !Array.isArray(value) ? value as JsonObject : {};
}

function requireCondition(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function parseObject(value: unknown): JsonObject {
  const parsed = typeof value === "string" ? JSON.parse(value) : value;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("response was not an object");
  return parsed as JsonObject;
}

function envValue(contents: string, name: string): string {
  const line = contents.split(/\r?\n/).find((entry) => entry.startsWith(`${name}=`));
  requireCondition(line, `${name} is missing`);
  const value = line.slice(name.length + 1).trim().replace(/^['"]|['"]$/g, "");
  requireCondition(value, `${name} is empty`);
  return value;
}

async function envFileValue(file: string, name: string): Promise<string> {
  return envValue(await readFile(path.join(root, file), "utf8"), name);
}

function safeBodyMetadata(value: unknown): JsonObject | null {
  const body = object(value);
  if (Object.keys(body).length === 0) return null;
  const output: JsonObject = {};
  for (const key of ["id", "title", "read_only", "private", "full_name", "name", "sha", "path", "ref", "repository_selection", "expires_at", "status", "status_code", "event", "guid", "delivered_at", "installation_id", "redelivery"]) {
    if (body[key] !== undefined) output[key] = body[key];
  }
  if (object(body.commit).sha) output.commit_sha = body.commit.sha;
  return output;
}

function safeResponse(response: ApiResult): JsonObject {
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

function sha256(bytes: Uint8Array): string { return createHash("sha256").update(bytes).digest("hex"); }

function progress(phase: string): void { console.error(`C2_E2E_PHASE:${phase}`); }

async function runGit(args: string[], cwd = root): Promise<string> {
  const result = await execFileAsync("git", args, { cwd, encoding: "utf8", maxBuffer: 2_000_000, windowsHide: true });
  return String(result.stdout).trim();
}

function runBuffer(command: string, args: string[], cwd: string, input?: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(Buffer.from(chunk)));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(Buffer.from(chunk)));
    child.on("error", reject);
    child.on("close", (code) => code === 0 ? resolve(Buffer.concat(stdout)) : reject(new Error(`${command} failed: ${Buffer.concat(stderr).toString("utf8").slice(0, 500)}`)));
    child.stdin.end(input);
  });
}

async function writeJson(file: string, value: unknown): Promise<Buffer> {
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
  await writeFile(path.join(root, file), bytes, { flag: "wx" });
  return bytes;
}

async function githubRequest(token: string, route: string, init: RequestInit = {}): Promise<ApiResult> {
  const response = await fetch(`${API}${route}`, {
    ...init,
    redirect: "error",
    signal: AbortSignal.timeout(60_000),
    headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": API_VERSION, "User-Agent": "t3n-breakglass-c2-e2e-r2", ...(init.headers ?? {}) },
  });
  const text = await response.text();
  let body: unknown = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = null; }
  const headers: Record<string, string> = {};
  for (const name of ["date", "etag", "x-github-request-id", "x-ratelimit-remaining"]) { const value = response.headers.get(name); if (value) headers[name] = value; }
  return { status: response.status, body, headers };
}

function repositoryRows(body: unknown): JsonObject[] {
  const value = object(body);
  return Array.isArray(value.repositories) ? value.repositories.map((row) => object(row)) : [];
}

function permissions(body: unknown): JsonObject {
  return object(body).permissions;
}

async function mintInstallationToken(requested: JsonObject, purpose: string): Promise<{ token: string; metadata: JsonObject; response: ApiResult }> {
  requireCondition(appJwtValue, "App JWT is unavailable");
  const response = await githubRequest(appJwtValue, `/app/installations/${INSTALLATION_ID}/access_tokens`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ repositories: [SANDBOX_REPOSITORY], permissions: requested }) });
  const body = object(response.body);
  const token = typeof body.token === "string" ? body.token : null;
  const rows = repositoryRows(body);
  requireCondition(token, `${purpose} token was not returned (HTTP ${response.status})`);
  requireCondition(body.repository_selection === "selected" && rows.some((row) => row.full_name === `${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}` && row.private === true), `${purpose} token did not prove exact private sandbox scope`);
  return { token, response, metadata: { purpose, requested_permissions: requested, actual_permissions: permissions(body), repository_selection: body.repository_selection ?? null, expires_at: body.expires_at ?? null, repositories: rows.map((row) => ({ id: row.id, full_name: row.full_name, private: row.private })) } };
}

async function revokeAndRefuse(token: string): Promise<JsonObject> {
  const revoke = await githubRequest(token, "/installation/token", { method: "DELETE" });
  requireCondition(revoke.status === 204, `token revoke failed HTTP ${revoke.status}`);
  const refusal = await githubRequest(token, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}`);
  requireCondition(refusal.status === 401 || refusal.status === 403, `revoked token was not refused HTTP ${refusal.status}`);
  return { revoke_http_status: revoke.status, refusal_http_status: refusal.status, refusal_confirmed: true };
}

async function appReadiness(): Promise<JsonObject> {
  requireCondition(appJwtValue, "App JWT is unavailable");
  const app = await githubRequest(appJwtValue, "/app");
  const installation = await githubRequest(appJwtValue, `/app/installations/${INSTALLATION_ID}`);
  const hook = await githubRequest(appJwtValue, "/app/hook/config");
  const appBody = object(app.body);
  const installationBody = object(installation.body);
  const appPermissions = permissions(appBody);
  const installationPermissions = permissions(installationBody);
  const events = Array.isArray(appBody.events) ? appBody.events : [];
  requireCondition(app.status === 200 && appBody.slug === APP_SLUG, `App readback failed HTTP ${app.status}`);
  requireCondition(appPermissions.administration === "write" && appPermissions.contents === "read" && appPermissions.metadata === "read" && events.includes("push"), "App permissions/events are not exact");
  requireCondition(installation.status === 200 && Number(installationBody.id) === Number(INSTALLATION_ID) && installationBody.repository_selection === "selected", "installation readback is not exact");
  requireCondition(installationPermissions.administration === "write" && installationPermissions.contents === "read" && installationPermissions.metadata === "read", "installation permissions are not exact");
  const hookBody = object(hook.body);
  requireCondition(hook.status === 200 && typeof hookBody.url === "string" && new URL(hookBody.url).origin === EXPECTED_PUBLIC_URL && new URL(hookBody.url).pathname === WEBHOOK_ROUTE && hookBody.content_type === "json" && hookBody.insecure_ssl === "0", "configured webhook URL/configuration is not exact");
  return { app: safeResponse(app), installation: safeResponse(installation), hook: { http_status: hook.status, configured: true, url_origin: EXPECTED_PUBLIC_URL, route: WEBHOOK_ROUTE, content_type: hookBody.content_type ?? null, insecure_ssl: hookBody.insecure_ssl ?? null }, app_permissions: appPermissions, installation_permissions: installationPermissions, events, repository_selection: installationBody.repository_selection };
}

async function curlStatus(url: string): Promise<number> {
  const result = await execFileAsync("curl.exe", ["--silent", "--show-error", "--ssl-no-revoke", "--connect-timeout", "10", "--max-time", "30", "--output", "NUL", "--write-out", "%{http_code}", url], { encoding: "utf8", windowsHide: true });
  const code = Number(String(result.stdout).trim());
  requireCondition(Number.isInteger(code), "curl did not return an HTTP status");
  return code;
}

async function ingressReachability(): Promise<JsonObject> {
  const local = await fetch(`http://127.0.0.1:8787${WEBHOOK_ROUTE}`, { method: "GET", signal: AbortSignal.timeout(15_000) });
  const tunnels = await fetch("http://127.0.0.1:4040/api/tunnels", { signal: AbortSignal.timeout(15_000) });
  requireCondition(local.status === 404 && tunnels.ok, "existing receiver/ngrok API is not reachable");
  const body = object(await tunnels.json());
  const tunnel = Array.isArray(body.tunnels) ? body.tunnels.find((row) => object(row).public_url === EXPECTED_PUBLIC_URL) : null;
  requireCondition(tunnel && String(object(tunnel.config).addr ?? "").includes("8787"), "frozen ngrok endpoint is not forwarding to port 8787");
  const publicStatus = await curlStatus(`${EXPECTED_PUBLIC_URL}${WEBHOOK_ROUTE}`);
  requireCondition(publicStatus === 404, `public receiver reachability returned HTTP ${publicStatus}`);
  return { local_http_status: local.status, public_http_status: publicStatus, public_url_origin: EXPECTED_PUBLIC_URL, route: WEBHOOK_ROUTE, tunnel_addr: object(tunnel.config).addr };
}

async function listenerPid(): Promise<number | null> {
  const result = await execFileAsync("netstat", ["-ano", "-p", "tcp"], { encoding: "utf8", windowsHide: true });
  const line = String(result.stdout).split(/\r?\n/).find((entry) => /127\.0\.0\.1:8787\s+.*LISTENING\s+\d+/i.test(entry));
  const match = line?.match(/LISTENING\s+(\d+)\s*$/i);
  return match ? Number(match[1]) : null;
}

async function stopExistingB0Receiver(): Promise<void> {
  const pid = await listenerPid();
  if (!pid || pid === process.pid) return;
  const command = await execFileAsync("powershell.exe", ["-NoProfile", "-Command", `(Get-CimInstance Win32_Process -Filter 'ProcessId=${pid}').CommandLine`], { encoding: "utf8", windowsHide: true });
  requireCondition(/c2-b0-live/i.test(String(command.stdout)), "port 8787 is occupied by an unexpected process");
  try {
    await execFileAsync("taskkill.exe", ["/PID", String(pid), "/T", "/F"], { encoding: "utf8", windowsHide: true });
  } catch {
    /* it may have exited between readback and signal; the bounded listener check below decides */
  }
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) { if (!(await listenerPid())) return; await new Promise((resolve) => setTimeout(resolve, 250)); }
  throw new Error("previous B0 receiver did not stop cleanly");
}

async function readBoundedBody(request: IncomingMessage): Promise<Buffer | null> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > 1_048_576) return null;
    chunks.push(buffer);
  }
  return Buffer.concat(chunks, size);
}

function requestHeaders(request: IncomingMessage): Record<string, string | undefined> {
  const output: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(request.headers)) output[key] = Array.isArray(value) ? value[0] : value;
  return output;
}

function requestMetadata(request: IncomingMessage): JsonObject {
  const length = typeof request.headers["content-length"] === "string" && /^\d+$/.test(request.headers["content-length"] as string) ? Number(request.headers["content-length"]) : null;
  return { method: request.method ?? null, url: request.url ?? null, remote_address: request.socket.remoteAddress ?? null, user_agent: typeof request.headers["user-agent"] === "string" ? (request.headers["user-agent"] as string).slice(0, 256) : null, content_type: typeof request.headers["content-type"] === "string" ? (request.headers["content-type"] as string).slice(0, 128) : null, content_length: length };
}

async function startE2EReceiver(secret: string, capturePath: string, dedupeDirectory: string): Promise<typeof receiver> {
  let latestRaw: Buffer | null = null;
  let latestHeaders: Record<string, string | undefined> = {};
  const server = createServer(async (request, reply) => {
    if (request.method !== "POST" || request.url !== WEBHOOK_ROUTE) { request.resume(); reply.statusCode = 404; reply.end("not found"); return; }
    const body = await readBoundedBody(request);
    if (!body) { reply.statusCode = 413; reply.end("request too large"); return; }
    let event;
    try { event = normalizeVerifiedPushEvent({ headers: requestHeaders(request), body }, secret); }
    catch { reply.statusCode = 401; reply.end("delivery rejected"); return; }
    if (latestRaw) latestRaw.fill(0);
    latestRaw = Buffer.from(body);
    latestHeaders = requestHeaders(request);
    const dedupe = await reserveDedupe(dedupeDirectory, event);
    await writeAtomicJson(capturePath, {
      received_at: new Date().toISOString(), request: requestMetadata(request), delivery_id: event.delivery_id, event: event.event_type, repository_id: event.repository_id, repository_full_name: event.repository_full_name, ref: event.ref, before: event.before, after: event.after, created: event.created, forced: event.forced, deleted: event.deleted, raw_body_sha256: event.raw_body_sha256,
      normalized: { repository_id: event.repository_id, repository_full_name: event.repository_full_name, ref: event.ref, before: event.before, after: event.after, created: event.created, forced: event.forced, deleted: event.deleted, sender_login: event.sender_login },
      signature_verified: true, hmac_verified: true, raw_body_persisted: false, webhook_secret_persisted: false, authority_processing_attempted: false, authority_eligible: false, authority_reason: "receiver_capture_only_before_explicit_C2_processing", source_reader_calls: 0, c1_request_created: false, dedupe: { status: dedupe.status, key: dedupe.key },
    });
    reply.statusCode = 202; reply.end("delivery captured");
  });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(8787, "127.0.0.1", () => resolve()); });
  return { server, getRaw: () => latestRaw ? Buffer.from(latestRaw) : null, getHeaders: () => ({ ...latestHeaders }), close: () => new Promise<void>((resolve) => server.close(() => resolve())) };
}

async function waitForFile(file: string, timeoutMs = 180_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (true) { try { await access(file); return; } catch { if (Date.now() > deadline) throw new Error(`timed out waiting for ${path.basename(file)}`); await new Promise((resolve) => setTimeout(resolve, 250)); } }
}

async function readJson<T = JsonObject>(file: string): Promise<T> { return JSON.parse(await readFile(file, "utf8")) as T; }

async function awaitDelivery(capturePath: string, afterSha: string): Promise<JsonObject> {
  const deadline = Date.now() + 180_000;
  while (Date.now() < deadline) {
    try {
      const capture = await readJson<JsonObject>(capturePath);
      if (capture.event === "push" && capture.repository_id === SANDBOX_REPOSITORY_ID && capture.repository_full_name === `${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}` && capture.ref === SANDBOX_REF && capture.before === BEFORE_SHA && capture.after === afterSha) {
        requireCondition(capture.created === false && capture.forced === false && capture.deleted === false && capture.signature_verified === true && capture.hmac_verified === true && capture.raw_body_persisted === false && capture.webhook_secret_persisted === false && capture.authority_processing_attempted === false && capture.authority_eligible === false && capture.source_reader_calls === 0 && capture.c1_request_created === false && capture.dedupe?.status === "NEW", "real delivery capture failed its exact safe shape");
        return capture;
      }
    } catch { /* capture file has not arrived yet */ }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error("timed out waiting for the one real GitHub trigger delivery; no retry permitted");
}

async function deliveryHistory(deliveryId: string): Promise<JsonObject> {
  requireCondition(appJwtValue, "App JWT unavailable for delivery history");
  const response = await githubRequest(appJwtValue, "/app/hook/deliveries?per_page=100");
  const rows = Array.isArray(response.body) ? response.body.map((row) => object(row)) : [];
  const match = rows.find((row) => row.guid === deliveryId);
  requireCondition(response.status === 200 && match, `GitHub delivery ${deliveryId} was not corroborated`);
  requireCondition(match.event === "push" && match.installation_id === Number(INSTALLATION_ID) && match.redelivery === false, "GitHub delivery corroboration identity is not exact");
  return { classification: "GITHUB_DELIVERY_CORROBORATED", http_status: response.status, delivery_numeric_id: match.id ?? null, guid: match.guid, event: match.event, delivered_at: match.delivered_at, status: match.status, status_code: match.status_code, installation_id: match.installation_id, redelivery: match.redelivery };
}

async function commitAndPush(files: string[], message: string): Promise<string> {
  const relative = files.map((file) => file.replaceAll("\\", "/")).sort();
  const status = (await runGit(["status", "--short", "--untracked-files=all"])).split(/\r?\n/).filter(Boolean).map((line) => line.slice(3)).sort();
  requireCondition(JSON.stringify(status) === JSON.stringify(relative), `unexpected working tree before commit: ${status.join(",")}`);
  await runGit(["add", "--", ...relative]);
  const staged = (await runGit(["diff", "--cached", "--name-only"])).split(/\r?\n/).filter(Boolean).sort();
  requireCondition(JSON.stringify(staged) === JSON.stringify(relative), "commit would include unexpected paths");
  await runGit(["commit", "--no-verify", "-m", message]);
  const sha = await runGit(["rev-parse", "HEAD"]);
  await runGit(["push", "origin", CODE_BRANCH]);
  requireCondition(await runGit(["rev-parse", "HEAD"]) === sha, "HEAD changed unexpectedly after push");
  return sha;
}

async function generateKeyAndStage(): Promise<{ title: string; publicKey: string; fingerprint: string; privateDigest: string; blobSha: string }> {
  tempKeyDirectory = await mkdtemp(path.join(os.tmpdir(), "t3n-c2-e2e-r2-key-"));
  const privatePath = path.join(tempKeyDirectory, "id_ed25519");
  const publicPath = `${privatePath}.pub`;
  const title = `breakglass-c2-b1-e2e-r2-${Date.now()}-${randomBytes(6).toString("hex")}`;
  await execFileAsync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", title, "-f", privatePath], { windowsHide: true });
  privateBytes = await readFile(privatePath);
  const generatedPublic = String((await execFileAsync("ssh-keygen", ["-y", "-f", privatePath], { windowsHide: true })).stdout).trim().split(/\s+/).slice(0, 2).join(" ");
  const recordedPublic = (await readFile(publicPath, "utf8")).trim().split(/\s+/).slice(0, 2).join(" ");
  requireCondition(generatedPublic === recordedPublic && generatedPublic.startsWith("ssh-ed25519 "), "private/public relation was not independently proven");
  const fingerprintOutput = String((await execFileAsync("ssh-keygen", ["-lf", publicPath, "-E", "sha256"], { windowsHide: true })).stdout);
  const fingerprint = fingerprintOutput.match(/SHA256:[A-Za-z0-9+/]+/)?.[0];
  requireCondition(fingerprint, "public fingerprint was not derived");
  stagingDirectory = await mkdtemp(path.join(os.tmpdir(), "t3n-c2-e2e-r2-stage-"));
  await execFileAsync("git", ["init", "--quiet", "--initial-branch=main"], { cwd: stagingDirectory, windowsHide: true });
  await execFileAsync("git", ["config", "core.autocrlf", "false"], { cwd: stagingDirectory, windowsHide: true });
  await execFileAsync("git", ["config", "core.safecrlf", "false"], { cwd: stagingDirectory, windowsHide: true });
  const stagedPath = path.join(stagingDirectory, SECRET_PATH);
  await mkdir(path.dirname(stagedPath), { recursive: true });
  await writeFile(stagedPath, privateBytes);
  await execFileAsync("git", ["add", "--", SECRET_PATH], { cwd: stagingDirectory, windowsHide: true });
  const blobSha = await runGit(["rev-parse", `:${SECRET_PATH}`], stagingDirectory);
  stagedBytes = await runBuffer("git", ["cat-file", "blob", blobSha], stagingDirectory);
  requireCondition(Buffer.compare(stagedBytes, privateBytes) === 0, "staged future secret bytes differ from intended private material");
  return { title, publicKey: generatedPublic, fingerprint, privateDigest: sha256(stagedBytes), blobSha };
}

async function createTarget(publicKey: string, title: string, expectedFingerprint: string): Promise<JsonObject> {
  const minted = await mintInstallationToken({ administration: "write" }, "fixture-setup");
  setupToken = minted.token;
  const before = await githubRequest(setupToken, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/keys?per_page=100`);
  requireCondition(before.status === 200, `deploy-key list preflight failed HTTP ${before.status}`);
  const create = await githubRequest(setupToken, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/keys`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ title, key: publicKey, read_only: true }) });
  requireCondition(create.status === 201, `fresh deploy-key create failed HTTP ${create.status}`);
  const created = object(create.body); targetId = Number(created.id);
  requireCondition(Number.isSafeInteger(targetId) && targetId > 0 && created.title === title && created.read_only === true, "fresh deploy-key metadata is invalid");
  const exact = await githubRequest(setupToken, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/keys/${targetId}`);
  const list = await githubRequest(setupToken, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/keys?per_page=100`);
  const exactBody = object(exact.body);
  requireCondition(exact.status === 200 && exactBody.id === targetId && exactBody.title === title && exactBody.read_only === true && String(exactBody.key).trim().split(/\s+/).slice(0, 2).join(" ") === publicKey, "fresh deploy-key exact readback failed");
  requireCondition(list.status === 200 && Array.isArray(list.body) && list.body.some((row) => object(row).id === targetId && object(row).title === title && object(row).read_only === true), "fresh deploy-key list readback failed");
  const providerPub = path.join(tempKeyDirectory!, "provider.pub");
  await writeFile(providerPub, `${publicKey}\n`, "utf8");
  const providerFingerprint = String((await execFileAsync("ssh-keygen", ["-lf", providerPub, "-E", "sha256"], { windowsHide: true })).stdout).match(/SHA256:[A-Za-z0-9+/]+/)?.[0];
  requireCondition(providerFingerprint === expectedFingerprint, "provider fingerprint differs from generated fingerprint");
  const lifecycle = await revokeAndRefuse(setupToken); setupToken = null;
  return { id: targetId, title, read_only: true, repository: `${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}`, generated_public_key_fingerprint: expectedFingerprint, provider_public_key_fingerprint: providerFingerprint, private_public_relation_proven: true, provider_readback_exact: true, setup_token: { ...minted.metadata, create_http_status: create.status, exact_get_http_status: exact.status, list_contains_target: true, lifecycle, revoke_http_status: lifecycle.revoke_http_status, refusal_http_status: lifecycle.refusal_http_status }, provider_exact_readback: safeResponse(exact), provider_list_readback: { http_status: list.status, contains_target: true } };
}

async function verifyBaseline(pat: string): Promise<JsonObject> {
  const ref = await githubRequest(pat, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/git/ref/heads/${SANDBOX_BRANCH}`);
  const head = object(object(ref.body).object).sha;
  const ping = await githubRequest(pat, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/contents/${PING_PATH}?ref=${BEFORE_SHA}`);
  const secret = await githubRequest(pat, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/contents/${SECRET_PATH}?ref=${BEFORE_SHA}`);
  requireCondition(ref.status === 200 && head === BEFORE_SHA, `sandbox baseline moved: expected ${BEFORE_SHA}, got ${String(head)}`);
  requireCondition(ping.status === 200 && secret.status === 404, "clean B1 baseline paths are not exact");
  return { branch: SANDBOX_BRANCH, branch_head_sha: head, ping_http_status: ping.status, secret_path_http_status: secret.status, secret_path_absent: true };
}

async function verifyTarget(pat: string, id: number, title: string, publicKey: string): Promise<JsonObject> {
  const exact = await githubRequest(pat, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/keys/${id}`);
  const body = object(exact.body);
  requireCondition(exact.status === 200 && body.id === id && body.title === title && body.read_only === true && String(body.key).trim().split(/\s+/).slice(0, 2).join(" ") === publicKey, "pre-trigger target readback failed");
  return { exact_get_http_status: exact.status, id, title, read_only: true, target_present: true };
}

async function remotePolicyReadback(pat: string, policy: C2PushPolicyV2, policyBytes: Buffer, freezeSha: string): Promise<JsonObject> {
  const encoded = POLICY_FILE.split("/").map((part) => encodeURIComponent(part)).join("/");
  const response = await githubRequest(pat, `/repos/${CODE_REPOSITORY}/contents/${encoded}?ref=${CODE_BRANCH}`);
  const body = object(response.body);
  requireCondition(response.status === 200 && typeof body.content === "string", `policy remote readback failed HTTP ${response.status}`);
  const remoteBytes = Buffer.from(String(body.content).replace(/\s+/g, ""), "base64");
  const remoteJson = JSON.parse(remoteBytes.toString("utf8")) as JsonObject;
  requireCondition(JSON.stringify(remoteJson.policy) === JSON.stringify(policy) && Buffer.compare(remoteBytes, policyBytes) === 0, "remote policy differs from frozen local bytes");
  const commit = await githubRequest(pat, `/repos/${CODE_REPOSITORY}/commits/${freezeSha}`);
  requireCondition(commit.status === 200 && object(commit.body).sha === freezeSha, "policy freeze commit readback failed");
  return { success: true, repository: CODE_REPOSITORY, ref: CODE_BRANCH, path: POLICY_FILE, policy_freeze_commit_sha: freezeSha, policy_content_sha256: sha256(remoteBytes), remote_blob_sha: body.sha ?? null, remote_readback_http_status: response.status, remote_readback_date: response.headers.date ?? null, commit_readback_http_status: commit.status };
}

async function triggerSecret(bytes: Buffer): Promise<JsonObject> {
  triggerDirectory = await mkdtemp(path.join(os.tmpdir(), "t3n-c2-e2e-r2-trigger-"));
  const directory = triggerDirectory;
  await execFileAsync("git", ["init", "--quiet", "--initial-branch=main"], { cwd: directory, windowsHide: true });
  await execFileAsync("git", ["config", "core.autocrlf", "false"], { cwd: directory, windowsHide: true });
  await execFileAsync("git", ["config", "user.name", "BreakGlass C2 E2E"], { cwd: directory, windowsHide: true });
  await execFileAsync("git", ["config", "user.email", "breakglass-c2-e2e@users.noreply.github.com"], { cwd: directory, windowsHide: true });
  await execFileAsync("git", ["remote", "add", "origin", `https://github.com/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}.git`], { cwd: directory, windowsHide: true });
  await execFileAsync("git", ["fetch", "--quiet", "origin", `refs/heads/${SANDBOX_BRANCH}`], { cwd: directory, windowsHide: true });
  const fetchedBefore = await runGit(["rev-parse", "FETCH_HEAD"], directory);
  requireCondition(fetchedBefore === BEFORE_SHA, `sandbox head changed before secret trigger: ${fetchedBefore}`);
  const beforeTree = await runGit(["rev-parse", `${BEFORE_SHA}^{tree}`], directory);
  await runGit(["read-tree", beforeTree], directory);
  const blobSha = (await runBuffer("git", ["hash-object", "-w", "--stdin"], directory, bytes)).toString("utf8").trim();
  requireCondition(/^[0-9a-f]{40}$/i.test(blobSha), "secret blob was not staged as a Git object");
  await runGit(["update-index", "--add", "--cacheinfo", `100644,${blobSha},${SECRET_PATH}`], directory);
  const treeSha = await runGit(["write-tree"], directory);
  const commitSha = await runGit(["commit-tree", treeSha, "-p", BEFORE_SHA, "-m", "C2-E2E-R2 exact disposable credential transition"], directory);
  requireCondition(/^[0-9a-f]{40}$/i.test(commitSha), "secret trigger did not create a commit SHA");
  await runGit(["update-ref", `refs/heads/${SANDBOX_BRANCH}`, commitSha], directory);
  secretPushIssued = true;
  await execFileAsync("git", ["push", "origin", `${commitSha}:refs/heads/${SANDBOX_BRANCH}`], { cwd: directory, windowsHide: true });
  const remote = String((await execFileAsync("git", ["ls-remote", "origin", `refs/heads/${SANDBOX_BRANCH}`], { cwd: directory, encoding: "utf8", windowsHide: true })).stdout).trim().split(/\s+/)[0];
  requireCondition(remote === commitSha, "sandbox branch did not advance to the exact trigger commit");
  const parents = (await runGit(["rev-list", "--parents", "-n", "1", commitSha], directory)).split(/\s+/).slice(1);
  const files = (await runGit(["diff-tree", "--no-commit-id", "--name-status", "-r", commitSha], directory)).split(/\r?\n/).filter(Boolean).map((line) => { const [status, ...name] = line.split(/\s+/); return { filename: name.join(" "), status }; });
  requireCondition(parents[0] === BEFORE_SHA && files.length === 1 && files[0].filename === SECRET_PATH && files[0].status === "A", "trigger commit is not one exact child adding only the secret path");
  const result = { mechanism: "Git over GitHub HTTPS one fast-forward commit", sha: commitSha, parent_sha: parents[0], branch: SANDBOX_BRANCH, only_changed_path: SECRET_PATH, fast_forward: true, commit_readback: { mechanism: "local Git object plus ls-remote", parent_sha: parents[0], files } };
  await rm(directory, { recursive: true, force: true }); triggerDirectory = null;
  return result;
}

async function readContentDigest(token: string, ref: string): Promise<{ status: number; digest: string | null; response: ApiResult }> {
  const response = await githubRequest(token, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/contents/${SECRET_PATH}?ref=${encodeURIComponent(ref)}`);
  if (response.status !== 200) return { status: response.status, digest: null, response };
  const content = object(response.body).content;
  requireCondition(typeof content === "string", "provider content response has no encoded content");
  const decoded = Buffer.from(content.replace(/\s+/g, ""), "base64");
  const digest = sha256(decoded); decoded.fill(0);
  return { status: response.status, digest, response };
}

function childEnvironment(additions: Record<string, string>): NodeJS.ProcessEnv {
  const output = { ...process.env };
  for (const key of Object.keys(output)) if (key === "T3N_API_KEY" || key === "AGENT_T3N_API_KEY" || key === "EFFECT_BROKER_T3N_API_KEY" || key === "GITHUB_PAT" || key.startsWith("GITHUB_")) delete output[key];
  Object.assign(output, additions);
  return output;
}

function runChild(script: string, args: string[], environment: NodeJS.ProcessEnv): Promise<ChildResult> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--import", "tsx", script, ...args], { cwd: root, env: environment, windowsHide: true, stdio: ["ignore", "ignore", "pipe"] });
    let stderr = ""; child.stderr.on("data", (chunk) => { stderr += String(chunk); }); child.on("close", (code) => resolve({ code: code ?? 1, stderr }));
  });
}

function c1Response(value: unknown, functionName: string, expected?: string): JsonObject {
  const response = parseObject(value);
  requireCondition(response.function === functionName, `${functionName} response label mismatch`);
  if (expected) requireCondition(response.result === expected, `${functionName} expected ${expected}, got ${String(response.result)}`);
  return response;
}

async function t3nReadiness(agentKey: string, brokerKey: string): Promise<{ t3n: Awaited<ReturnType<typeof connectTenant>>["t3n"]; nodeUrl: string; readiness: JsonObject }> {
  progress("t3n-connect");
  const connected = await connectTenant();
  requireCondition(connected.tenantDid === OPERATOR_DID, "operator DID mismatch");
  progress("t3n-contract-map");
  const inventory = (await connected.tenant.contracts.listDetailed()).contracts.find((item) => item.name === CONTRACT_ID && item.version === CONTRACT_VERSION);
  const mapStatus = await connected.tenant.maps.getStatus(INCIDENT_MAP_TAIL);
  const org = new SessionOrgDataClient(connected.t3n, connected.nodeUrl);
  progress("t3n-organization-readback");
  const admin = await org.amIAdmin({ orgDid: ORGANISATION_DID });
  const grants = await connected.t3n.getMemberDelegation();
  const rem = grants.grants.find((grant) => grant.grantee === REMEDIATION_DID && grant.contract_id === CONTRACT_ID);
  const broker = grants.grants.find((grant) => grant.grantee === BROKER_DID && grant.contract_id === CONTRACT_ID);
  const remEgress = await org.getAgentEgress({ orgDid: ORGANISATION_DID, agentDid: REMEDIATION_DID, contractId: CONTRACT_ID });
  const brokerEgress = await org.getAgentEgress({ orgDid: ORGANISATION_DID, agentDid: BROKER_DID, contractId: CONTRACT_ID });
  requireCondition(inventory?.status === "active" && mapStatus === "active" && admin, "C1 contract/map/operator readiness failed");
  requireCondition(rem?.version_req === CONTRACT_VERSION && JSON.stringify([...(rem.functions ?? [])].sort()) === JSON.stringify([RESERVATION_FUNCTION]) && !remEgress.egress, "remediation delegation readiness failed");
  requireCondition(broker?.version_req === CONTRACT_VERSION && JSON.stringify([...(broker.functions ?? [])].sort()) === JSON.stringify([...BROKER_FUNCTIONS].sort()) && !brokerEgress.egress, "broker delegation readiness failed");
  progress("t3n-principal-probes");
  const noSuch = `C2-E2E-R2-READINESS-${Date.now()}-${randomBytes(4).toString("hex")}`;
  const operatorRead = c1Response(await invokeC1OperatorSession(connected.t3n, CONTRACT_ID, "get-incident", { incident_id: noSuch }), "get-incident");
  requireCondition(operatorRead.result === "DENIED" && operatorRead.note === "incident authority does not exist", "operator C1 readiness did not return harmless nonexistent-incident denial");
  const agentProbe = c1Response(await invokeC1(agentKey, connected.nodeUrl, CONTRACT_ID, RESERVATION_FUNCTION, { incident_id: `${noSuch}-agent` }), RESERVATION_FUNCTION);
  const brokerProbe = c1Response(await invokeC1(brokerKey, connected.nodeUrl, CONTRACT_ID, "claim-effect", { incident_id: `${noSuch}-broker`, expected_claim_version: 0, contender_nonce: randomBytes(16).toString("hex") }), "claim-effect");
  requireCondition(agentProbe.result === "DENIED" && brokerProbe.result === "DENIED", "principal readiness probes did not return harmless denials");
  const balance = await connected.t3n.getBalance();
  requireCondition(balance.credit_exhausted !== true, "operator credits are exhausted");
  return { t3n: connected.t3n, nodeUrl: connected.nodeUrl, readiness: { contract: { name: CONTRACT_ID, version: inventory?.version, status: inventory?.status, numeric_id: 878 }, map_status: mapStatus, operator_admin: admin, delegations: { remediation: { did: REMEDIATION_DID, functions: rem?.functions ?? [], version_req: rem?.version_req ?? null, egress: Boolean(remEgress.egress) }, broker: { did: BROKER_DID, functions: broker?.functions ?? [], version_req: broker?.version_req ?? null, egress: Boolean(brokerEgress.egress) } }, probes: { operator: { function: "get-incident", result: operatorRead.result, note: operatorRead.note }, agent: { function: RESERVATION_FUNCTION, result: agentProbe.result, note: agentProbe.note }, broker: { function: "claim-effect", result: brokerProbe.result, note: brokerProbe.note } }, operator_balance: { available_base_units: balance.available, reserved_base_units: balance.reserved, credit_exhausted: balance.credit_exhausted }, provider_mutations: 0 } };
}

async function cleanupFreshTarget(reason: string): Promise<JsonObject | null> {
  if (!targetId || incidentCreated || effectStartConfirmed || !appJwtValue) return null;
  let token: string | null = null;
  try {
    const minted = await mintInstallationToken({ administration: "write" }, secretPushIssued ? "fixture-emergency-cleanup" : "fixture-setup-cleanup"); token = minted.token;
    const exact = await githubRequest(token, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/keys/${targetId}`);
    requireCondition(exact.status === 200 && object(exact.body).id === targetId, "cleanup target identity was not confirmed");
    const deletion = await githubRequest(token, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/keys/${targetId}`, { method: "DELETE" });
    const after = await githubRequest(token, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/keys/${targetId}`);
    const cleanup = { classification: secretPushIssued ? "FIXTURE_EMERGENCY_CLEANUP" : "PRE_TRIGGER_FIXTURE_CLEANUP", reason, deploy_key_id: targetId, delete_http_status: deletion.status, exact_after_http_status: after.status, absent: deletion.status === 204 && after.status === 404 };
    const lifecycle = await revokeAndRefuse(token); token = null;
    return { ...cleanup, token_cleanup: lifecycle };
  } finally { if (token) { try { await revokeAndRefuse(token); } catch {} } }
}

async function main(): Promise<void> {
  progress("load-credentials");
  const pat = process.env.GITHUB_PAT ?? await envFileValue(".env.bootstrap", "GITHUB_PAT");
  if (!process.env.GITHUB_PAT) process.env.GITHUB_PAT = pat;
  if (!process.env.T3N_API_KEY) process.env.T3N_API_KEY = await envFileValue(".env.bootstrap", "T3N_API_KEY");
  const agentKey = await envFileValue(".env.replacement-agent", "REPLACEMENT_AGENT_T3N_API_KEY");
  const brokerKey = await envFileValue(".env.effect-broker", "EFFECT_BROKER_T3N_API_KEY");
  const appFile = await readFile(path.join(root, ".env.c0r-github-app"), "utf8");
  appConfig = appConfigFromEnvironment({ GITHUB_APP_ID: envValue(appFile, "GITHUB_APP_ID"), GITHUB_APP_INSTALLATION_ID: envValue(appFile, "GITHUB_APP_INSTALLATION_ID"), GITHUB_APP_PRIVATE_KEY_PATH: envValue(appFile, "GITHUB_APP_PRIVATE_KEY_PATH"), GITHUB_OWNER: SANDBOX_OWNER, GITHUB_REPO: SANDBOX_REPOSITORY });
  appJwtValue = await appJwt(appConfig);
  requireCondition(await runGit(["branch", "--show-current"]) === CODE_BRANCH, "E2E must run on winner-v2-core");
  const executionHead = await runGit(["rev-parse", "HEAD"]);
  STARTING_SHA = executionHead;
  MAIN_SHA = await runGit(["rev-parse", "origin/main"]);
  BEFORE_SHA = requireValue("C2_E2E_EXPECTED_BEFORE_SHA");
  requireCondition(/^[0-9a-f]{40}$/i.test(STARTING_SHA), "runtime starting SHA is invalid");
  requireCondition(/^[0-9a-f]{40}$/i.test(MAIN_SHA), "runtime main SHA is invalid");
  requireCondition(/^[0-9a-f]{40}$/i.test(BEFORE_SHA), "C2_E2E_EXPECTED_BEFORE_SHA is invalid");
  requireCondition(await runGit(["rev-parse", "origin/winner-v2-core"]) === executionHead, "origin/winner-v2-core must equal the clean E2E code head");
  requireCondition(await runGit(["rev-parse", "origin/main"]) === MAIN_SHA, "origin/main changed during launch checkpoint");
  requireCondition((await runGit(["status", "--porcelain", "--untracked-files=all"])) === "", "working tree is not clean at E2E start");
  const registration = await readJson<JsonObject>("winner/evidence/contract-registration.json");
  requireCondition(registration.contract?.version === CONTRACT.version && registration.contract?.contract_id === CONTRACT.numeric_id && registration.contract?.wasm_bytes === CONTRACT.wasm_bytes && registration.contract?.wasm_sha256 === CONTRACT.wasm_sha256, "C1 artifact identity changed");
  for (const file of [POLICY_FILE, MARKER_FILE, FINAL_FILE, RETIREMENT_FILE]) { try { await access(path.join(root, file)); throw new Error(`${file} already exists; refusing a second E2E run`); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; } }

  progress("start-receiver-and-verify-ingress");
  tempRunDirectory = await mkdtemp(path.join(os.tmpdir(), "t3n-c2-e2e-r2-run-"));
  const capturePath = path.join(tempRunDirectory, "github-delivery.json");
  const dedupeDirectory = path.join(tempRunDirectory, "dedupe");
  const webhookSecret = await envFileValue(".env.c2-b0-live", "C2_WEBHOOK_SECRET");
  await stopExistingB0Receiver();
  receiver = await startE2EReceiver(webhookSecret, capturePath, dedupeDirectory);
  const ingressLive = await ingressReachability();
  const appBefore = await appReadiness();
  progress("verify-t3n-and-capabilities");
  const t3nReady = await t3nReadiness(agentKey, brokerKey);
  progress("setup-token-capability");
  const setupCapability = await mintInstallationToken({ administration: "write" }, "setup-capability-preflight");
  const setupCapabilityCleanup = await revokeAndRefuse(setupCapability.token);
  progress("source-token-capability");
  const sourceCapability = await mintInstallationToken({ contents: "read" }, "source-capability-preflight");
  progress("verifier-token-capability");
  const verifierCapability = await mintInstallationToken({ administration: "read" }, "verifier-capability-preflight");
  const verifierCapabilityCleanup = await revokeAndRefuse(verifierCapability.token);
  progress("verify-clean-baseline");
  let baseline: JsonObject;
  let sourceCapabilityCleanup: JsonObject;
  try { baseline = await verifyBaseline(sourceCapability.token); }
  finally { sourceCapabilityCleanup = await revokeAndRefuse(sourceCapability.token); }
  requireCondition(baseline.branch_head_sha === BEFORE_SHA, "baseline changed during preflight");
  const executionCheckpoint = freezeLiveExecutionCheckpoint({
    starting_sha: STARTING_SHA,
    expected_before_sha: BEFORE_SHA,
    expected_main_sha: MAIN_SHA,
    origin_winner_sha: await runGit(["rev-parse", "origin/winner-v2-core"]),
    origin_main_sha: await runGit(["rev-parse", "origin/main"]),
    sandbox_before_sha: baseline.branch_head_sha,
    runner_implementation_final: process.env.C2_E2E_RUNNER_IMPLEMENTATION_FINAL === "true",
    receiver_implementation_final: process.env.C2_E2E_RECEIVER_IMPLEMENTATION_FINAL === "true",
    verifier_implementation_final: process.env.C2_E2E_VERIFIER_IMPLEMENTATION_FINAL === "true",
    tests_passed: process.env.C2_E2E_PREFLIGHT_TESTS_PASSED === "true",
    implementation_commit_after_freeze: process.env.C2_E2E_IMPLEMENTATION_COMMIT_AFTER_FREEZE === "true",
  });

  requireCondition((await appReadiness()).hook.configured === true, "webhook configuration changed before target setup");

  progress("generate-key-and-create-target");
  const key = await generateKeyAndStage();
  const target = await createTarget(key.publicKey, key.title, key.fingerprint);
  requireCondition(target.id === targetId, "fresh target ID was not retained");
  const historicalB1PolicyWrapper = await readJson<JsonObject>(HISTORICAL_B1_POLICY_FILE);
  const historicalB1Policy = historicalB1PolicyWrapper.policy as C2PushPolicyV2;
  const historicalR1PolicyWrapper = await readJson<JsonObject>(HISTORICAL_R1_POLICY_FILE);
  const historicalR1Policy = historicalR1PolicyWrapper.policy as C2PushPolicyV2;
  const historicalPolicies = [historicalB1Policy, historicalR1Policy];
  const b1Retirement = await readJson<JsonObject>(HISTORICAL_B1_RETIREMENT_FILE);
  const r1Retirement = await readJson<JsonObject>(HISTORICAL_R1_RETIREMENT_FILE);
  const retirement = b1Retirement;
  const retiredIds = retiredPolicyIdSet([
    { policy_id: b1Retirement.historical_policy_id, retired: true, retirement_reason: b1Retirement.failure_classification, retirement_timestamp: b1Retirement.retirement_timestamp, retirement_evidence_identity: b1Retirement.retirement_evidence_identity },
    { policy_id: r1Retirement.policy_id ?? r1Retirement.historical_policy_id, retired: true, retirement_reason: r1Retirement.reason ?? r1Retirement.failure_classification ?? "historical failed E2E policy", retirement_timestamp: r1Retirement.retirement_timestamp, retirement_evidence_identity: r1Retirement.retirement_evidence_identity },
  ]);
  const policyId = `c2-policy:github-push-c2-e2e-r2-${Date.now()}-${randomBytes(6).toString("hex")}`;
  const policy = buildC2PushPolicyV2({ policy_id: policyId, policy_version: 2, deploy_key_id: target.id, expected_deploy_key_title: key.title, expected_read_only: true, expected_public_key_fingerprint: key.fingerprint, expected_private_material_sha256: key.privateDigest, remediation_agent_did: REMEDIATION_DID, effect_broker_did: BROKER_DID, ttl_secs: 900, enabled: true, actual_creation_timestamp: new Date().toISOString(), creation_commit_or_registry_identity: policyId, provenance: { classification: "LIVE_PROVENANCE", creation_evidence: `${POLICY_FILE} remote readback`, enabled_before_event_proof: true } });
  const policySelection = lookupPreExistingPushPolicy({ provider: "github", event_type: "push", action: "push", delivery_id: "00000000-0000-0000-0000-000000000001", repository_id: SANDBOX_REPOSITORY_ID, repository_full_name: `${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}`, ref: SANDBOX_REF, before: BEFORE_SHA, after: "1".repeat(40), deleted: false, forced: false, created: false, sender_login: "preflight", raw_body_sha256: "0".repeat(64) }, [...historicalPolicies, policy], { retiredPolicyIds: retiredIds });
  requireCondition(policySelection.kind === "MATCH" && policySelection.policy.policy_id === policyId, "retired historical policy plus fresh policy did not uniquely match");
  progress("freeze-policy-and-marker");
  const authorityFields = { ...policy };
  const policyBytes = await writeJson(POLICY_FILE, { artifact: "C2-E2E-R2 LIVE AUTHORITY-BEARING POLICY", registry_identity: policyId, policy: authorityFields });
  const policyFreezeSha = await commitAndPush([POLICY_FILE], `c2: freeze E2E-R2 live policy ${policyId}`);
  const remotePolicy = await remotePolicyReadback(pat, policy, policyBytes, policyFreezeSha);
  const marker = { artifact: "POLICY_FROZEN_AND_REMOTE_CONFIRMED", registry_identity: policyId, policy_freeze_commit_sha: policyFreezeSha, policy_content_sha256: remotePolicy.policy_content_sha256, remote_readback_success: true, remote_readback_date: remotePolicy.remote_readback_date, deploy_key_id: target.id, expected_public_key_fingerprint: key.fingerprint, expected_private_material_sha256: key.privateDigest, enabled_before_event_proof: true };
  await writeJson(MARKER_FILE, marker);
  const markerSha = await commitAndPush([MARKER_FILE], `c2: attest E2E-R2 policy freeze ${policyId}`);
  const targetVerifierCapability = await mintInstallationToken({ administration: "read" }, "target-pretrigger-verifier");
  let targetVerifierCleanup: JsonObject;
  let preTriggerTarget: JsonObject;
  try { preTriggerTarget = await verifyTarget(targetVerifierCapability.token, target.id, key.title, key.publicKey); }
  finally { targetVerifierCleanup = await revokeAndRefuse(targetVerifierCapability.token); }
  const stagedBefore = await runBuffer("git", ["cat-file", "blob", key.blobSha], stagingDirectory!);
  requireCondition(sha256(stagedBefore) === key.privateDigest && Buffer.compare(stagedBefore, privateBytes!) === 0, "staged secret bytes changed after policy freeze");
  progress("issue-one-secret-trigger");
  const trigger = await triggerSecret(stagedBefore);
  stagedBefore.fill(0); if (stagedBytes) { stagedBytes.fill(0); stagedBytes = null; } if (privateBytes) { privateBytes.fill(0); privateBytes = null; } if (tempKeyDirectory) { await rm(tempKeyDirectory, { recursive: true, force: true }); tempKeyDirectory = null; } if (stagingDirectory) { await rm(stagingDirectory, { recursive: true, force: true }); stagingDirectory = null; }
  const capture = await awaitDelivery(capturePath, trigger.sha);
  progress("verify-delivery-and-transition");
  const history = await deliveryHistory(String(capture.delivery_id));
  requireCondition(remotePolicy.remote_readback_date && history.delivered_at && Date.parse(String(remotePolicy.remote_readback_date)) < Date.parse(String(history.delivered_at)), "remote policy readback was not before GitHub delivery");
  const raw = receiver?.getRaw(); const rawHeaders = receiver?.getHeaders() ?? {};
  requireCondition(raw, "real delivery raw bytes were not retained in process memory");
  const sourceMint = await mintInstallationToken({ contents: "read" }, "source-reader");
  const sourcePermissions = sourceMint.metadata.actual_permissions;
  requireCondition(sourcePermissions.contents === "read" && sourcePermissions.administration !== "write", "source-reader token scope is too broad");
  const beforeRead = await readContentDigest(sourceMint.token, BEFORE_SHA);
  const afterRead = await readContentDigest(sourceMint.token, trigger.sha);
  requireCondition(beforeRead.status === 404 && beforeRead.digest === null && afterRead.status === 200 && afterRead.digest === key.privateDigest, "immutable source reads did not prove exact 404 to digest transition");
  const sourceCleanup = await revokeAndRefuse(sourceMint.token);
  const rawRequest = { headers: rawHeaders, body: raw };
  const observations: { before: ImmutablePathObservation; after: ImmutablePathObservation } = { before: { repository: `${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}`, commit_sha: BEFORE_SHA, path: SECRET_PATH, status: 404 }, after: { repository: `${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}`, commit_sha: trigger.sha, path: SECRET_PATH, status: 200, content_sha256: afterRead.digest! } };
  const c2 = await processPushWebhook(rawRequest, webhookSecret, dedupeDirectory, [...historicalPolicies, policy], observations, { retiredPolicyIds: retiredIds });
  requireCondition(c2.classification === "C2_PUSH_SELECTED", `C2 production pipeline rejected the real transition: ${c2.classification}`);
  requireCondition(c2.dedupe.status === "DUPLICATE_SAME" && c2.create_request.deploy_key_id === target.id, "C2 pipeline did not resume the receiver's durable NEW reservation exactly");
  const event = c2.event;
  const readPlan = createImmutablePushReadPlan(event, policy);
  const transition = verifyPushSecretTransition(observations.before, observations.after, policy, readPlan);
  requireCondition(transition.classification === "CAUSAL_SECRET_INTRODUCED", "transition verifier did not return CAUSAL_SECRET_INTRODUCED");
  const derivedRequest = c2.create_request;
  const verificationContext: B1VerificationContext = { expectedStartingSha: STARTING_SHA, expectedMainSha: MAIN_SHA, expectedBeforeSha: BEFORE_SHA };
  const b1Evidence = buildB1Evidence({ starting_sha: STARTING_SHA, main_sha: MAIN_SHA, b0_before_sha: BEFORE_SHA, policy_freeze_commit_sha: policyFreezeSha, policy_marker_commit_sha: markerSha, final_sha: "recorded_by_containing_git_commit", ingress_readiness: ingressLive, app_readback: appBefore, fresh_deploy_key: target, private_material_sha256: key.privateDigest, policy: { registry_identity: policyId, policy_version: 2, authority_fields: authorityFields, content_sha256: remotePolicy.policy_content_sha256, remote_readback: remotePolicy }, policy_before_event: { policy_freeze_commit_sha: policyFreezeSha, marker_commit_sha: markerSha, remote_policy_readback_before_trigger: true, marker_persisted_before_trigger: true, trigger_issued_after_marker: true, policy_readback_completed_at: remotePolicy.remote_readback_date }, pre_trigger_target_recheck: preTriggerTarget, secret_trigger_commit: trigger, real_delivery: { delivery_id: event.delivery_id, event_type: event.event_type, repository_id: event.repository_id, repository_full_name: event.repository_full_name, ref: event.ref, before: event.before, after: event.after, created: event.created, forced: event.forced, deleted: event.deleted, sender_login: event.sender_login, raw_body_sha256: event.raw_body_sha256, signature_verified: true, raw_body_persisted: false, webhook_secret_persisted: false, authority_processing_attempted: false, authority_eligible: false, dedupe_status: "NEW" }, immutable_before: { status: beforeRead.status, commit_sha: BEFORE_SHA, path: SECRET_PATH }, immutable_after: { status: afterRead.status, commit_sha: trigger.sha, path: SECRET_PATH, content_sha256: afterRead.digest }, transition_classification: transition.classification, immutable_read_plan: readPlan, derived_c1_request: derivedRequest, source_reader_token: { ...sourceMint.metadata, requested_permissions: { contents: "read" }, actual_permissions: sourcePermissions, immutable_before_http_status: beforeRead.status, immutable_after_http_status: afterRead.status, revoke_http_status: sourceCleanup.revoke_http_status, refusal_http_status: sourceCleanup.refusal_http_status, administration_write_granted: false, token_value_persisted: false }, github_delivery_corroboration: history, c1_artifact: CONTRACT, mutation_counters: { t3n_create_calls: 0, provider_effects: 0 }, sensitive_value_hygiene: { private_material_in_policy: false, private_material_in_evidence: false, raw_webhook_body_in_evidence: false, webhook_secret_in_evidence: false } });
  const b1Verification = verifyB1Evidence(b1Evidence, verificationContext);
  requireCondition(b1Verification.valid && b1Verification.reasons.length === 0, `B1 verifier failed before T3N create: ${b1Verification.reasons.join(", ")}`);

  progress("create-and-reserve-c1-authority");
  const connected = await connectTenant();
  requireCondition(connected.tenantDid === OPERATOR_DID, "operator DID changed before C1 create");
  const create = c1Response(await invokeC1OperatorSession(connected.t3n, CONTRACT_ID, "create-incident", derivedRequest), "create-incident", "WON");
  incidentCreated = true;
  requireCondition(create.state === "ACTIVE" && object(create.detail).action === ACTION && object(create.detail).github_owner === SANDBOX_OWNER && object(create.detail).github_repo === SANDBOX_REPOSITORY && object(create.detail).deploy_key_id === target.id && object(create.detail).remediation_agent_did === REMEDIATION_DID && object(create.detail).effect_broker_did === BROKER_DID && object(create.detail).effect_attempts === 0, "created T3N authority does not match derived request");
  const active = c1Response(await invokeC1OperatorSession(connected.t3n, CONTRACT_ID, "get-incident", { incident_id: derivedRequest.incident_id }), "get-incident", "FOUND");
  requireCondition(active.state === "ACTIVE" && object(active.detail).deploy_key_id === target.id && object(active.detail).effect_attempts === 0, "ACTIVE readback mismatch");
  const reserve = c1Response(await invokeC1(agentKey, connected.nodeUrl, CONTRACT_ID, RESERVATION_FUNCTION, { incident_id: derivedRequest.incident_id }), RESERVATION_FUNCTION, "WON");
  requireCondition(reserve.state === "RESERVED", "reservation did not reach RESERVED");
  const reserved = c1Response(await invokeC1OperatorSession(connected.t3n, CONTRACT_ID, "get-incident", { incident_id: derivedRequest.incident_id }), "get-incident", "FOUND");
  requireCondition(reserved.state === "RESERVED" && object(reserved.detail).effect_attempts === 0, "RESERVED readback mismatch");

  const brokerRun = await mkdtemp(path.join(os.tmpdir(), "t3n-c2-e2e-r2-broker-"));
  progress("run-two-broker-contenders");
  const barrier = path.join(brokerRun, "claim-release.json"); const proposalsComplete = path.join(brokerRun, "claim-proposals-complete.json"); const effectReady = path.join(brokerRun, "effect-start-ready.json"); const preDeleteRelease = path.join(brokerRun, "pre-delete-release.json");
  const brokerEnvironment = childEnvironment({ EFFECT_BROKER_T3N_API_KEY: brokerKey, EFFECT_BROKER_DID: BROKER_DID, C1_BARRIER_FILE: barrier, C1_PROPOSALS_COMPLETE_FILE: proposalsComplete, C1_OPERATOR_DID: OPERATOR_DID, C1_EXPECTED_CLAIM_VERSION: "0", C1_EXPECTED_TARGET_TITLE: key.title, C1_EFFECT_START_READY_FILE: effectReady, C1_PRE_DELETE_RELEASE_FILE: preDeleteRelease, GITHUB_APP_ID: appConfig.appId, GITHUB_APP_INSTALLATION_ID: appConfig.installationId, GITHUB_APP_PRIVATE_KEY_PATH: appConfig.privateKeyPath, GITHUB_OWNER: SANDBOX_OWNER, GITHUB_REPO: SANDBOX_REPOSITORY });
  const brokerAFile = path.join(brokerRun, "broker-a.result.json"); const brokerBFile = path.join(brokerRun, "broker-b.result.json"); const readyA = path.join(brokerRun, "broker-a.ready.json"); const readyB = path.join(brokerRun, "broker-b.ready.json");
  const aPromise = runChild(path.join(root, "winner/broker/run.ts"), [derivedRequest.incident_id], { ...brokerEnvironment, C1_READY_FILE: readyA, C1_RESULT_FILE: brokerAFile, C1_CONTENDER_ID: "broker-a" });
  const bPromise = runChild(path.join(root, "winner/broker/run.ts"), [derivedRequest.incident_id], { ...brokerEnvironment, C1_READY_FILE: readyB, C1_RESULT_FILE: brokerBFile, C1_CONTENDER_ID: "broker-b" });
  try { await Promise.all([waitForFile(readyA, 120_000), waitForFile(readyB, 120_000)]); } catch (error) { await writeAtomicJson(barrier, { abort: true, reason: "contender readiness failed" }); await Promise.all([aPromise, bPromise]); throw error; }
  await writeAtomicJson(barrier, { incident_id: derivedRequest.incident_id, released_once: true });
  await Promise.all([waitForFile(brokerAFile, 120_000), waitForFile(brokerBFile, 120_000)]);
  await writeAtomicJson(proposalsComplete, { incident_id: derivedRequest.incident_id, both_results_persisted: true, confirmation_allowed_after_marker: true });
  await waitForFile(effectReady, 120_000);
  const effectReadyDoc = await readJson<JsonObject>(effectReady);
  const beforeDeleteState = c1Response(await invokeC1OperatorSession(connected.t3n, CONTRACT_ID, "get-incident", { incident_id: derivedRequest.incident_id }), "get-incident", "FOUND");
  requireCondition(beforeDeleteState.state === "EFFECT_STARTED" && object(beforeDeleteState.detail).effect_attempts === 1 && beforeDeleteState.detail.effect_start_id === effectReadyDoc.effect_start_id, "effect-start was not committed before provider authority release");
  effectStartConfirmed = true;
  await writeAtomicJson(preDeleteRelease, { incident_id: derivedRequest.incident_id, operator_authority_verified: true, released_once: true });
  const [aResult, bResult] = await Promise.all([aPromise, bPromise]);
  const brokerA = await readJson<JsonObject>(brokerAFile); const brokerB = await readJson<JsonObject>(brokerBFile); const brokerResults = [brokerA, brokerB];
  requireCondition(aResult.code === 0 && bResult.code === 0, `broker child failed: ${redact(`${aResult.stderr} ${bResult.stderr}`, [brokerKey])}`);
  const brokerAdjudication = adjudicateBrokerResults(brokerResults);
  requireCondition(brokerAdjudication.valid && brokerAdjudication.confirmed_owner_count === 1, `broker ownership adjudication failed: ${brokerAdjudication.reason}`);
  const winner = brokerResults.find((item) => item.contender === brokerAdjudication.owner_contender);
  const loser = brokerResults.find((item) => item.contender !== brokerAdjudication.owner_contender);
  requireCondition(winner && loser, "broker adjudication did not identify owner and non-owner contenders");
  requireCondition(loser.token_minted === false && loser.provider_credential_mint_count === 0 && loser.destructive_call_count === 0 && loser.delete_attempted === false && loser.provider_calls_after_ownership_loss === 0 && !Object.prototype.hasOwnProperty.call(loser, "effect_token"), "loser crossed provider authority boundary");
  const closed = c1Response(await invokeC1OperatorSession(connected.t3n, CONTRACT_ID, "get-incident", { incident_id: derivedRequest.incident_id }), "get-incident", "FOUND");
  requireCondition(closed.state === "CLOSED" && object(closed.detail).effect_attempts === 1 && object(closed.detail).final_result_classification === "VERIFIED_ABSENT", "C1 did not close VERIFIED_ABSENT");
  requireCondition(winner.destructive_call_count === 1 && winner.delete?.http_status === 204 && winner.after?.target_absent === true && winner.verifier_token?.mutation_count === 0, "provider effect/verification was not exact");

  progress("replay-and-retire-policy");
  const replayRequest = { headers: rawHeaders, body: raw };
  const c2Replay = await processPushWebhook(replayRequest, webhookSecret, dedupeDirectory, [...historicalPolicies, policy], observations, { retiredPolicyIds: retiredIds });
  requireCondition(c2Replay.classification === "C2_PUSH_SELECTED" && c2Replay.replayed === true && c2Replay.dedupe.status === "DUPLICATE_SAME" && c2Replay.incident_id === derivedRequest.incident_id && JSON.stringify(c2Replay.create_request) === JSON.stringify(derivedRequest), "C2 replay did not return the durable request");
  const c1ReplayReserve = c1Response(await invokeC1(agentKey, connected.nodeUrl, CONTRACT_ID, RESERVATION_FUNCTION, { incident_id: derivedRequest.incident_id }), RESERVATION_FUNCTION);
  const replayRun = await mkdtemp(path.join(os.tmpdir(), "t3n-c2-e2e-r2-replay-")); const replayBarrier = path.join(replayRun, "barrier.json"); const replayReady = path.join(replayRun, "ready.json"); const replayResult = path.join(replayRun, "result.json");
  const replayPromise = runChild(path.join(root, "winner/broker/run.ts"), [derivedRequest.incident_id], { ...brokerEnvironment, C1_BARRIER_FILE: replayBarrier, C1_PROPOSALS_COMPLETE_FILE: path.join(replayRun, "proposals.json"), C1_READY_FILE: replayReady, C1_RESULT_FILE: replayResult, C1_CONTENDER_ID: "replay", C1_EXPECTED_CLAIM_VERSION: String(object(closed.detail).effect_claim_version ?? 1), C1_EFFECT_START_READY_FILE: "", C1_PRE_DELETE_RELEASE_FILE: "" });
  await waitForFile(replayReady, 60_000); await writeAtomicJson(replayBarrier, { incident_id: derivedRequest.incident_id, released_once: true }); await waitForFile(replayResult, 60_000); const replayBroker = await readJson<JsonObject>(replayResult); const replayChild = await replayPromise;
  requireCondition(replayChild.code === 0 && replayBroker.token_minted === false && replayBroker.provider_credential_mint_count === 0 && replayBroker.destructive_call_count === 0 && replayBroker.delete_attempted === false, "C1 replay obtained provider authority");
  const terminalAgain = c1Response(await invokeC1OperatorSession(connected.t3n, CONTRACT_ID, "get-incident", { incident_id: derivedRequest.incident_id }), "get-incident", "FOUND");
  requireCondition(terminalAgain.state === "CLOSED" && object(terminalAgain.detail).effect_attempts === 1 && JSON.stringify(terminalAgain.detail) === JSON.stringify(closed.detail), "C1 replay changed terminal state");
  const policyRetirement = { artifact: "C2-E2E-R2-POLICY-RETIREMENT", policy_id: policyId, deploy_key_id: target.id, terminal_incident_id: derivedRequest.incident_id, terminal_classification: "VERIFIED_ABSENT", retired: true, retirement_timestamp: new Date().toISOString(), retirement_evidence_identity: FINAL_FILE, reason: "C2_E2E_R2_COMPLETED_TARGET_REMOVED" };
  const bundle: JsonObject = { classification: "C2_E2E_R1_FULL_CAUSAL_REMEDIATION_PASS", starting_sha: STARTING_SHA, execution_code_head_sha: executionHead, execution_checkpoint: executionCheckpoint, policy_freeze_sha: policyFreezeSha, final_sha: "recorded_by_containing_git_commit", main_sha: MAIN_SHA, sandbox_before_sha: BEFORE_SHA, sandbox_secret_commit_sha: trigger.sha, ingress_readiness: ingressLive, github_app_readiness: appBefore, t3n_readiness: t3nReady.readiness, provider_capability_preflight: { setup: { ...setupCapability.metadata, lifecycle: setupCapabilityCleanup }, source: { ...sourceCapability.metadata, lifecycle: sourceCapabilityCleanup }, verifier: { ...verifierCapability.metadata, lifecycle: verifierCapabilityCleanup } }, sandbox_baseline: baseline, fresh_target: target, policy: { registry_identity: policyId, policy_version: 2, authority_fields: authorityFields, content_sha256: remotePolicy.policy_content_sha256, remote_readback: remotePolicy }, historical_policy_retirement: { historical_policy_id: retirement.historical_policy_id, historical_deploy_key_id: retirement.historical_deploy_key_id, retired: true, cleanup_proven: retirement.cleanup_proven }, policy_before_event: { policy_freeze_commit_sha: policyFreezeSha, marker_commit_sha: markerSha, remote_policy_readback_before_trigger: true, marker_persisted_before_trigger: true, trigger_issued_after_marker: true, remote_policy_readback_date: remotePolicy.remote_readback_date, trigger_delivery_at: history.delivered_at }, secret_trigger_commit: trigger, real_delivery: { event_type: "push", delivery_id: capture.delivery_id, repository_id: capture.repository_id, repository_full_name: capture.repository_full_name, ref: capture.ref, before: capture.before, after: capture.after, created: capture.created, forced: capture.forced, deleted: capture.deleted, sender_login: capture.sender_login, raw_body_sha256: capture.raw_body_sha256, signature_verified: true, raw_body_persisted: false, webhook_secret_persisted: false, authority_processing_attempted: false, authority_eligible: true, classification: "REAL_AUTHENTICATED_PUSH_WITH_CAUSAL_TRANSITION", dedupe_status: "NEW" }, immutable_before: { status: beforeRead.status, commit_sha: BEFORE_SHA, path: SECRET_PATH }, immutable_after: { status: afterRead.status, commit_sha: trigger.sha, path: SECRET_PATH, content_sha256: afterRead.digest }, transition_classification: transition.classification, b1_evidence: b1Evidence, b1_verifier: { valid: b1Verification.valid, reasons: b1Verification.reasons, context: verificationContext }, derived_c1_request: derivedRequest, t3n: { create: sanitize(create), active_readback: sanitize(active), reservation: sanitize(reserve), reserved_readback: sanitize(reserved), brokers: { broker_a: sanitize(brokerA, [brokerKey]), broker_b: sanitize(brokerB, [brokerKey]), adjudication: brokerAdjudication, winner: winner.contender, loser: loser.contender, confirmed_owner_count: brokerAdjudication.confirmed_owner_count }, pre_delete_authority: sanitize({ effect_start_ready: effectReadyDoc, operator_readback: beforeDeleteState, delete_allowed_after_this_read: true }), closed_readback: sanitize(closed), effect_start_id: winner.effect_start_id, finalization: sanitize(winner.finalize), final_result_classification: "VERIFIED_ABSENT" }, provider_effect: { delete_attempt_count: winner.destructive_call_count, delete_http_status: winner.delete?.http_status, delete_request_id: winner.delete?.provider_request_id ?? null, target_absent: winner.after?.target_absent === true }, effect_token: sanitize({ ...winner.effect_token, cleanup: winner.effect_token_cleanup }), independent_verifier: sanitize({ token: winner.verifier_token, readback: winner.independent_provider_verification, cleanup: winner.verifier_token_cleanup }), c2_replay: { classification: c2Replay.dedupe.status, incident_id: c2Replay.incident_id, create_request: c2Replay.create_request, new_immutable_source_reads: 0, new_t3n_incident_creations: 0, provider_authority_count: 0, provider_mutations: 0 }, c1_replay: { remediation_reserve: sanitize(c1ReplayReserve), closed_replay_rejected: c1ReplayReserve.result !== "WON", broker: sanitize(replayBroker, [brokerKey]), new_effect_token_mints: 0, new_delete_count: 0, effect_attempts: 1, target_absent: true }, successful_policy_retirement: policyRetirement, mutation_counters: { fixture_setup: { ssh_key_generations: 1, deploy_key_creates: 1 }, causal_source: { secret_trigger_pushes: 1 }, t3n_protocol: { incident_creates: 1, reservations: 1, effect_attempts: 1 }, provider_effect: { deploy_key_deletes: 1 }, independent_verification: { provider_mutations: 0 }, replay: { provider_token_mints: 0, provider_mutations: 0, deploy_key_deletes: 0 } }, sensitive_value_hygiene: { private_material_in_policy: false, private_material_in_evidence: false, raw_webhook_body_in_evidence: false, app_private_key_in_evidence: false, installation_token_in_evidence: false, webhook_secret_in_evidence: false, raw_webhook_body_retained_only_in_process_memory: true, private_local_copy_removed_after_trigger: true }, tests: { b1_verifier: "PASS", c2_replay: "PASS", c1_replay: "PASS", offline_e2e_verifier: "pending", c2_and_product: "run_before_final_commit" }, claims_earned: ["one real authenticated GitHub push introduced the exact private material bound by a pre-existing live policy to one fresh read-only deploy key", "immutable GitHub reads proved the exact 404-to-digest transition", "B1 evidence verified with an explicit execution context", "one exact C1 request created one bounded T3N incident", "one confirmed broker owner committed one effect-start and one provider DELETE", "independent verification proved the target absent and T3N closed VERIFIED_ABSENT", "C2 and C1 replay earned zero provider authority and zero provider mutation"], claims_forbidden: ["GitHub globally guarantees exactly-once", "atomic T3N/GitHub transaction", "ephemeral GitHub App root", "zero standing GitHub root authority", "arbitrary incident/provider support", "C2 submission readiness"] };
  bundle.classification = "C2_E2E_R2_FULL_CAUSAL_REMEDIATION_PASS";
  bundle.historical_policy_retirements = [
    { historical_policy_id: b1Retirement.historical_policy_id, historical_deploy_key_id: b1Retirement.historical_deploy_key_id, retired: true, cleanup_proven: b1Retirement.cleanup_proven },
    { historical_policy_id: r1Retirement.policy_id, historical_deploy_key_id: r1Retirement.deploy_key_id, retired: true, cleanup_proven: r1Retirement.cleanup_proven },
  ];
  target.pre_trigger_target_readback = { ...preTriggerTarget, token_lifecycle: { ...targetVerifierCapability.metadata, lifecycle: targetVerifierCleanup } };
  const offline = verifyE2EBundle(bundle, verificationContext satisfies E2EVerificationContext); requireCondition(offline.ok, `offline E2E verifier failed: ${offline.errors.join(", ")}`); bundle.tests.offline_e2e_verifier = "PASS";
  progress("write-final-evidence");
  await writeJson(FINAL_FILE, bundle); await writeJson(RETIREMENT_FILE, policyRetirement);
  const finalSha = await commitAndPush([FINAL_FILE, RETIREMENT_FILE], "c2: prove full causal GitHub-to-T3N remediation");
  if (receiver) { await receiver.close(); const rawToClear = receiver.getRaw(); rawToClear?.fill(0); receiver = null; }
  console.log(JSON.stringify({ classification: bundle.classification, final_sha: finalSha, policy_freeze_sha: policyFreezeSha, incident_id: derivedRequest.incident_id, deploy_key_id: target.id, delivery_id: event.delivery_id, secret_commit_sha: trigger.sha, delete_count: winner.destructive_call_count, final_state: closed.state, final_result_classification: "VERIFIED_ABSENT", evidence: FINAL_FILE }, null, 2));
}

main().catch(async (error) => {
  try { if (receiver) { await receiver.close(); const raw = receiver.getRaw(); raw?.fill(0); receiver = null; } } catch {}
  try { if (privateBytes) privateBytes.fill(0); if (stagedBytes) stagedBytes.fill(0); if (tempKeyDirectory) await rm(tempKeyDirectory, { recursive: true, force: true }); if (stagingDirectory) await rm(stagingDirectory, { recursive: true, force: true }); if (triggerDirectory) await rm(triggerDirectory, { recursive: true, force: true }); } catch {}
  let cleanup: JsonObject | null = null;
  try { cleanup = await cleanupFreshTarget(error instanceof Error ? error.message : String(error)); } catch {}
  console.error(JSON.stringify({ classification: "C2_E2E_R2_FAILURE", error: redact(error, [process.env.GITHUB_PAT ?? "", process.env.T3N_API_KEY ?? "", process.env.AGENT_T3N_API_KEY ?? "", process.env.EFFECT_BROKER_T3N_API_KEY ?? ""]), secret_push_issued: secretPushIssued, incident_created: incidentCreated, effect_start_confirmed: effectStartConfirmed, cleanup, no_automatic_second_run: true }, null, 2));
  process.exitCode = 1;
});
