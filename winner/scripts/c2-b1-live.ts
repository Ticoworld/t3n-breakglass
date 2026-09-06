import { createHash, randomBytes } from "node:crypto";
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import os from "node:os";
import path from "node:path";
import { appConfigFromEnvironment, appJwt } from "../broker/github-app.js";
import { buildC2PushPolicyV2, type C2PushPolicyV2 } from "../c2/push-policy.js";
import { createImmutablePushReadPlan } from "../c2/push-read-plan.js";
import { derivePushC1CreateRequest } from "../c2/push-c1.js";
import { verifyPushSecretTransition, type ImmutablePathObservation } from "../c2/push-transition.js";
import { verifyB1Evidence, type B1VerificationContext, B1_REPOSITORY, B1_REF, B1_SECRET_PATH } from "../c2/b1-verifier.js";
import { buildB1Evidence, serializeB1Evidence } from "../c2/b1-evidence.js";
import type { NormalizedPushEvent } from "../c2/types.js";

const execFileAsync = promisify(execFile);
const root = path.resolve(import.meta.dirname, "../..");
const API = "https://api.github.com";
const API_VERSION = "2022-11-28";
const CODE_OWNER = "Ticoworld";
const CODE_REPOSITORY = "t3n-breakglass";
const CODE_BRANCH = "winner-v2-core";
const SANDBOX_OWNER = "Ticoworld";
const SANDBOX_REPOSITORY = "t3n-breakglass-sandbox";
const INSTALLATION_ID = "158227303";
const APP_SLUG = "breakglass-c0r-jit-probe";
const B0_PUBLIC_URL = "https://dde7-197-210-70-114.ngrok-free.app";
const B0_ROUTE = "/c2-b0/github-push";
const B0_CAPTURE_ENV = ".env.c2-b0-live";
const POLICY_FILE = "winner/evidence/C2-B1-LIVE-POLICY.json";
const MARKER_FILE = "winner/evidence/C2-B1-POLICY-FROZEN-AND-REMOTE-CONFIRMED.json";
const FINAL_EVIDENCE_FILE = "winner/evidence/C2-B1-CAUSAL-SECRET-INTRODUCTION.json";
const REMEDIATION_DID = "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019";
const BROKER_DID = "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57";
const CONTRACT = { version: "2.0.4", id: 878, bytes: 227011, sha256: "ca7032b112b837b06e4334c10bca8820447f6ea1756b74db9bccd3181ad4d5d0" };
const CODE_REPO = `${CODE_OWNER}/${CODE_REPOSITORY}`;
const SANDBOX_REPO = `${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}`;
const SECRET_PATH_PARTS = B1_SECRET_PATH.split("/").map((part) => encodeURIComponent(part)).join("/");

type JsonObject = Record<string, any>;
type ApiResult = { status: number; body: unknown; headers: Record<string, string> };

let appConfig: ReturnType<typeof appConfigFromEnvironment> | null = null;
let appJwtValue: string | null = null;
let setupToken: string | null = null;
let sourceToken: string | null = null;
let targetId: number | null = null;
let secretPushIssued = false;
let completed = false;
let tempKeyDirectory: string | null = null;
let stagingDirectory: string | null = null;
let privateBytes: Buffer | null = null;
let stagedBytes: Buffer | null = null;
let executionContext: B1VerificationContext | null = null;

function asObject(value: unknown): JsonObject | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as JsonObject : null;
}

function requireCondition(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function requireExecutionContext(): B1VerificationContext {
  requireCondition(executionContext, "explicit B1 execution context is required");
  return executionContext;
}

function readExecutionContext(): B1VerificationContext {
  const context = {
    expectedStartingSha: process.env.C2_B1_EXPECTED_STARTING_SHA,
    expectedMainSha: process.env.C2_B1_EXPECTED_MAIN_SHA,
    expectedBeforeSha: process.env.C2_B1_EXPECTED_BEFORE_SHA,
  };
  requireCondition(typeof context.expectedStartingSha === "string" && /^[0-9a-f]{40}$/i.test(context.expectedStartingSha), "C2_B1_EXPECTED_STARTING_SHA is required and must be a 40-hex SHA");
  requireCondition(typeof context.expectedMainSha === "string" && /^[0-9a-f]{40}$/i.test(context.expectedMainSha), "C2_B1_EXPECTED_MAIN_SHA is required and must be a 40-hex SHA");
  requireCondition(typeof context.expectedBeforeSha === "string" && /^[0-9a-f]{40}$/i.test(context.expectedBeforeSha), "C2_B1_EXPECTED_BEFORE_SHA is required and must be a 40-hex SHA");
  return context as B1VerificationContext;
}

function envFileValue(contents: string, name: string): string {
  const line = contents.split(/\r?\n/).find((entry) => entry.startsWith(`${name}=`));
  requireCondition(line, `${name} is missing from environment file`);
  const value = line.slice(name.length + 1).trim().replace(/^['"]|['"]$/g, "");
  requireCondition(value, `${name} is empty`);
  return value;
}

async function readEnvFileValue(file: string, name: string): Promise<string> {
  return envFileValue(await readFile(path.join(root, file), "utf8"), name);
}

function githubHeaders(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": API_VERSION, "User-Agent": "t3n-breakglass-c2-b1" };
}

async function githubRequest(token: string, route: string, init: RequestInit = {}): Promise<ApiResult> {
  const response = await fetch(`${API}${route}`, { ...init, redirect: "error", headers: { ...githubHeaders(token), ...(init.headers ?? {}) } });
  const text = await response.text();
  let body: unknown = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = null; }
  const headers: Record<string, string> = {};
  for (const name of ["date", "etag", "x-github-request-id", "x-ratelimit-remaining", "retry-after"]) {
    const value = response.headers.get(name);
    if (value) headers[name] = value;
  }
  return { status: response.status, body, headers };
}

function safeBodyMetadata(body: unknown): JsonObject | null {
  const value = asObject(body);
  if (!value) return null;
  const output: JsonObject = {};
  for (const key of ["id", "title", "read_only", "private", "full_name", "name", "sha", "path", "ref", "repository_selection", "expires_at", "html_url", "message", "status_code", "event", "guid", "redelivery", "delivered_at", "installation_id"]) {
    if (value[key] !== undefined) output[key] = value[key];
  }
  if (asObject(value.commit)?.sha) output.commit_sha = value.commit.sha;
  return output;
}

function safeResponse(response: ApiResult): JsonObject {
  return { http_status: response.status, response_headers: response.headers, body_metadata: safeBodyMetadata(response.body) };
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function normalizePublicKey(value: string): string {
  const fields = value.trim().split(/\s+/);
  requireCondition(fields.length >= 2 && fields[0] === "ssh-ed25519", "public key is not an ed25519 OpenSSH key");
  return `${fields[0]} ${fields[1]}`;
}

function safeKeyRows(body: unknown): JsonObject[] {
  return Array.isArray(body) ? body.map((value) => {
    const row = asObject(value) ?? {};
    return { id: row.id ?? null, title: row.title ?? null, read_only: row.read_only ?? null, created_at: row.created_at ?? null };
  }) : [];
}

function safePermissions(body: unknown): JsonObject {
  const value = asObject(body);
  return value && asObject(value.permissions) ? value.permissions : {};
}

function repositoryRows(body: unknown): JsonObject[] {
  const value = asObject(body);
  return value && Array.isArray(value.repositories) ? value.repositories.map((row) => asObject(row) ?? {}) : [];
}

async function runGit(args: string[], cwd = root): Promise<string> {
  const result = await execFileAsync("git", args, { cwd, encoding: "utf8", maxBuffer: 2_000_000 });
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
    if (input) child.stdin.end(input); else child.stdin.end();
  });
}

async function writeJson(file: string, value: unknown): Promise<Buffer> {
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
  await writeFile(path.join(root, file), bytes);
  return bytes;
}

async function assertNoPreexistingB1Files(): Promise<void> {
  for (const file of [POLICY_FILE, MARKER_FILE, FINAL_EVIDENCE_FILE]) {
    try { await access(path.join(root, file)); throw new Error(`${file} already exists; refusing an automatic second B1 run`); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  }
}

async function verifyIngress(): Promise<JsonObject> {
  const local = await fetch(`http://127.0.0.1:8787${B0_ROUTE}`, { method: "GET" });
  requireCondition(local.status === 404, `local B0 receiver reachability returned HTTP ${local.status}`);
  const tunnelResponse = await fetch("http://127.0.0.1:4040/api/tunnels");
  requireCondition(tunnelResponse.ok, `ngrok API returned HTTP ${tunnelResponse.status}`);
  const tunnelBody = asObject(await tunnelResponse.json());
  const tunnel = Array.isArray(tunnelBody?.tunnels) ? tunnelBody.tunnels.find((row: unknown) => asObject(row)?.public_url === B0_PUBLIC_URL) as JsonObject | undefined : undefined;
  requireCondition(tunnel, "the frozen B0 ngrok URL is not currently active");
  requireCondition(String(asObject(tunnel.config)?.addr ?? "").includes("8787"), "ngrok is not forwarding to the B0 receiver port");
  const publicCheck = await fetch(`${B0_PUBLIC_URL}${B0_ROUTE}`, { method: "GET" });
  requireCondition(publicCheck.status === 404, `public B0 route reachability returned HTTP ${publicCheck.status}`);
  return { local_route_http_status: local.status, public_url: B0_PUBLIC_URL, public_route_http_status: publicCheck.status, ngrok_addr: asObject(tunnel.config)?.addr ?? null };
}

async function appReadback(): Promise<{ app: ApiResult; installation: ApiResult; appBody: JsonObject; installationBody: JsonObject }> {
  requireCondition(appJwtValue && appConfig, "App JWT configuration is unavailable");
  const app = await githubRequest(appJwtValue, "/app");
  requireCondition(app.status === 200, `GitHub App readback failed HTTP ${app.status}`);
  const appBody = asObject(app.body) ?? {};
  requireCondition(Number(appBody.id) === Number(appConfig.appId) && appBody.slug === APP_SLUG, "GitHub App identity readback mismatch");
  const appPermissions = safePermissions(appBody);
  const events = Array.isArray(appBody.events) ? appBody.events : [];
  requireCondition(appPermissions.administration === "write" && appPermissions.contents === "read" && appPermissions.metadata === "read", "GitHub App permissions are not administration:write + contents:read + metadata:read");
  requireCondition(events.includes("push"), "GitHub App push subscription is missing");
  const installation = await githubRequest(appJwtValue, `/app/installations/${INSTALLATION_ID}`);
  requireCondition(installation.status === 200, `GitHub installation readback failed HTTP ${installation.status}`);
  const installationBody = asObject(installation.body) ?? {};
  const installationPermissions = safePermissions(installationBody);
  requireCondition(Number(installationBody.id) === Number(INSTALLATION_ID), "installation identity readback mismatch");
  requireCondition(installationPermissions.administration === "write" && installationPermissions.contents === "read" && installationPermissions.metadata === "read", "installation permissions are not exact");
  requireCondition(installationBody.repository_selection === "selected", "installation repository selection is not selected");
  return { app, installation, appBody, installationBody };
}

async function mintInstallationToken(permissions: JsonObject, purpose: string): Promise<{ token: string; response: ApiResult; metadata: JsonObject }> {
  requireCondition(appJwtValue, "App JWT is unavailable");
  const response = await githubRequest(appJwtValue, `/app/installations/${INSTALLATION_ID}/access_tokens`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ repositories: [SANDBOX_REPOSITORY], permissions }) });
  const body = asObject(response.body) ?? {};
  const token = typeof body.token === "string" ? body.token : null;
  requireCondition(token, `${purpose} installation token mint failed HTTP ${response.status}`);
  const actual = safePermissions(body);
  const rows = repositoryRows(body);
  requireCondition(body.repository_selection === "selected" && rows.some((row) => row.full_name === SANDBOX_REPO && row.private === true), `${purpose} token repository scope is not the exact private sandbox`);
  return { token, response, metadata: { purpose, requested_permissions: permissions, actual_permissions: actual, repository_selection: body.repository_selection ?? null, expires_at: body.expires_at ?? null, repositories: rows.map((row) => ({ name: row.name, full_name: row.full_name, private: row.private })) } };
}

async function revokeAndProbe(token: string): Promise<JsonObject> {
  const revoke = await githubRequest(token, "/installation/token", { method: "DELETE" });
  const probe = await githubRequest(token, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}`);
  requireCondition(revoke.status === 204, `installation token revoke returned HTTP ${revoke.status}`);
  requireCondition(probe.status === 401 || probe.status === 403, `revoked token was not refused; probe HTTP ${probe.status}`);
  return { revoke_http_status: revoke.status, refusal_http_status: probe.status, refusal_confirmed: true };
}

async function verifyBaseline(pat: string, context: B1VerificationContext): Promise<JsonObject> {
  const ref = await githubRequest(pat, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/git/ref/heads/c2-breakglass-demo`);
  const refBody = asObject(ref.body) ?? {};
  const objectSha = asObject(refBody.object)?.sha;
  requireCondition(ref.status === 200 && objectSha === context.expectedBeforeSha, `sandbox baseline moved: expected ${context.expectedBeforeSha}, got ${String(objectSha)}`);
  const secret = await githubRequest(pat, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/contents/${SECRET_PATH_PARTS}?ref=${context.expectedBeforeSha}`);
  requireCondition(secret.status === 404, `secret path is not absent at the exact B0 baseline (HTTP ${secret.status})`);
  const ping = await githubRequest(pat, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/contents/.breakglass-c2/ping.txt?ref=${context.expectedBeforeSha}`);
  requireCondition(ping.status === 200, `B0 ping path is not readable at baseline (HTTP ${ping.status})`);
  return { branch: "c2-breakglass-demo", branch_head_sha: objectSha, ping_http_status: ping.status, secret_path_http_status: secret.status, secret_path_absent: true };
}

async function generateKeyAndStage(): Promise<{ title: string; publicKey: string; publicFingerprint: string; privateDigest: string; stagedBlobSha: string }> {
  tempKeyDirectory = await mkdtemp(path.join(os.tmpdir(), "t3n-c2-b1-key-"));
  const privatePath = path.join(tempKeyDirectory, "id_ed25519");
  const publicPath = `${privatePath}.pub`;
  const title = `breakglass-c2-b1-${Date.now()}-${randomBytes(5).toString("hex")}`;
  await execFileAsync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", title, "-f", privatePath], { windowsHide: true });
  privateBytes = await readFile(privatePath);
  const generatedPublic = normalizePublicKey((await readFile(publicPath, "utf8")));
  const derivedPublic = normalizePublicKey(String((await execFileAsync("ssh-keygen", ["-y", "-f", privatePath], { windowsHide: true })).stdout));
  requireCondition(generatedPublic === derivedPublic, "private key did not independently derive the generated public key");
  const fingerprintOutput = String((await execFileAsync("ssh-keygen", ["-lf", publicPath, "-E", "sha256"], { windowsHide: true })).stdout);
  const fingerprint = fingerprintOutput.match(/SHA256:[A-Za-z0-9+/]+/)?.[0];
  requireCondition(fingerprint, "generated public-key fingerprint was not produced");

  stagingDirectory = await mkdtemp(path.join(os.tmpdir(), "t3n-c2-b1-stage-"));
  await execFileAsync("git", ["init", "--quiet", "--initial-branch=main"], { cwd: stagingDirectory, windowsHide: true });
  await execFileAsync("git", ["config", "core.autocrlf", "false"], { cwd: stagingDirectory, windowsHide: true });
  await execFileAsync("git", ["config", "core.safecrlf", "false"], { cwd: stagingDirectory, windowsHide: true });
  const stagedPath = path.join(stagingDirectory, ".breakglass-c2", "exposed-deploy-key");
  await mkdir(path.dirname(stagedPath), { recursive: true });
  await writeFile(stagedPath, privateBytes);
  await execFileAsync("git", ["add", "--", ".breakglass-c2/exposed-deploy-key"], { cwd: stagingDirectory, windowsHide: true });
  const stagedBlobSha = await runGit(["rev-parse", ":.breakglass-c2/exposed-deploy-key"], stagingDirectory);
  stagedBytes = await runBuffer("git", ["cat-file", "blob", stagedBlobSha], stagingDirectory);
  requireCondition(Buffer.compare(stagedBytes, privateBytes) === 0, "staged Git blob differs byte-for-byte from intended private material");
  const privateDigest = sha256Hex(stagedBytes);
  return { title, publicKey: generatedPublic, publicFingerprint: fingerprint, privateDigest, stagedBlobSha };
}

async function createAndVerifyTarget(publicKey: string, title: string, expectedFingerprint: string): Promise<{ target: JsonObject; setupToken: JsonObject; providerFingerprint: string; exact: ApiResult; list: ApiResult }> {
  requireCondition(appJwtValue, "App JWT unavailable for target setup");
  const minted = await mintInstallationToken({ administration: "write" }, "fixture-setup");
  setupToken = minted.token;
  const beforeList = await githubRequest(setupToken, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/keys?per_page=100`);
  const existing = safeKeyRows(beforeList.body);
  requireCondition(beforeList.status === 200 && !existing.some((row) => row.title === title), "deploy-key preflight failed or title collided");
  const create = await githubRequest(setupToken, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/keys`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ title, key: publicKey, read_only: true }) });
  requireCondition(create.status === 201, `fresh deploy-key create failed HTTP ${create.status}`);
  const createdBody = asObject(create.body) ?? {};
  targetId = Number(createdBody.id);
  requireCondition(Number.isSafeInteger(targetId) && targetId > 0 && createdBody.title === title && createdBody.read_only === true, "GitHub returned invalid fresh deploy-key metadata");
  const exact = await githubRequest(setupToken, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/keys/${targetId}`);
  const list = await githubRequest(setupToken, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/keys?per_page=100`);
  const exactBody = asObject(exact.body) ?? {};
  requireCondition(exact.status === 200 && exactBody.id === targetId && exactBody.title === title && exactBody.read_only === true && normalizePublicKey(String(exactBody.key ?? "")) === publicKey, "fresh deploy-key exact readback failed");
  const rows = safeKeyRows(list.body);
  requireCondition(list.status === 200 && rows.some((row) => row.id === targetId && row.title === title && row.read_only === true), "fresh deploy-key list readback failed");
  const providerKeyPath = path.join(tempKeyDirectory!, "provider.pub");
  await writeFile(providerKeyPath, `${normalizePublicKey(String(exactBody.key))}\n`, "utf8");
  const providerOutput = String((await execFileAsync("ssh-keygen", ["-lf", providerKeyPath, "-E", "sha256"], { windowsHide: true })).stdout);
  const providerFingerprint = providerOutput.match(/SHA256:[A-Za-z0-9+/]+/)?.[0];
  requireCondition(providerFingerprint, "provider public-key fingerprint was not produced");
  requireCondition(providerFingerprint === expectedFingerprint, "provider public key fingerprint does not match generated public key");
  return { target: { id: targetId, title, read_only: true, public_key: publicKey }, setupToken: minted.metadata, providerFingerprint, exact, list };
}

async function derivePublicFingerprint(publicKey: string): Promise<string> {
  const file = path.join(tempKeyDirectory!, "generated-fingerprint.pub");
  await writeFile(file, `${publicKey}\n`, "utf8");
  const output = String((await execFileAsync("ssh-keygen", ["-lf", file, "-E", "sha256"], { windowsHide: true })).stdout);
  const fingerprint = output.match(/SHA256:[A-Za-z0-9+/]+/)?.[0];
  requireCondition(fingerprint, "generated public-key fingerprint was not reproducible");
  return fingerprint;
}

async function commitAndPush(file: string, message: string): Promise<string> {
  const relative = file.replaceAll("\\", "/");
  const status = await runGit(["status", "--short", "--", relative]);
  requireCondition(status === `?? ${relative}` || status === `A  ${relative}`, `unexpected working-tree changes before committing ${relative}: ${status}`);
  await runGit(["add", "--", relative]);
  const staged = await runGit(["diff", "--cached", "--name-only"]);
  requireCondition(staged === relative, `commit would include unexpected paths: ${staged}`);
  await runGit(["commit", "--no-verify", "-m", message]);
  const sha = await runGit(["rev-parse", "HEAD"]);
  await runGit(["push", "origin", CODE_BRANCH]);
  requireCondition(await runGit(["rev-parse", "HEAD"]) === sha, `local HEAD changed unexpectedly after pushing ${relative}`);
  return sha;
}

async function remotePolicyReadback(pat: string, policy: C2PushPolicyV2, policyBytes: Buffer, policyFreezeSha: string, registryIdentity: string): Promise<JsonObject> {
  const encoded = POLICY_FILE.split("/").map((part) => encodeURIComponent(part)).join("/");
  const response = await githubRequest(pat, `/repos/${CODE_OWNER}/${CODE_REPOSITORY}/contents/${encoded}?ref=${CODE_BRANCH}`);
  const body = asObject(response.body) ?? {};
  requireCondition(response.status === 200 && typeof body.content === "string", `remote policy readback failed HTTP ${response.status}`);
  const remoteBytes = Buffer.from(String(body.content).replace(/\s+/g, ""), "base64");
  const remoteJson = JSON.parse(remoteBytes.toString("utf8")) as JsonObject;
  const remotePolicy = asObject(remoteJson.policy);
  requireCondition(remotePolicy && JSON.stringify(remotePolicy) === JSON.stringify(policy), "remote policy authority fields differ from local policy");
  requireCondition(Buffer.compare(remoteBytes, policyBytes) === 0, "remote policy content is not byte-identical to local committed policy");
  const commit = await githubRequest(pat, `/repos/${CODE_OWNER}/${CODE_REPOSITORY}/commits/${policyFreezeSha}`);
  requireCondition(commit.status === 200 && asObject(commit.body)?.sha === policyFreezeSha, "policy freeze commit was not remotely readable");
  return { success: true, repository: CODE_REPO, ref: CODE_BRANCH, path: POLICY_FILE, policy_registry_identity: registryIdentity, policy_freeze_commit_sha: policyFreezeSha, policy_content_sha256: sha256Hex(remoteBytes), remote_blob_sha: body.sha ?? null, remote_readback_http_status: response.status, remote_readback_date: response.headers.date ?? null, remote_commit_readback_http_status: commit.status };
}

async function verifyTargetWithPat(pat: string, id: number, title: string, publicKey: string): Promise<JsonObject> {
  const exact = await githubRequest(pat, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/keys/${id}`);
  const list = await githubRequest(pat, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/keys?per_page=100`);
  const body = asObject(exact.body) ?? {};
  const rows = safeKeyRows(list.body);
  requireCondition(exact.status === 200 && body.id === id && body.title === title && body.read_only === true && normalizePublicKey(String(body.key ?? "")) === publicKey, "pre-trigger target recheck does not match policy target");
  requireCondition(list.status === 200 && rows.some((row) => row.id === id && row.title === title && row.read_only === true), "pre-trigger target list recheck failed");
  return { exact_get_http_status: exact.status, list_get_http_status: list.status, list_contains_target: true, title, read_only: true, id };
}

async function secretTrigger(pat: string, bytes: Buffer, context: B1VerificationContext): Promise<{ response: ApiResult; commitSha: string; parentSha: string; afterRefSha: string; commitReadback: JsonObject }> {
  const ref = await githubRequest(pat, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/git/ref/heads/c2-breakglass-demo`);
  requireCondition(asObject(asObject(ref.body)?.object)?.sha === context.expectedBeforeSha, "sandbox head moved immediately before secret trigger");
  const beforePath = await githubRequest(pat, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/contents/${SECRET_PATH_PARTS}?ref=${context.expectedBeforeSha}`);
  requireCondition(beforePath.status === 404, "secret path was not absent immediately before trigger");
  const body = JSON.stringify({ message: "C2-B1 exact disposable credential transition", content: bytes.toString("base64"), branch: "c2-breakglass-demo" });
  secretPushIssued = true;
  const response = await githubRequest(pat, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/contents/${SECRET_PATH_PARTS}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body });
  requireCondition(response.status === 201, `secret-introduction commit request returned HTTP ${response.status}; no retry permitted`);
  const responseBody = asObject(response.body) ?? {};
  const commitSha = String(asObject(responseBody.commit)?.sha ?? "");
  requireCondition(/^[0-9a-f]{40}$/i.test(commitSha), "GitHub did not return the secret commit SHA");
  const afterRef = await githubRequest(pat, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/git/ref/heads/c2-breakglass-demo`);
  const afterRefSha = String(asObject(asObject(afterRef.body)?.object)?.sha ?? "");
  requireCondition(afterRef.status === 200 && afterRefSha === commitSha, "sandbox branch did not advance to the returned secret commit");
  const commit = await githubRequest(pat, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/commits/${commitSha}`);
  const commitBody = asObject(commit.body) ?? {};
  const parents = Array.isArray(commitBody.parents) ? commitBody.parents.map((parent) => asObject(parent)?.sha) : [];
  const files = Array.isArray(commitBody.files) ? commitBody.files.map((file) => { const row = asObject(file) ?? {}; return { filename: row.filename, status: row.status, additions: row.additions, deletions: row.deletions }; }) : [];
  requireCondition(commit.status === 200 && parents.length >= 1 && parents[0] === context.expectedBeforeSha && files.length === 1 && files[0].filename === B1_SECRET_PATH && files[0].status === "added", "secret commit is not one exact fast-forward child adding only the policy path");
  return { response, commitSha, parentSha: parents[0], afterRefSha, commitReadback: { http_status: commit.status, parent_sha: parents[0], files } };
}

async function readCapturePath(): Promise<string> {
  return path.resolve(await readEnvFileValue(B0_CAPTURE_ENV, "C2_B0_CAPTURE_PATH"));
}

async function readCapture(file: string): Promise<JsonObject | null> {
  try { return JSON.parse(await readFile(file, "utf8")) as JsonObject; } catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return null; throw error; }
}

async function awaitRealDelivery(file: string, priorDeliveryId: string | null, afterSha: string, context: B1VerificationContext): Promise<JsonObject> {
  const deadline = Date.now() + 180_000;
  while (Date.now() < deadline) {
    const capture = await readCapture(file);
    if (capture && capture.delivery_id !== priorDeliveryId) {
      requireCondition(capture.event === "push" && capture.repository_id === 1350596128 && capture.repository_full_name === B1_REPOSITORY && capture.ref === B1_REF, "new capture is not the exact GitHub push vertical");
      requireCondition(capture.before === context.expectedBeforeSha && capture.after === afterSha && capture.created === false && capture.forced === false && capture.deleted === false, "new capture does not have the exact B1 authority-safe before/after shape");
      requireCondition(capture.signature_verified === true && capture.raw_body_persisted === false && capture.webhook_secret_persisted === false, "real delivery capture failed authentication or secret-hygiene checks");
      requireCondition(capture.authority_processing_attempted === false && capture.authority_eligible === false && capture.source_reader_calls === 0 && capture.c1_request_created === false, "receiver entered authority mode for the B1 delivery");
      requireCondition(asObject(capture.dedupe)?.status === "NEW", "B1 delivery was not durably reserved as NEW");
      return capture;
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error("timed out waiting for the one real GitHub secret-introduction webhook; no retry permitted");
}

async function readContentDigest(token: string, ref: string): Promise<{ status: number; digest: string | null; response: ApiResult }> {
  const response = await githubRequest(token, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/contents/${SECRET_PATH_PARTS}?ref=${encodeURIComponent(ref)}`);
  if (response.status !== 200) return { status: response.status, digest: null, response };
  const body = asObject(response.body) ?? {};
  requireCondition(typeof body.content === "string", "GitHub content response did not contain an encoded file");
  const decoded = Buffer.from(String(body.content).replace(/\s+/g, ""), "base64");
  const digest = sha256Hex(decoded);
  decoded.fill(0);
  return { status: response.status, digest, response };
}

async function deliveryHistory(deliveryId: string): Promise<JsonObject> {
  requireCondition(appJwtValue, "App JWT unavailable for delivery corroboration");
  const response = await githubRequest(appJwtValue, "/app/hook/deliveries?per_page=100");
  const rows = Array.isArray(response.body) ? response.body.map((row) => asObject(row) ?? {}) : [];
  const match = rows.find((row) => row.guid === deliveryId);
  if (!match) return { classification: "RECEIVER_PRIMARY_EVIDENCE_ONLY", http_status: response.status, delivery_found: false };
  return { classification: "GITHUB_DELIVERY_CORROBORATED", http_status: response.status, delivery_found: true, delivery_numeric_id: match.id ?? null, guid: match.guid ?? null, event: match.event ?? null, delivered_at: match.delivered_at ?? null, status: match.status ?? null, status_code: match.status_code ?? null, installation_id: match.installation_id ?? null, redelivery: match.redelivery ?? null };
}

async function emergencyCleanup(pat: string | null, reason: string): Promise<JsonObject | null> {
  if (!targetId || !appJwtValue) return null;
  let token: string | null = setupToken;
  let minted = false;
  try {
    if (!token) { token = (await mintInstallationToken({ administration: "write" }, "fixture-emergency-cleanup")).token; minted = true; }
    const deletion = await githubRequest(token, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/keys/${targetId}`, { method: "DELETE" });
    const exact = await githubRequest(token, `/repos/${SANDBOX_OWNER}/${SANDBOX_REPOSITORY}/keys/${targetId}`);
    const result = { classification: secretPushIssued ? "FIXTURE_EMERGENCY_CLEANUP" : "FIXTURE_SETUP_CLEANUP", reason, deploy_key_id: targetId, delete_http_status: deletion.status, exact_after_http_status: exact.status, absent: deletion.status === 204 && exact.status === 404 };
    if (minted && token) { const lifecycle = await revokeAndProbe(token); return { ...result, token_cleanup: lifecycle }; }
    return result;
  } catch (error) { return { classification: secretPushIssued ? "FIXTURE_EMERGENCY_CLEANUP" : "FIXTURE_SETUP_CLEANUP", reason, deploy_key_id: targetId, cleanup_error: String(error).slice(0, 400) }; }
}

async function main(): Promise<void> {
  const pat = process.env.GITHUB_PAT;
  requireCondition(pat, "GITHUB_PAT is required for the explicitly authorized B1 GitHub setup/trigger workflow");
  executionContext = readExecutionContext();
  const context = requireExecutionContext();
  requireCondition(await runGit(["rev-parse", "--abbrev-ref", "HEAD"]) === CODE_BRANCH, "B1 must run on winner-v2-core");
  const implementationHead = await runGit(["rev-parse", "HEAD"]);
  requireCondition(implementationHead === context.expectedStartingSha, "B1 implementation HEAD does not equal the explicit execution starting SHA");
  requireCondition(await runGit(["rev-parse", "origin/winner-v2-core"]) === implementationHead, "origin/winner-v2-core does not match the checked-in B1 implementation");
  requireCondition(await runGit(["rev-parse", "origin/main"]) === context.expectedMainSha, "origin/main does not match the explicit execution context");
  requireCondition((await runGit(["status", "--porcelain"])) === "", "working tree is not clean at B1 start");
  await assertNoPreexistingB1Files();
  const registration = JSON.parse(await readFile(path.join(root, "winner/evidence/contract-registration.json"), "utf8")) as JsonObject;
  requireCondition(registration.contract?.version === CONTRACT.version && registration.contract?.contract_id === CONTRACT.id && registration.contract?.wasm_bytes === CONTRACT.bytes && registration.contract?.wasm_sha256 === CONTRACT.sha256, "frozen C1 artifact identity changed");
  appConfig = appConfigFromEnvironment({ GITHUB_APP_ID: await readEnvFileValue(".env.c0r-github-app", "GITHUB_APP_ID"), GITHUB_APP_INSTALLATION_ID: await readEnvFileValue(".env.c0r-github-app", "GITHUB_APP_INSTALLATION_ID"), GITHUB_APP_PRIVATE_KEY_PATH: await readEnvFileValue(".env.c0r-github-app", "GITHUB_APP_PRIVATE_KEY_PATH"), GITHUB_OWNER: SANDBOX_OWNER, GITHUB_REPO: SANDBOX_REPOSITORY });
  appJwtValue = await appJwt(appConfig);
  const ingress = await verifyIngress();
  const app = await appReadback();
  const baseline = await verifyBaseline(pat, context);
  const captureFile = await readCapturePath();
  const priorCapture = await readCapture(captureFile);
  const priorDeliveryId = typeof priorCapture?.delivery_id === "string" ? priorCapture.delivery_id : null;

  const key = await generateKeyAndStage();
  const generatedFingerprint = await derivePublicFingerprint(key.publicKey);
  requireCondition(generatedFingerprint === key.publicFingerprint, "generated public-key fingerprint changed during independent verification");
  const target = await createAndVerifyTarget(key.publicKey, key.title, generatedFingerprint);
  requireCondition(target.providerFingerprint === generatedFingerprint, "fresh target does not bind to generated key fingerprint");
  const setupTokenValue = setupToken;
  requireCondition(setupTokenValue, "fixture setup token was not retained for its required cleanup");
  const setupTokenLifecycle = await revokeAndProbe(setupTokenValue);
  setupToken = null;

  const policyId = `c2-policy:github-push-c2-b1-${Date.now()}-${randomBytes(6).toString("hex")}`;
  const policy = buildC2PushPolicyV2({
    policy_id: policyId,
    policy_version: 2,
    deploy_key_id: key ? target.target.id : 0,
    expected_deploy_key_title: key.title,
    expected_read_only: true,
    expected_public_key_fingerprint: generatedFingerprint,
    expected_private_material_sha256: key.privateDigest,
    remediation_agent_did: REMEDIATION_DID,
    effect_broker_did: BROKER_DID,
    ttl_secs: 900,
    enabled: true,
    actual_creation_timestamp: new Date().toISOString(),
    creation_commit_or_registry_identity: policyId,
    provenance: { classification: "LIVE_PROVENANCE", creation_evidence: `${POLICY_FILE} remote readback`, enabled_before_event_proof: true },
  });
  const authorityFields = { policy_id: policy.policy_id, policy_version: policy.policy_version, source_provider: policy.source_provider, source_event_type: policy.source_event_type, repository_id: policy.repository_id, repository_full_name: policy.repository_full_name, ref: policy.ref, secret_path: policy.secret_path, deploy_key_id: policy.deploy_key_id, expected_deploy_key_title: policy.expected_deploy_key_title, expected_read_only: policy.expected_read_only, expected_public_key_fingerprint: policy.expected_public_key_fingerprint, expected_private_material_sha256: policy.expected_private_material_sha256, remediation_agent_did: policy.remediation_agent_did, effect_broker_did: policy.effect_broker_did, ttl_secs: policy.ttl_secs, enabled: policy.enabled, actual_creation_timestamp: policy.actual_creation_timestamp, creation_commit_or_registry_identity: policy.creation_commit_or_registry_identity, provenance: policy.provenance };
  const policyBytes = await writeJson(POLICY_FILE, { artifact: "C2-B1 LIVE AUTHORITY-BEARING POLICY", registry_identity: policyId, policy: policy });
  const policyFreezeSha = await commitAndPush(POLICY_FILE, `c2: freeze live B1 policy ${policyId}`);
  const remotePolicy = await remotePolicyReadback(pat, policy, policyBytes, policyFreezeSha, policyId);
  const marker = { artifact: "POLICY_FROZEN_AND_REMOTE_CONFIRMED", registry_identity: policyId, policy_freeze_commit_sha: policyFreezeSha, policy_content_sha256: remotePolicy.policy_content_sha256, remote_readback_success: true, remote_readback_date: remotePolicy.remote_readback_date, deploy_key_id: target.target.id, expected_public_key_fingerprint: generatedFingerprint, expected_private_material_sha256: key.privateDigest, enabled_before_event_proof: true };
  await writeJson(MARKER_FILE, marker);
  const markerSha = await commitAndPush(MARKER_FILE, `c2: attest B1 policy freeze ${policyId}`);
  const preTriggerTarget = await verifyTargetWithPat(pat, target.target.id, key.title, key.publicKey);
  const stagedBeforePush = await runBuffer("git", ["cat-file", "blob", key.stagedBlobSha], stagingDirectory!);
  requireCondition(sha256Hex(stagedBeforePush) === key.privateDigest && Buffer.compare(stagedBeforePush, privateBytes!) === 0, "staged private material changed after policy freeze");
  const trigger = await secretTrigger(pat, stagedBeforePush, context);
  stagedBeforePush.fill(0);
  if (stagedBytes) { stagedBytes.fill(0); stagedBytes = null; }
  if (privateBytes) { privateBytes.fill(0); privateBytes = null; }
  if (tempKeyDirectory) { await rm(tempKeyDirectory, { recursive: true, force: true }); tempKeyDirectory = null; }
  if (stagingDirectory) { await rm(stagingDirectory, { recursive: true, force: true }); stagingDirectory = null; }
  const capture = await awaitRealDelivery(captureFile, priorDeliveryId, trigger.commitSha, context);
  const deliveryHistoryResult = await deliveryHistory(String(capture.delivery_id));
  if (deliveryHistoryResult.classification === "GITHUB_DELIVERY_CORROBORATED" && remotePolicy.remote_readback_date && deliveryHistoryResult.delivered_at) requireCondition(Date.parse(remotePolicy.remote_readback_date) < Date.parse(String(deliveryHistoryResult.delivered_at)), "GitHub policy readback Date is not before webhook delivery time");

  const sourceMint = await mintInstallationToken({ contents: "read" }, "source-reader");
  sourceToken = sourceMint.token;
  const actualPermissions = sourceMint.metadata.actual_permissions;
  requireCondition(actualPermissions.contents === "read" && actualPermissions.administration !== "write", "source-reader token granted broader than Contents:read-only scope");
  const beforeRead = await readContentDigest(sourceToken, context.expectedBeforeSha);
  requireCondition(beforeRead.status === 404 && beforeRead.digest === null, "immutable BEFORE read did not prove a missing secret path");
  const afterRead = await readContentDigest(sourceToken, trigger.commitSha);
  requireCondition(afterRead.status === 200 && afterRead.digest === key.privateDigest, "immutable AFTER read did not match the exact private-material digest");
  const sourceTokenValue = sourceToken;
  requireCondition(sourceTokenValue, "source-reader token was not retained for its required cleanup");
  const sourceTokenLifecycle = await revokeAndProbe(sourceTokenValue);
  sourceToken = null;

  const event: NormalizedPushEvent = { provider: "github", event_type: "push", action: "push", delivery_id: String(capture.delivery_id), repository_id: 1350596128, repository_full_name: B1_REPOSITORY, ref: B1_REF, before: String(capture.before), after: String(capture.after), deleted: false, forced: false, created: false, sender_login: String(asObject(capture.normalized)?.sender_login ?? "Ticoworld"), raw_body_sha256: String(capture.raw_body_sha256) };
  const readPlan = createImmutablePushReadPlan(event, policy);
  const beforeObservation: ImmutablePathObservation = { repository: B1_REPOSITORY, commit_sha: context.expectedBeforeSha, path: B1_SECRET_PATH, status: 404 };
  const afterObservation: ImmutablePathObservation = { repository: B1_REPOSITORY, commit_sha: trigger.commitSha, path: B1_SECRET_PATH, status: 200, content_sha256: key.privateDigest };
  const transition = verifyPushSecretTransition(beforeObservation, afterObservation, policy, readPlan);
  requireCondition(transition.classification === "CAUSAL_SECRET_INTRODUCED", `unexpected transition classification ${transition.classification}`);
  const derived = derivePushC1CreateRequest(event, policy, transition);
  requireCondition(derived.create_request.deploy_key_id === target.target.id && derived.create_request.ttl_secs === 900, "derived C1 request does not match exact fresh target policy");

  const evidence: JsonObject = buildB1Evidence({
    starting_sha: context.expectedStartingSha,
    policy_freeze_commit_sha: policyFreezeSha,
    policy_marker_commit_sha: markerSha,
    final_sha: "recorded_by_containing_git_commit",
    main_sha: context.expectedMainSha,
    b0_before_sha: context.expectedBeforeSha,
    ingress_readiness: ingress,
    app_readback: { registration: safeResponse(app.app), installation: safeResponse(app.installation), app_slug: APP_SLUG, installation_id: INSTALLATION_ID, permissions: safePermissions(app.appBody), events: app.appBody.events ?? [], installation_permissions: safePermissions(app.installationBody), repository_selection: app.installationBody.repository_selection ?? null },
    fresh_deploy_key: { ...target.target, generated_public_key_fingerprint: generatedFingerprint, provider_public_key_fingerprint: target.providerFingerprint, private_public_relation_proven: true, setup_token: { ...target.setupToken, lifecycle: setupTokenLifecycle }, provider_exact_readback: safeResponse(target.exact), provider_list_readback: { http_status: target.list.status, rows: safeKeyRows(target.list.body) } },
    private_material_sha256: key.privateDigest,
    policy: { registry_identity: policyId, policy_version: 2, authority_fields: authorityFields, content_sha256: remotePolicy.policy_content_sha256, remote_readback: remotePolicy },
    policy_before_event: { policy_freeze_commit_sha: policyFreezeSha, marker_commit_sha: markerSha, remote_policy_readback_before_trigger: true, marker_persisted_before_trigger: true, policy_readback_completed_at: remotePolicy.remote_readback_date ?? null, trigger_issued_after_marker: true },
    pre_trigger_target_recheck: preTriggerTarget,
    secret_trigger_commit: { mechanism: "GitHub Contents API single fast-forward commit (one push webhook)", sha: trigger.commitSha, parent_sha: trigger.parentSha, branch: "c2-breakglass-demo", only_changed_path: B1_SECRET_PATH, fast_forward: true, commit_readback: trigger.commitReadback, response: safeResponse(trigger.response) },
    real_delivery: { delivery_id: event.delivery_id, event_type: event.event_type, repository_id: event.repository_id, repository_full_name: event.repository_full_name, ref: event.ref, before: event.before, after: event.after, created: event.created, forced: event.forced, deleted: event.deleted, sender_login: event.sender_login, raw_body_sha256: event.raw_body_sha256, signature_verified: capture.signature_verified, raw_body_persisted: capture.raw_body_persisted, webhook_secret_persisted: capture.webhook_secret_persisted, authority_processing_attempted: capture.authority_processing_attempted, authority_eligible: capture.authority_eligible, dedupe_status: asObject(capture.dedupe)?.status ?? null, dedupe_key: asObject(capture.dedupe)?.key ?? null },
    immutable_before: { status: beforeRead.status, commit_sha: context.expectedBeforeSha, path: B1_SECRET_PATH, response: safeResponse(beforeRead.response) },
    immutable_after: { status: afterRead.status, commit_sha: trigger.commitSha, path: B1_SECRET_PATH, content_sha256: afterRead.digest, response: safeResponse(afterRead.response) },
    transition_classification: transition.classification,
    immutable_read_plan: readPlan,
    derived_c1_request: derived.create_request,
    source_reader_token: { ...sourceMint.metadata, read_http_status: afterRead.status, immutable_before_http_status: beforeRead.status, immutable_after_http_status: afterRead.status, revoke_http_status: sourceTokenLifecycle.revoke_http_status, refusal_http_status: sourceTokenLifecycle.refusal_http_status, administration_write_granted: false, token_value_persisted: false, jwt_value_persisted: false },
    github_delivery_corroboration: deliveryHistoryResult,
    compromised_target_state: "COMPROMISED_DISPOSABLE_TARGET_PENDING_CAUSAL_REMEDIATION",
    mutation_counters: { app_permission_writes: 0, app_subscription_writes: 0, webhook_configuration_writes: 0, deploy_key_creates: 1, deploy_key_deletes: 0, secret_introduction_pushes: 1, secret_exposures: 1, live_policy_v2_creates: 1, t3n_create_calls: 0, c1_create_calls: 0, provider_effects: 0, t3n_writes: 0 },
    sensitive_value_hygiene: { private_material_in_policy: false, private_material_in_evidence: false, private_material_in_dedupe: false, raw_webhook_body_in_evidence: false, webhook_secret_in_evidence: false, installation_token_in_evidence: false, app_jwt_in_evidence: false, private_local_copy_removed_after_trigger: true },
    tests: { offline_verifier: "pending", c2_and_product_tests: "run_before_final_commit", git_diff_check: "run_before_final_commit" },
    c1_artifact: CONTRACT,
    claims_earned: ["one fresh read-only deploy key was bound to the generated public key", "the exact private/public/target relation and private-material digest were frozen", "the live policy was committed and remotely read back before the security event", "one real authenticated push introduced the exact policy-bound private material", "immutable BEFORE/AFTER reads proved CAUSAL_SECRET_INTRODUCED", "the exact C1 request was derived without sending create-incident"],
    claims_forbidden: ["T3N incident created", "remediation executed", "deploy key revoked", "C2-C completion", "autonomous remediation", "C2 submission readiness"],
  });
  const offline = verifyB1Evidence(evidence, context);
  requireCondition(offline.valid, `offline B1 verifier failed: ${offline.reasons.join(", ")}`);
  evidence.tests.offline_verifier = "PASS";
  const finalEvidenceBytes = serializeB1Evidence(evidence);
  await writeFile(path.join(root, FINAL_EVIDENCE_FILE), finalEvidenceBytes);
  const finalSha = await commitAndPush(FINAL_EVIDENCE_FILE, `c2: record causal B1 secret introduction ${policyId}`);
  completed = true;
  console.log(JSON.stringify({ final_sha: finalSha, main_sha: context.expectedMainSha, policy_freeze_commit_sha: policyFreezeSha, marker_commit_sha: markerSha, deploy_key_id: target.target.id, target_title: key.title, delivery_id: event.delivery_id, secret_commit_sha: trigger.commitSha, transition: transition.classification, derived_c1_request: derived.create_request, evidence: FINAL_EVIDENCE_FILE, total_provider_mutations: 2, t3n_create_calls: 0, note: `final evidence bytes ${finalEvidenceBytes.length}; final_sha is reported from the containing commit` }, null, 2));
}

main().catch(async (error) => {
  try {
    if (sourceToken) { await revokeAndProbe(sourceToken); sourceToken = null; }
    if (setupToken) { await revokeAndProbe(setupToken); setupToken = null; }
    if (!completed && targetId) {
      const cleanup = await emergencyCleanup(process.env.GITHUB_PAT ?? null, error instanceof Error ? error.message : String(error));
      if (cleanup) await writeJson(`winner/evidence/C2-B1-FAILURE-${Date.now()}.json`, { classification: "C2_B1_FAIL", cleanup, secret_push_issued: secretPushIssued, private_material_in_evidence: false, t3n_create_calls: 0 });
    }
  } catch {}
  if (privateBytes) privateBytes.fill(0);
  if (stagedBytes) stagedBytes.fill(0);
  if (tempKeyDirectory) await rm(tempKeyDirectory, { recursive: true, force: true }).catch(() => undefined);
  if (stagingDirectory) await rm(stagingDirectory, { recursive: true, force: true }).catch(() => undefined);
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
