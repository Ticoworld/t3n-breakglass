import { execFile } from "node:child_process";
import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const root = path.resolve(import.meta.dirname, "..");
const outputDir = path.join(root, "evidence", "phase2e");
const API_BASE = "https://api.github.com";
const API_VERSION = "2026-03-10";
const OWNER = "Ticoworld";
const REPOSITORY = "t3n-breakglass-sandbox";
const REPLACEMENT_DID = "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019";
const TTL_SECONDS = 300;

type JsonObject = Record<string, unknown>;
type FetchEvent = { host: string; method: string; path: string; status: number; date?: string | null };

const githubEvents: FetchEvent[] = [];
const trustEvents: FetchEvent[] = [];
const originalFetch = globalThis.fetch;

function urlOf(input: RequestInfo | URL): URL {
  if (typeof input === "string") return new URL(input);
  if (input instanceof URL) return input;
  return new URL(input.url);
}

globalThis.fetch = async (input, init) => {
  const response = await originalFetch(input, init);
  const url = urlOf(input);
  const event = { host: url.host, method: init?.method ?? "GET", path: url.pathname, status: response.status, date: response.headers.get("date") } satisfies FetchEvent;
  if (url.origin === API_BASE) githubEvents.push(event);
  if (url.pathname === "/api/trust-manifest") trustEvents.push(event);
  return response;
};

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function redact(error: unknown): string {
  let message = error instanceof Error ? error.message : String(error);
  for (const name of ["GITHUB_PAT", "T3N_API_KEY", "REPLACEMENT_AGENT_T3N_API_KEY", "AGENT_T3N_API_KEY"]) {
    const secret = process.env[name];
    if (secret) message = message.split(secret).join("[REDACTED]");
  }
  return message.replace(/t3n_key_[A-Za-z0-9_-]+/g, "[REDACTED_T3N_KEY]");
}

function githubHeaders(): HeadersInit {
  return {
    Authorization: `Bearer ${required("GITHUB_PAT")}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": API_VERSION,
    "User-Agent": "breakglass-phase2e-evidence-refresh",
  };
}

async function githubJson(pathname: string): Promise<{ status: number; value: unknown }> {
  const response = await originalFetch(`${API_BASE}${pathname}`, { headers: githubHeaders(), redirect: "error" });
  const body = await response.text();
  let value: unknown = undefined;
  if (body) {
    try { value = JSON.parse(body); } catch { value = undefined; }
  }
  return { status: response.status, value };
}

async function writeJson(name: string, value: unknown): Promise<void> {
  await writeFile(path.join(outputDir, name), JSON.stringify(value, null, 2) + "\n");
}

async function exists(filePath: string): Promise<boolean> {
  try { await access(filePath); return true; } catch { return false; }
}

function projection(value: unknown): JsonObject {
  const authority = value as JsonObject;
  return {
    incident_id: authority.incident_id,
    agent_did: authority.agent_did,
    action: authority.action,
    github_owner: authority.github_owner,
    github_repo: authority.github_repo,
    deploy_key_id: authority.deploy_key_id,
    created_at: authority.created_at,
    expires_at: authority.expires_at,
    max_uses: authority.max_uses,
    uses: authority.uses,
    status: authority.status,
  };
}

async function readAuthority(tenant: { maps: { entryGet: (tail: string, key: string) => Promise<string | null> } }, incidentId: string): Promise<JsonObject> {
  const raw = await tenant.maps.entryGet("incidents", incidentId);
  if (!raw) throw new Error(`incident authority ${incidentId} was not found`);
  return projection(JSON.parse(raw));
}

async function runRawAgent(incidentId: string): Promise<JsonObject> {
  const agentEnv = { ...process.env };
  for (const name of ["GITHUB_PAT", "T3N_API_KEY", "T3N_API_KEY_ALT", "AGENT_T3N_API_KEY", "AGENT_DID", "AGENT_ORGANISATION_DID", "REPLACEMENT_AGENT_T3N_API_KEY", "REPLACEMENT_AGENT_DID", "REPLACEMENT_AGENT_ORGANISATION_DID"]) delete agentEnv[name];
  const result = await execFileAsync("node", [
    "--env-file-if-exists=.env.replacement-agent",
    "node_modules/tsx/dist/cli.mjs",
    "scripts/phase2e-agent-raw.ts",
    incidentId,
  ], { cwd: root, env: agentEnv, maxBuffer: 1024 * 1024 });
  return JSON.parse(result.stdout.trim()) as JsonObject;
}

async function environment(): Promise<JsonObject> {
  const sdkPackage = JSON.parse(await readFile(path.join(root, "node_modules", "@terminal3", "t3n-sdk", "package.json"), "utf8")) as { name?: string; version?: string };
  const command = (name: string, args: string[]) => {
    try { return execFileAsync(name, args, { cwd: root }).then((r) => r.stdout.trim()); } catch { return Promise.resolve("unavailable"); }
  };
  const [rustc, cargo, rustup] = await Promise.all([
    command("rustc", ["--version"]),
    command("cargo", ["--version"]),
    command("rustup", ["show", "active-toolchain"]),
  ]);
  return {
    environment: "testnet",
    node: process.version,
    sdk: `${sdkPackage.name} ${sdkPackage.version}`,
    rustc,
    cargo,
    rustup_active_toolchain: rustup,
    contract_version: "1.0.0",
    contract_function: "execute-incident",
  };
}

async function main() {
  if (await exists(path.join(outputDir, "phase2e-live-proof.json"))) throw new Error("phase2e evidence already exists; refusing to overwrite it");
  await mkdir(outputDir, { recursive: true });
  const { ensurePhase2DisposableTarget } = await import("./github.js");
  const { connectTenant, redactError } = await import("./lib.js");
  const { persistPreparedIncident, prepareIncidentAuthority } = await import("./incident-create.js");

  const env = await environment();
  const preTargetList = await githubJson(`/repos/${OWNER}/${REPOSITORY}/keys`);
  if (preTargetList.status !== 200 || !Array.isArray(preTargetList.value) || preTargetList.value.length !== 0) {
    throw new Error(`expected zero existing deploy keys before fresh target creation; observed HTTP ${preTargetList.status} count ${Array.isArray(preTargetList.value) ? preTargetList.value.length : "non-array"}`);
  }

  const target = await ensurePhase2DisposableTarget(OWNER, REPOSITORY);
  const targetPath = `/repos/${OWNER}/${REPOSITORY}/keys/${target.deployKeyId}`;
  const repoResponse = await githubJson(`/repos/${OWNER}/${REPOSITORY}`);
  const keyResponse = await githubJson(targetPath);
  const listResponse = await githubJson(`/repos/${OWNER}/${REPOSITORY}/keys`);
  const keys = Array.isArray(listResponse.value) ? listResponse.value as JsonObject[] : [];
  const key = keyResponse.value as JsonObject;
  const targetBefore = {
    host: API_BASE,
    repository: `${OWNER}/${REPOSITORY}`,
    repository_get_http_status: repoResponse.status,
    exact_deploy_key_endpoint: `${API_BASE}${targetPath}`,
    exact_deploy_key_get_http_status: keyResponse.status,
    deploy_key_list_endpoint: `${API_BASE}/repos/${OWNER}/${REPOSITORY}/keys`,
    deploy_key_list_http_status: listResponse.status,
    target_deploy_key_id: target.deployKeyId,
    target_present: keyResponse.status === 200 && key.id === target.deployKeyId && keys.some((item) => item.id === target.deployKeyId),
    list_count: keys.length,
    read_only: key.read_only === true,
    title: typeof key.title === "string" ? key.title : null,
    new_target_post_count: githubEvents.filter((event) => event.method === "POST" && event.path === `/repos/${OWNER}/${REPOSITORY}/keys`).length,
    new_target_post_http_statuses: githubEvents.filter((event) => event.method === "POST" && event.path === `/repos/${OWNER}/${REPOSITORY}/keys`).map((event) => event.status),
    private_key_recorded: false,
  };
  if (repoResponse.status !== 200 || keyResponse.status !== 200 || listResponse.status !== 200 || !targetBefore.target_present || targetBefore.list_count !== 1 || !targetBefore.read_only || targetBefore.new_target_post_count !== 1 || targetBefore.new_target_post_http_statuses[0] !== 201) {
    throw new Error("fresh target did not satisfy the exact before-state proof");
  }
  await writeJson("target-before.json", targetBefore);

  const incidentId = `INC-PHASE2E-LIVE-${Date.now()}`;
  const trustStart = trustEvents.length;
  const prepared = await prepareIncidentAuthority({ incidentId, owner: OWNER, repository: REPOSITORY, deployKeyId: target.deployKeyId, ttlSeconds: TTL_SECONDS });
  const trustDuringPrepare = trustEvents.slice(trustStart);
  const trustedResponse = trustDuringPrepare.at(-1);
  if (!trustedResponse?.date || trustedResponse.status !== 200) throw new Error("trusted time response did not expose a usable Date header");
  const parsedTrustedSeconds = Math.floor(Date.parse(trustedResponse.date) / 1000);
  if (!Number.isSafeInteger(parsedTrustedSeconds) || parsedTrustedSeconds !== prepared.preview.created_at) throw new Error("trusted Date header did not match authority created_at");
  const trustedTime = {
    source: `${prepared.nodeUrl}/api/trust-manifest`,
    http_status: trustedResponse.status,
    raw_date_header: trustedResponse.date,
    parsed_timestamp_seconds: parsedTrustedSeconds,
    created_at: prepared.preview.created_at,
    ttl_seconds: TTL_SECONDS,
    calculated_expires_at: prepared.preview.expires_at,
    calculation: "parsed_timestamp_seconds + ttl_seconds",
    responses_during_operator_preparation: trustDuringPrepare.map((event, index) => ({ index, http_status: event.status, raw_date_header: event.date })),
  };
  await writeJson("trusted-time.json", trustedTime);

  const authority = await persistPreparedIncident(prepared);
  const operatorBefore = await connectTenant();
  const beforeAuthority = await readAuthority(operatorBefore.tenant, incidentId);
  const incidentBefore = { map_private: true, authority: beforeAuthority, operator_confirmation: true };
  if (beforeAuthority.status !== "ACTIVE" || beforeAuthority.uses !== 0 || beforeAuthority.max_uses !== 1 || beforeAuthority.agent_did !== REPLACEMENT_DID || beforeAuthority.deploy_key_id !== target.deployKeyId) throw new Error("pre-execution authority proof failed");
  await writeJson("incident-before.json", incidentBefore);

  const agentRequest = { incident_id: incidentId };
  const executionEnvelope = await runRawAgent(incidentId);
  const t3nExecution = {
    agent_did: executionEnvelope.agent_did,
    request: executionEnvelope.request,
    request_fields: Object.keys((executionEnvelope.request ?? {}) as JsonObject),
    target_fields_in_request: executionEnvelope.target_fields_in_request,
    contract: executionEnvelope.contract,
    version: executionEnvelope.version,
    function: executionEnvelope.function,
    result: executionEnvelope.result,
    target_endpoint_from_authority: `${API_BASE}/repos/${OWNER}/${REPOSITORY}/keys/${target.deployKeyId}`,
    credential_flags: { github_credential_in_process: executionEnvelope.github_credential_in_process, operator_credential_in_process: executionEnvelope.operator_credential_in_process },
  };
  if (JSON.stringify(executionEnvelope.request) !== JSON.stringify(agentRequest)) throw new Error("agent request was not incident-only");
  await writeJson("agent-request.json", { request: agentRequest, fields: Object.keys(agentRequest), target_fields_in_request: false });
  await writeJson("t3n-execution.json", t3nExecution);

  const independentAfterRaw = await Promise.all([githubJson(targetPath), githubJson(`/repos/${OWNER}/${REPOSITORY}/keys`)]);
  const afterKeys = Array.isArray(independentAfterRaw[1].value) ? independentAfterRaw[1].value as JsonObject[] : [];
  const githubIndependentAfter = {
    classification: "INDEPENDENT GITHUB VERIFICATION",
    host: API_BASE,
    repository: `${OWNER}/${REPOSITORY}`,
    exact_deploy_key_endpoint: `${API_BASE}${targetPath}`,
    exact_deploy_key_get_http_status: independentAfterRaw[0].status,
    deploy_key_list_http_status: independentAfterRaw[1].status,
    target_deploy_key_id: target.deployKeyId,
    target_absent: independentAfterRaw[0].status === 404 && afterKeys.every((item) => item.id !== target.deployKeyId),
    list_count: afterKeys.length,
  };
  if (githubIndependentAfter.exact_deploy_key_get_http_status !== 404 || githubIndependentAfter.deploy_key_list_http_status !== 200 || !githubIndependentAfter.target_absent) throw new Error("independent GitHub after-state proof failed");
  await writeJson("github-independent-after.json", githubIndependentAfter);

  const afterAuthorityConnection = await connectTenant();
  const afterAuthority = await readAuthority(afterAuthorityConnection.tenant, incidentId);
  const incidentAfter = { map_private: true, authority: afterAuthority };
  if (afterAuthority.status !== "CONSUMED" || afterAuthority.uses !== 1 || afterAuthority.max_uses !== 1 || afterAuthority.agent_did !== REPLACEMENT_DID || afterAuthority.deploy_key_id !== target.deployKeyId || afterAuthority.action !== "revoke_github_deploy_key") throw new Error("post-consumption authority proof failed");
  await writeJson("incident-after.json", incidentAfter);

  const replayEnvelope = await runRawAgent(incidentId);
  const replayAuthorityConnection = await connectTenant();
  const replayAuthority = await readAuthority(replayAuthorityConnection.tenant, incidentId);
  const replay = {
    agent_did: replayEnvelope.agent_did,
    request: replayEnvelope.request,
    result: replayEnvelope.result,
    authority_after_replay: replayAuthority,
    delete_attempted: (replayEnvelope.result as JsonObject)?.destructive_call instanceof Object ? ((replayEnvelope.result as JsonObject).destructive_call as JsonObject).attempted : false,
  };
  if ((replayEnvelope.result as JsonObject)?.status !== "REPLAY_REFUSED" || replayAuthority.status !== "CONSUMED" || replayAuthority.uses !== 1 || replayAuthority.max_uses !== 1 || replay.delete_attempted !== false) throw new Error("replay proof failed");
  await writeJson("replay.json", replay);

  const replayAfterRaw = await Promise.all([githubJson(targetPath), githubJson(`/repos/${OWNER}/${REPOSITORY}/keys`)]);
  const replayAfterKeys = Array.isArray(replayAfterRaw[1].value) ? replayAfterRaw[1].value as JsonObject[] : [];
  const githubAfterReplay = {
    classification: "INDEPENDENT GITHUB VERIFICATION",
    host: API_BASE,
    repository: `${OWNER}/${REPOSITORY}`,
    exact_deploy_key_get_http_status: replayAfterRaw[0].status,
    deploy_key_list_http_status: replayAfterRaw[1].status,
    target_deploy_key_id: target.deployKeyId,
    target_absent: replayAfterRaw[0].status === 404 && replayAfterKeys.every((item) => item.id !== target.deployKeyId),
    list_count: replayAfterKeys.length,
  };
  if (githubAfterReplay.exact_deploy_key_get_http_status !== 404 || githubAfterReplay.deploy_key_list_http_status !== 200 || !githubAfterReplay.target_absent) throw new Error("independent GitHub replay after-state proof failed");
  await writeJson("github-after-replay.json", githubAfterReplay);

  const result = {
    environment: { ...env, node_url: prepared.nodeUrl },
    target_before: targetBefore,
    trusted_time: trustedTime,
    incident_before: incidentBefore,
    agent_request: { ...agentRequest, fields: ["incident_id"], target_fields_supplied: false },
    t3n_execution: t3nExecution,
    github_independent_after: githubIndependentAfter,
    incident_after: incidentAfter,
    replay,
    github_after_replay: githubAfterReplay,
    classification: {
      contract_reported: ["t3n_execution.result.before", "t3n_execution.result.destructive_call", "t3n_execution.result.verification", "t3n_execution.result.authority", "replay.result"],
      independently_verified: ["target_before GitHub statuses", "github_independent_after", "incident_after private map read", "github_after_replay"],
      inferred: ["ACTIVE → EXECUTING is represented by authority ACTIVE plus result state.before EXECUTING; no separate externally observable transition event was invented", "target endpoint string is a sanitized projection of the private authority target"],
      delete_204: "T3N-CONTRACT-REPORTED EXTERNAL HTTP RESULT",
    },
    secrets_printed: false,
    original_phase2_evidence_overwritten: false,
  };
  await writeJson("phase2e-live-proof.json", result);
  await writeFile(path.join(outputDir, "run-events-sanitized.json"), JSON.stringify({ github_events: githubEvents.map(({ host, method, path: eventPath, status }) => ({ host, method, path: eventPath, status })), trust_events: trustEvents.map(({ host, method, path: eventPath, status, date }) => ({ host, method, path: eventPath, status, date })) }, null, 2) + "\n");
  console.log(JSON.stringify({ status: "PASS", incident_id: incidentId, agent_did: REPLACEMENT_DID, deploy_key_id: target.deployKeyId, evidence: "evidence/phase2e/phase2e-live-proof.json", destructive_calls_first_execution: 1, destructive_calls_replay: 0, secrets_printed: false }, null, 2));
}

main().catch((error) => {
  console.error(`phase2e failed: ${redact(error)}`);
  process.exitCode = 1;
});
