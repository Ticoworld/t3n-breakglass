import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { processMustRefusePat } from "./logic.js";
import {
  appConfigFromEnvironment,
  appJwt,
  createDisposableDeployKey,
  exactKey,
  listInstallationRepositories,
  listKeys,
  mintEffectInstallationToken,
  mintReadOnlyInstallationToken,
  repositoryContains,
  repositoryListIsWellFormed,
  repositoryRead,
  revokeInstallationToken,
  validateInstallation,
} from "./github-app.js";
import { redact } from "../scripts/t3n.js";

const root = path.resolve(import.meta.dirname, "../..");
const FIXED_OWNER = "Ticoworld";
const FIXED_REPOSITORY = "t3n-breakglass-sandbox";
const EXISTING_TARGET_ID = 162351194;
const EXISTING_TARGET_TITLE = "breakglass-r4e-disposable-20260904";

type JsonObject = Record<string, unknown>;

function envValue(name: string, required = true): string | undefined {
  const value = process.env[name]?.trim();
  if (!value && required) throw new Error(`${name} is required`);
  return value || undefined;
}

function safeResponse(response: { status: number; body: unknown; responseHeaders: Record<string, string> }): JsonObject {
  const body = response.body && typeof response.body === "object" && !Array.isArray(response.body) ? response.body as JsonObject : null;
  return {
    http_status: response.status,
    response_headers: response.responseHeaders,
    body_metadata: body ? { id: body.id ?? null, title: body.title ?? null, read_only: body.read_only ?? null, private: body.private ?? null, full_name: body.full_name ?? null, message: body.message ?? null } : null,
  };
}

function evidencePath(): string {
  const configured = envValue("C1_TARGET_EVIDENCE_FILE", false);
  if (configured) return path.resolve(configured);
  return path.join(root, "winner", "evidence", `target-setup-${Date.now()}.json`);
}

function parseExistingTarget(): { id: number; title: string } {
  const rawId = envValue("C1_EXISTING_TARGET_ID");
  const id = Number(rawId);
  if (!Number.isSafeInteger(id) || id <= 0) throw new Error("existing target ID must be a positive safe integer");
  const title = envValue("C1_EXISTING_TARGET_TITLE");
  if (id !== EXISTING_TARGET_ID) throw new Error("existing target ID is not the frozen R4E-R1 target");
  if (title !== EXISTING_TARGET_TITLE) throw new Error("existing target title does not match the frozen R4E-R1 target");
  return { id, title };
}

function targetFromBody(body: unknown): { id: number; title: string; read_only: boolean } | null {
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  const value = body as JsonObject;
  const id = Number(value.id);
  return Number.isSafeInteger(id) && id > 0 && typeof value.title === "string" && typeof value.read_only === "boolean"
    ? { id, title: value.title, read_only: value.read_only }
    : null;
}

async function main(): Promise<void> {
  if (processMustRefusePat(process.env)) throw new Error("C1 target setup refuses a GitHub PAT");
  const mode = envValue("C1_TARGET_MODE", false) ?? "create";
  if (mode !== "existing" && mode !== "create") throw new Error("C1_TARGET_MODE must be existing or create");
  const output = evidencePath();
  const config = appConfigFromEnvironment(process.env);
  const targetExpectation = mode === "existing" ? parseExistingTarget() : null;
  const evidence: JsonObject = {
    experiment: "C1 provider target preflight",
    mode,
    status: "IN_PROGRESS",
    github_api_version: "2022-11-28",
    app: { app_id: config.appId, installation_id: config.installationId },
    repository: { owner: config.owner, name: config.repository, full_name: `${config.owner}/${config.repository}`, private: true },
    expected_target: targetExpectation ? { id: targetExpectation.id, title: targetExpectation.title, read_only: true } : null,
    provider_mutations: { deploy_key_create_count: 0, deploy_key_delete_count: 0 },
    credentials_in_evidence: false,
  };
  let token: string | null = null;
  let cleanup: (() => Promise<void>) | undefined;
  let cleanupError: unknown;
  try {
    const jwt = await appJwt(config);
    const installation = await validateInstallation(config, jwt);
    evidence.installation = safeResponse(installation);
    if (installation.status !== 200) throw new Error(`INSTALLATION_MISMATCH: App installation GET HTTP ${installation.status}`);

    const minted = mode === "existing"
      ? await mintReadOnlyInstallationToken(config, jwt, "target-preflight")
      : await mintEffectInstallationToken(config, jwt);
    evidence.setup_token = { minted: Boolean(minted.token), ...minted.metadata, exchange_http_status: minted.response.status };
    token = minted.token;
    if (!token) throw new Error(`TOKEN_EXCHANGE_FAILED: GitHub access-token exchange HTTP ${minted.response.status}`);

    const repositories = await listInstallationRepositories(token);
    const rows = repositories.body && typeof repositories.body === "object" && !Array.isArray(repositories.body) ? (repositories.body as JsonObject).repositories : null;
    const targetRepo = Array.isArray(rows) ? rows.find((row) => row && typeof row === "object" && !Array.isArray(row) && (row as JsonObject).full_name === `${FIXED_OWNER}/${FIXED_REPOSITORY}`) as JsonObject | undefined : undefined;
    evidence.repository_scope = { http_status: repositories.status, target_repository: targetRepo ? { full_name: targetRepo.full_name, private: targetRepo.private } : null };
    if (repositories.status !== 200 || !targetRepo || targetRepo.private !== true || config.owner !== FIXED_OWNER || config.repository !== FIXED_REPOSITORY) throw new Error("TOKEN_SCOPE_INVALID: exact private repository scope was not proven");

    if (mode === "existing") {
      const exact = await exactKey(token, FIXED_OWNER, FIXED_REPOSITORY, targetExpectation!.id);
      const listed = await listKeys(token, FIXED_OWNER, FIXED_REPOSITORY);
      const body = targetFromBody(exact.body);
      const listValid = repositoryListIsWellFormed(listed.body);
      const present = exact.status === 200 && body?.id === targetExpectation!.id && body.title === targetExpectation!.title && body.read_only === true && listed.status === 200 && listValid && repositoryContains(listed.body, targetExpectation!.id);
      evidence.target = { id: body?.id ?? targetExpectation!.id, title: body?.title ?? targetExpectation!.title, read_only: body?.read_only ?? null, repository: `${FIXED_OWNER}/${FIXED_REPOSITORY}` };
      evidence.target_preflight = { exact_get: safeResponse(exact), list_get: safeResponse(listed), list_body_valid: listValid, list_contains_target: repositoryContains(listed.body, targetExpectation!.id), target_present: present };
      if (!present) throw new Error("FRESH_TARGET_NOT_READY: existing target did not match the frozen exact target");
      evidence.status = "FRESH_TARGET_READY";
    } else {
      const target = await createDisposableDeployKey(token, config);
      cleanup = target.cleanup;
      evidence.target = { id: target.id, title: target.title, read_only: target.readOnly, repository: target.repository };
      evidence.provider_mutations = { deploy_key_create_count: 1, deploy_key_delete_count: 0 };
      evidence.status = "READY";
    }
  } catch (error) {
    evidence.status = "TARGET_PREFLIGHT_FAILED";
    evidence.error = redact(error, [token ?? ""]);
    throw error;
  } finally {
    if (token) {
      try {
        const revoke = await revokeInstallationToken(token);
        const refusal = revoke.status === 204 ? await repositoryRead(token, FIXED_OWNER, FIXED_REPOSITORY) : null;
        evidence.token_cleanup = { revoke_http_status: revoke.status, revoked: revoke.status === 204, same_token_probe_http_status: refusal?.status ?? null, same_token_refused: refusal ? refusal.status === 401 || refusal.status === 403 : false };
        if (revoke.status !== 204 || !refusal || (refusal.status !== 401 && refusal.status !== 403)) cleanupError = new Error("target preflight token cleanup gate failed");
      } catch (error) {
        cleanupError = error;
        evidence.token_cleanup = { revoke_http_status: null, revoked: false, same_token_probe_http_status: null, same_token_refused: false, error: redact(error, [token]) };
      }
    }
    if (cleanup) {
      try { await cleanup(); } catch (error) { cleanupError ??= error; }
    }
    if (cleanupError) {
      evidence.status = "TARGET_PREFLIGHT_FAILED";
      evidence.error = redact(cleanupError, [token ?? ""]);
    }
    await mkdir(path.dirname(output), { recursive: true });
    await writeFile(output, `${JSON.stringify(evidence, null, 2)}\n`, "utf8");
  }
  if (cleanupError) throw cleanupError;
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((error) => { console.error(`C1 target setup failed: ${redact(error, [process.env.GITHUB_APP_PRIVATE_KEY ?? "", process.env.GITHUB_PAT ?? ""])}`); process.exitCode = 1; });
