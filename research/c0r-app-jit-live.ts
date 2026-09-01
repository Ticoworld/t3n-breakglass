import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createSign } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const repoRoot = process.cwd();
const configPath = join(repoRoot, ".env.c0r-github-app");
const apiBase = "https://api.github.com";
const githubApiVersion = "2022-11-28";
const expected = {
  appId: "4793116",
  installationId: "158227303",
  privateKeyPath: "C:\\Users\\timot\\.breakglass-secrets\\breakglass-c0r-github-app.pem",
  owner: "Ticoworld",
  repository: "t3n-breakglass-sandbox",
};

type JsonObject = Record<string, any>;

function parseConfig(text: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const separator = trimmed.indexOf("=");
    if (separator <= 0) continue;
    result[trimmed.slice(0, separator).trim()] = trimmed.slice(separator + 1).trim();
  }
  return result;
}

function safeError(error: unknown): JsonObject {
  if (error instanceof Error) return { name: error.name, message: error.message };
  return { name: "Error", message: String(error) };
}

function base64url(value: string | Buffer): string {
  return Buffer.from(value).toString("base64url");
}

function mintAppJwt(appId: string, privateKeyPem: string): string {
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64url(JSON.stringify({ iss: appId, iat: now - 60, exp: now + 540 }));
  const signingInput = `${header}.${payload}`;
  const signer = createSign("RSA-SHA256");
  signer.update(signingInput);
  signer.end();
  return `${signingInput}.${signer.sign(privateKeyPem).toString("base64url")}`;
}

type ApiResult = {
  status: number | null;
  ok: boolean;
  data?: any;
  error?: JsonObject;
};

async function githubRequest(path: string, options: { token?: string; method?: string; body?: JsonObject } = {}): Promise<ApiResult> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": githubApiVersion,
    "User-Agent": "BreakGlass-C0R-JIT-Probe",
  };
  if (options.token) headers.Authorization = `Bearer ${options.token}`;
  if (options.body) headers["Content-Type"] = "application/json";
  try {
    const response = await fetch(`${apiBase}${path}`, {
      method: options.method ?? "GET",
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
    });
    const text = await response.text();
    let data: any = undefined;
    if (text) {
      try { data = JSON.parse(text); } catch { data = undefined; }
    }
    return { status: response.status, ok: response.ok, data };
  } catch (error) {
    return { status: null, ok: false, error: safeError(error) };
  }
}

function keyMetadata(value: any): JsonObject {
  return {
    id: typeof value?.id === "number" ? value.id : null,
    title: typeof value?.title === "string" ? value.title : null,
    read_only: value?.read_only === true,
  };
}

function listKeyMetadata(value: any): JsonObject[] {
  return Array.isArray(value) ? value.map(keyMetadata) : [];
}

function sameTargetKeyPresent(list: JsonObject[], keyId: number): boolean {
  return list.some((key) => key.id === keyId);
}

const result: JsonObject = {
  experiment: "R5 live GitHub App installation-token JIT authority",
  date_utc: new Date().toISOString(),
  classification: "SETUP_BLOCKED",
  github_api_version: githubApiVersion,
  app: {
    name: "BreakGlass C0R JIT Probe",
    app_id: Number(expected.appId),
    installation_id: Number(expected.installationId),
  },
  target: {
    owner: expected.owner,
    repository: expected.repository,
    repository_private: null,
  },
  credential_safety: {
    private_key_in_evidence: false,
    jwt_in_evidence: false,
    installation_token_in_evidence: false,
    authorization_header_in_evidence: false,
    pat_used: false,
  },
  token: {
    requested_repositories: [expected.repository],
    requested_permissions: { administration: "write" },
    expires_at: null,
    scope_verified: false,
  },
  deploy_key: { id: null, title: null, read_only: null },
  before: { exact_get_http_status: null, list_http_status: null, target_present: false },
  delete: { attempted: false, destructive_call_count: 0, http_status: null, provider_acknowledged: false },
  after: { exact_get_http_status: null, list_http_status: null, target_absent: false, verified_absent: false },
  revoke: { attempted: false, http_status: null, success: false },
  revoked_token_probe: { same_token: true, http_status: null, refused: false },
  standing_root_note: "GitHub App private key remains a standing trust root.",
};

let installationToken: string | undefined;
let temporaryKeyDir: string | undefined;
let revokeNeeded = false;

try {
  if (process.env.GITHUB_PAT) throw new Error("GITHUB_PAT is present; refusing to run and refusing PAT fallback");
  const config = parseConfig(await readFile(configPath, "utf8"));
  const missing = [
    "GITHUB_APP_ID",
    "GITHUB_APP_INSTALLATION_ID",
    "GITHUB_APP_PRIVATE_KEY_PATH",
    "GITHUB_OWNER",
    "GITHUB_REPO",
  ].filter((name) => !config[name]);
  if (missing.length) throw new Error(`missing configuration variables: ${missing.join(",")}`);
  const mismatch = Object.entries({
    GITHUB_APP_ID: expected.appId,
    GITHUB_APP_INSTALLATION_ID: expected.installationId,
    GITHUB_APP_PRIVATE_KEY_PATH: expected.privateKeyPath,
    GITHUB_OWNER: expected.owner,
    GITHUB_REPO: expected.repository,
  }).filter(([name, value]) => config[name] !== value).map(([name]) => name);
  if (mismatch.length) throw new Error(`configuration mismatch: ${mismatch.join(",")}`);

  const privateKeyPem = await readFile(config.GITHUB_APP_PRIVATE_KEY_PATH, "utf8");
  const jwt = mintAppJwt(config.GITHUB_APP_ID, privateKeyPem);

  const appResponse = await githubRequest("/app", { token: jwt });
  if (appResponse.status !== 200 || appResponse.data?.id !== Number(expected.appId)) {
    result.classification = "JWT_MINT_FAILED";
    result.failure = { stage: "app_validation", http_status: appResponse.status, error: appResponse.error ?? null };
    throw new Error("App JWT validation failed");
  }
  result.app.name = typeof appResponse.data.name === "string" ? appResponse.data.name : result.app.name;

  const installationResponse = await githubRequest(`/app/installations/${expected.installationId}`, { token: jwt });
  const installation = installationResponse.data;
  const installationMatches = installationResponse.status === 200
    && installation?.id === Number(expected.installationId)
    && installation?.account?.login === expected.owner;
  result.installation_validation = {
    http_status: installationResponse.status,
    installation_id: installation?.id ?? null,
    account_login: installation?.account?.login ?? null,
    repository_selection: installation?.repository_selection ?? null,
    matches_expected_owner: installation?.account?.login === expected.owner,
  };
  if (!installationMatches) {
    result.classification = "INSTALLATION_MISMATCH";
    throw new Error("installation validation failed");
  }

  const tokenResponse = await githubRequest(`/app/installations/${expected.installationId}/access_tokens`, {
    token: jwt,
    method: "POST",
    body: {
      repositories: [expected.repository],
      permissions: { administration: "write" },
    },
  });
  const tokenData = tokenResponse.data;
  if (tokenResponse.status !== 201 || typeof tokenData?.token !== "string") {
    result.classification = "TOKEN_EXCHANGE_FAILED";
    result.token.exchange_http_status = tokenResponse.status;
    result.token.exchange_error = tokenResponse.error ?? null;
    throw new Error("installation token exchange failed");
  }
  installationToken = tokenData.token;
  revokeNeeded = true;
  result.token.expires_at = tokenData.expires_at ?? null;
  result.token.repository_selection = tokenData.repository_selection ?? null;
  result.token.response_permissions = tokenData.permissions ?? null;
  result.token.response_repositories = Array.isArray(tokenData.repositories)
    ? tokenData.repositories.map((repo: any) => repo?.full_name).filter((name: unknown): name is string => typeof name === "string")
    : [];

  const repositoryResponse = await githubRequest(`/repos/${expected.owner}/${expected.repository}`, { token: installationToken });
  result.target.repository_private = repositoryResponse.data?.private === true;
  result.token.scope_verified = repositoryResponse.status === 200
    && repositoryResponse.data?.full_name === `${expected.owner}/${expected.repository}`
    && repositoryResponse.data?.private === true
    && tokenData.repository_selection === "selected"
    && tokenData.permissions?.administration === "write";
  if (!result.token.scope_verified) {
    result.classification = "TOKEN_SCOPE_INVALID";
    result.token.scope_http_status = repositoryResponse.status;
    throw new Error("installation token scope could not be verified");
  }

  temporaryKeyDir = await mkdtemp(join(tmpdir(), "c0r-app-jit-"));
  const title = `breakglass-c0r-app-jit-${Date.now()}`;
  const privateKeyPath = join(temporaryKeyDir, "id_ed25519");
  await execFileAsync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", title, "-f", privateKeyPath], { windowsHide: true });
  const publicKey = (await readFile(`${privateKeyPath}.pub`, "utf8")).trim();
  if (!publicKey.startsWith("ssh-ed25519 ")) throw new Error("generated key is not an ed25519 public key");

  const createResponse = await githubRequest(`/repos/${expected.owner}/${expected.repository}/keys`, {
    token: installationToken,
    method: "POST",
    body: { title, key: publicKey, read_only: true },
  });
  if (createResponse.status !== 201 || typeof createResponse.data?.id !== "number") {
    result.classification = "TARGET_SETUP_FAILED";
    result.target_setup_http_status = createResponse.status;
    result.target_setup_error = createResponse.error ?? null;
    throw new Error("fresh deploy-key creation failed");
  }
  const keyId = createResponse.data.id;
  result.deploy_key = { id: keyId, title, read_only: createResponse.data.read_only === true };

  const beforeExact = await githubRequest(`/repos/${expected.owner}/${expected.repository}/keys/${keyId}`, { token: installationToken });
  const beforeList = await githubRequest(`/repos/${expected.owner}/${expected.repository}/keys`, { token: installationToken });
  const beforeKeys = listKeyMetadata(beforeList.data);
  result.before = {
    exact_get_http_status: beforeExact.status,
    list_http_status: beforeList.status,
    target_present: beforeExact.status === 200
      && beforeExact.data?.id === keyId
      && beforeExact.data?.read_only === true
      && beforeList.status === 200
      && sameTargetKeyPresent(beforeKeys, keyId),
    exact_get_metadata: keyMetadata(beforeExact.data),
    list_target_metadata: beforeKeys.find((key) => key.id === keyId) ?? null,
  };
  if (!result.before.target_present) {
    result.classification = "PRECHECK_FAILED";
    throw new Error("fresh deploy key precheck failed");
  }

  const deleteResponse = await githubRequest(`/repos/${expected.owner}/${expected.repository}/keys/${keyId}`, {
    token: installationToken,
    method: "DELETE",
  });
  result.delete = {
    attempted: true,
    destructive_call_count: 1,
    http_status: deleteResponse.status,
    provider_acknowledged: deleteResponse.status === 204,
    transport_error: deleteResponse.error ?? null,
  };

  const afterExact = await githubRequest(`/repos/${expected.owner}/${expected.repository}/keys/${keyId}`, { token: installationToken });
  const afterList = await githubRequest(`/repos/${expected.owner}/${expected.repository}/keys`, { token: installationToken });
  const afterKeys = listKeyMetadata(afterList.data);
  result.after = {
    exact_get_http_status: afterExact.status,
    list_http_status: afterList.status,
    target_absent: afterExact.status === 404 && afterList.status === 200 && !sameTargetKeyPresent(afterKeys, keyId),
    verified_absent: afterExact.status === 404 && afterList.status === 200 && !sameTargetKeyPresent(afterKeys, keyId),
    list_target_metadata: afterKeys.find((key) => key.id === keyId) ?? null,
  };

  if (!result.delete.provider_acknowledged && result.after.verified_absent) result.classification = "DELETE_ATTEMPTED_OUTCOME_UNKNOWN";
  else if (!result.after.verified_absent) result.classification = "VERIFICATION_FAILED";
  else if (!result.delete.provider_acknowledged) result.classification = "DELETE_ATTEMPTED_OUTCOME_UNKNOWN";

  const revokeResponse = await githubRequest("/installation/token", { token: installationToken, method: "DELETE" });
  result.revoke = {
    attempted: true,
    http_status: revokeResponse.status,
    success: revokeResponse.status === 204,
  };
  revokeNeeded = false;

  const revokedProbe = await githubRequest(`/repos/${expected.owner}/${expected.repository}`, { token: installationToken });
  result.revoked_token_probe = {
    same_token: true,
    http_status: revokedProbe.status,
    refused: revokedProbe.status === 401 || revokedProbe.status === 403,
  };

  if (!result.revoke.success) result.classification = "TOKEN_REVOKE_FAILED";
  else if (!result.revoked_token_probe.refused) result.classification = "REVOKED_TOKEN_STILL_ACCEPTED";
  else if (result.delete.provider_acknowledged && result.after.verified_absent) result.classification = "PASS";
} catch (error) {
  if (result.classification === "SETUP_BLOCKED") {
    result.failure = { stage: "configuration_or_setup", error: safeError(error) };
  } else if (!result.failure) {
    result.failure ??= { stage: "experiment", error: safeError(error) };
  }
} finally {
  // If setup failed after token mint but before the planned revoke, revoke the
  // same token. This is cleanup, not a second token or a second deploy-key
  // deletion. The result still reports the original bounded failure.
  if (revokeNeeded && installationToken) {
    const cleanup = await githubRequest("/installation/token", { token: installationToken, method: "DELETE" });
    result.cleanup_revoke = { attempted: true, http_status: cleanup.status, success: cleanup.status === 204 };
  }
  if (temporaryKeyDir) await rm(temporaryKeyDir, { recursive: true, force: true });
  result.credential_safety = {
    private_key_in_evidence: false,
    jwt_in_evidence: false,
    installation_token_in_evidence: false,
    authorization_header_in_evidence: false,
    pat_used: false,
  };
  await import("node:fs/promises").then(({ writeFile }) => writeFile(
    join(repoRoot, "research", "C-0R-app-jit-live-result.json"),
    `${JSON.stringify(result, null, 2)}\n`,
    "utf8",
  ));
  console.log(JSON.stringify(result, null, 2));
}
