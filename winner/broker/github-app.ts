import { createSign, randomBytes } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const API = "https://api.github.com";
const API_VERSION = "2022-11-28";
const REPOSITORY_ROOT = path.resolve(import.meta.dirname, "../..");

type GithubResponse = { status: number; body: unknown; responseHeaders: Record<string, string> };

function b64url(value: string | Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function safeBody(body: unknown): unknown {
  if (typeof body !== "string") return body;
  return body
    .replace(/(Authorization\s*:\s*Bearer\s+)[A-Za-z0-9._~+\/-]+/gi, "$1[REDACTED]")
    .replace(/(Bearer\s+)[A-Za-z0-9._~+\/-]+/gi, "$1[REDACTED]")
    .replace(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, "[REDACTED_JWT]")
    .replace(/(gh[pousr]_|github_pat_|t3n_key_)[A-Za-z0-9._~+\/-]+/gi, "$1[REDACTED_TOKEN]");
}

async function request(method: string, route: string, token: string, body?: unknown): Promise<GithubResponse> {
  const response = await fetch(`${API}${route}`, {
    method,
    headers: {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": API_VERSION,
      "User-Agent": "t3n-breakglass-c1-effect-broker",
      Authorization: `Bearer ${token}`,
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: "error",
  });
  const text = await response.text();
  let decoded: unknown = null;
  try { decoded = text ? JSON.parse(text) : null; } catch { decoded = safeBody(text); }
  const responseHeaders: Record<string, string> = {};
  for (const header of ["x-github-request-id", "x-ratelimit-remaining", "retry-after"]) { const value = response.headers.get(header); if (value) responseHeaders[header] = value; }
  return { status: response.status, body: decoded, responseHeaders };
}

export type AppConfig = { appId: string; installationId: string; privateKeyPath: string; owner: string; repository: string };

export function appConfigFromEnvironment(env: NodeJS.ProcessEnv): AppConfig {
  const appId = env.GITHUB_APP_ID;
  const installationId = env.GITHUB_APP_INSTALLATION_ID;
  const privateKeyPath = env.GITHUB_APP_PRIVATE_KEY_PATH;
  const owner = env.GITHUB_OWNER;
  const repository = env.GITHUB_REPO;
  if (!appId || !installationId || !privateKeyPath || !owner || !repository) throw new Error("GITHUB_APP_ID, GITHUB_APP_INSTALLATION_ID, GITHUB_APP_PRIVATE_KEY_PATH, GITHUB_OWNER, and GITHUB_REPO are required");
  if (owner !== "Ticoworld" || repository !== "t3n-breakglass-sandbox") throw new Error("C1 refuses an unexpected GitHub target");
  if (!/^\d+$/.test(appId) || !/^\d+$/.test(installationId)) throw new Error("GitHub App identifiers are invalid");
  const relativeKeyPath = path.relative(REPOSITORY_ROOT, path.resolve(privateKeyPath));
  if (relativeKeyPath === "" || (!relativeKeyPath.startsWith(`..${path.sep}`) && relativeKeyPath !== ".." && !path.isAbsolute(relativeKeyPath))) throw new Error("C1 GitHub App private key must be outside the repository");
  return { appId, installationId, privateKeyPath, owner, repository };
}

export async function appJwt(config: AppConfig): Promise<string> {
  const pem = await readFile(config.privateKeyPath, "utf8");
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = b64url(JSON.stringify({ iat: now - 60, exp: now + 540, iss: config.appId }));
  const unsigned = `${header}.${payload}`;
  const signer = createSign("RSA-SHA256");
  signer.update(unsigned);
  signer.end();
  return `${unsigned}.${signer.sign(pem).toString("base64url")}`;
}

export async function validateInstallation(config: AppConfig, jwt: string): Promise<GithubResponse> {
  return request("GET", `/app/installations/${config.installationId}`, jwt);
}

export async function mintInstallationToken(config: AppConfig, jwt: string): Promise<{ response: GithubResponse; token: string | null; metadata: Record<string, unknown> }> {
  const response = await request("POST", `/app/installations/${config.installationId}/access_tokens`, jwt, { repositories: [config.repository], permissions: { administration: "write" } });
  if (response.status < 200 || response.status >= 300 || !response.body || typeof response.body !== "object") return { response, token: null, metadata: {} };
  const body = response.body as Record<string, unknown>;
  const token = typeof body.token === "string" ? body.token : null;
  const repositories = Array.isArray(body.repositories) ? body.repositories.filter((repo) => repo && typeof repo === "object").map((repo) => ({ name: (repo as Record<string, unknown>).name, full_name: (repo as Record<string, unknown>).full_name, private: (repo as Record<string, unknown>).private })) : [];
  return { response, token, metadata: { expires_at: body.expires_at ?? null, repository_selection: body.repository_selection ?? null, permissions: body.permissions ?? null, repositories } };
}

export async function listInstallationRepositories(token: string): Promise<GithubResponse> { return request("GET", "/installation/repositories?per_page=100", token); }
export async function exactKey(token: string, owner: string, repository: string, keyId: number): Promise<GithubResponse> { return request("GET", `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repository)}/keys/${keyId}`, token); }
export async function listKeys(token: string, owner: string, repository: string): Promise<GithubResponse> { return request("GET", `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repository)}/keys?per_page=100`, token); }
export async function deleteKey(token: string, owner: string, repository: string, keyId: number): Promise<GithubResponse> { return request("DELETE", `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repository)}/keys/${keyId}`, token); }
export async function revokeInstallationToken(token: string): Promise<GithubResponse> { return request("DELETE", "/installation/token", token); }
export async function repositoryRead(token: string, owner: string, repository: string): Promise<GithubResponse> { return request("GET", `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repository)}`, token); }

export async function createDisposableDeployKey(token: string, config: AppConfig): Promise<{ id: number; title: string; readOnly: boolean; repository: string; cleanup: () => Promise<void> }> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "breakglass-c1-ssh-"));
  const privatePath = path.join(directory, "id_ed25519");
  const title = `breakglass-c1-${Date.now()}-${randomBytes(4).toString("hex")}`;
  try {
    // Generate OpenSSH material locally. The private bytes never enter the
    // repository or evidence and are removed by the returned cleanup hook.
    const { execFileSync } = await import("node:child_process");
    execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "c1-disposable", "-f", privatePath], { stdio: ["ignore", "ignore", "ignore"] });
    await chmod(privatePath, 0o600);
    const publicPath = `${privatePath}.pub`;
    const publicKey = execFileSync("ssh-keygen", ["-y", "-f", privatePath], { stdio: ["ignore", "pipe", "ignore"] }).toString().trim();
    await writeFile(publicPath, `${publicKey} c1-disposable\n`, { mode: 0o600 });
    const response = await request("POST", `/repos/${encodeURIComponent(config.owner)}/${encodeURIComponent(config.repository)}/keys`, token, { title, key: `${publicKey} c1-disposable`, read_only: true });
    if (response.status !== 201 || !response.body || typeof response.body !== "object") throw new Error(`TARGET_SETUP_FAILED: GitHub deploy-key create HTTP ${response.status}`);
    const body = response.body as Record<string, unknown>;
    const id = Number(body.id);
    if (!Number.isSafeInteger(id) || id <= 0 || body.title !== title || body.read_only !== true) throw new Error("TARGET_SETUP_FAILED: GitHub returned invalid deploy-key metadata");
    return { id, title, readOnly: true, repository: `${config.owner}/${config.repository}`, cleanup: async () => { await rm(directory, { recursive: true, force: true }); } };
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}

export function repositoryContains(body: unknown, keyId: number): boolean {
  return Array.isArray(body) && body.some((entry) => entry && typeof entry === "object" && Number((entry as Record<string, unknown>).id) === keyId);
}

export function repositoryListIsWellFormed(body: unknown): boolean {
  return Array.isArray(body) && body.every((entry) => entry && typeof entry === "object" && Number.isSafeInteger(Number((entry as Record<string, unknown>).id)) && Number((entry as Record<string, unknown>).id) > 0);
}
