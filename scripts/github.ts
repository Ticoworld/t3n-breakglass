import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import { redactError, required } from "./lib.js";

const execFileAsync = promisify(execFile);
const root = path.resolve(import.meta.dirname, "..");
const rawDir = path.join(root, "evidence", "raw");
const phase2KeyBase = path.join(rawDir, "t3n-breakglass-phase2-disposable");
const phase2KeyTitle = "breakglass-phase2-disposable";
const API_BASE = "https://api.github.com";
const API_VERSION = "2026-03-10";

export type GithubTarget = {
  host: typeof API_BASE;
  owner: string;
  repository: string;
  deployKeyId: number;
  title?: string;
  readOnly?: boolean;
  repositoryPrivate: boolean;
  keyCount: number;
};

type GithubKey = {
  id?: number;
  title?: string;
  key?: string;
  read_only?: boolean;
  created_at?: string;
};

export function assertGithubPathSegment(value: string, label: "owner" | "repository"): string {
  const pattern = label === "owner"
    ? /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/
    : /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})$/;
  if (!pattern.test(value) || value === "." || value === "..") throw new Error(`${label} contains unsafe characters`);
  return value;
}

function normalizePublicKey(value: string): string {
  const parts = value.trim().split(/\s+/);
  return parts.length >= 2 ? `${parts[0]} ${parts[1]}` : value.trim();
}

async function exists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

function githubHeaders(pat: string, userAgent: string): HeadersInit {
  return {
    Authorization: `Bearer ${pat}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": API_VERSION,
    "User-Agent": userAgent,
  };
}

async function request<T>(
  pat: string,
  pathname: string,
  userAgent: string,
  init?: RequestInit,
): Promise<{ status: number; value: T }> {
  const response = await fetch(`${API_BASE}${pathname}`, {
    ...init,
    redirect: "error",
    headers: { ...githubHeaders(pat, userAgent), ...(init?.headers ?? {}) },
  });
  if (!response.ok) throw new Error(`${init?.method ?? "GET"} ${pathname} failed with HTTP ${response.status}`);
  return { status: response.status, value: await response.json() as T };
}

export async function inspectGithubTarget(ownerInput: string, repositoryInput: string, deployKeyId: number): Promise<GithubTarget> {
  const owner = assertGithubPathSegment(ownerInput, "owner");
  const repository = assertGithubPathSegment(repositoryInput, "repository");
  if (!Number.isSafeInteger(deployKeyId) || deployKeyId <= 0) throw new Error("deploy-key ID must be a positive integer");
  const pat = required("GITHUB_PAT");
  const userAgent = "breakglass-phase2-operator";
  const base = `/repos/${owner}/${repository}`;
  const repo = (await request<{ private?: boolean; full_name?: string }>(pat, base, userAgent)).value;
  if (repo.private !== true || repo.full_name !== `${owner}/${repository}`) {
    throw new Error("target repository is not the expected private repository");
  }
  const keyResponse = await request<GithubKey>(pat, `${base}/keys/${deployKeyId}`, userAgent);
  const listResponse = await request<GithubKey[]>(pat, `${base}/keys`, userAgent);
  if (!Number.isSafeInteger(keyResponse.value.id) || keyResponse.value.id !== deployKeyId) {
    throw new Error("GitHub returned an unexpected deploy-key ID");
  }
  if (!Array.isArray(listResponse.value) || !listResponse.value.some((key) => key.id === deployKeyId)) {
    throw new Error("deploy key was not present in the repository key list");
  }
  return {
    host: API_BASE,
    owner,
    repository,
    deployKeyId,
    title: keyResponse.value.title,
    readOnly: keyResponse.value.read_only,
    repositoryPrivate: true,
    keyCount: listResponse.value.length,
  };
}

export async function verifyGithubAbsent(ownerInput: string, repositoryInput: string, deployKeyId: number): Promise<{
  host: typeof API_BASE;
  owner: string;
  repository: string;
  deployKeyId: number;
  exactKeyGetHttpStatus: number;
  keyListHttpStatus: number;
  keyCount: number;
  absent: boolean;
}> {
  const owner = assertGithubPathSegment(ownerInput, "owner");
  const repository = assertGithubPathSegment(repositoryInput, "repository");
  if (!Number.isSafeInteger(deployKeyId) || deployKeyId <= 0) throw new Error("deploy-key ID must be a positive integer");
  const pat = required("GITHUB_PAT");
  const base = `/repos/${owner}/${repository}`;
  const headers = githubHeaders(pat, "breakglass-phase2-independent-verification");
  const exact = await fetch(`${API_BASE}${base}/keys/${deployKeyId}`, { headers, redirect: "error" });
  const list = await fetch(`${API_BASE}${base}/keys`, { headers, redirect: "error" });
  const keys = await list.json() as GithubKey[];
  if (exact.status !== 404 || !list.ok || !Array.isArray(keys)) {
    throw new Error(`GitHub after-state failed: exact key ${exact.status}, list ${list.status}`);
  }
  return {
    host: API_BASE,
    owner,
    repository,
    deployKeyId,
    exactKeyGetHttpStatus: exact.status,
    keyListHttpStatus: list.status,
    keyCount: keys.length,
    absent: keys.every((key) => key.id !== deployKeyId),
  };
}

export async function ensurePhase2DisposableTarget(ownerInput: string, repositoryInput: string): Promise<GithubTarget> {
  const owner = assertGithubPathSegment(ownerInput, "owner");
  const repository = assertGithubPathSegment(repositoryInput, "repository");
  const pat = required("GITHUB_PAT");
  const userAgent = "breakglass-phase2-bootstrap";
  const repoPath = `/repos/${owner}/${repository}`;
  const repo = (await request<{ private?: boolean; full_name?: string }>(pat, repoPath, userAgent)).value;
  if (repo.private !== true || repo.full_name !== `${owner}/${repository}`) {
    throw new Error("target repository is not the expected private repository");
  }

  await mkdir(rawDir, { recursive: true });
  const privateExists = await exists(phase2KeyBase);
  const publicExists = await exists(`${phase2KeyBase}.pub`);
  if (!privateExists && !publicExists) {
    await execFileAsync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", phase2KeyTitle, "-f", phase2KeyBase]);
  } else if (!privateExists || !publicExists) {
    throw new Error("Phase 2 disposable keypair is incomplete; refusing to overwrite it");
  }
  const publicKey = (await readFile(`${phase2KeyBase}.pub`, "utf8")).trim();
  if (!/^ssh-ed25519\s+[A-Za-z0-9+/]+={0,2}(?:\s+.*)?$/.test(publicKey)) {
    throw new Error("Phase 2 public key is not a valid ed25519 OpenSSH key");
  }
  const normalizedPublicKey = normalizePublicKey(publicKey);
  let keys = (await request<GithubKey[]>(pat, `${repoPath}/keys`, userAgent)).value;
  if (!Array.isArray(keys)) throw new Error("GitHub deploy-key list was not an array");
  if (keys.length === 0) {
    await request<GithubKey>(pat, `${repoPath}/keys`, userAgent, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: phase2KeyTitle, key: publicKey, read_only: true }),
    });
  } else if (keys.length === 1 && keys[0]?.title === phase2KeyTitle && keys[0]?.read_only === true && Number.isSafeInteger(keys[0]?.id)) {
    const existing = (await request<GithubKey>(pat, `${repoPath}/keys/${keys[0].id}`, userAgent)).value;
    if (!existing.key || normalizePublicKey(existing.key) !== normalizedPublicKey) {
      throw new Error("existing Phase 2 deploy key does not match the local disposable key");
    }
  } else {
    throw new Error(`refusing to proceed: expected zero keys or the exact Phase 2 key, found ${keys.length}`);
  }

  keys = (await request<GithubKey[]>(pat, `${repoPath}/keys`, userAgent)).value;
  const intended = keys.length === 1 && keys[0]?.title === phase2KeyTitle && keys[0]?.read_only === true && Number.isSafeInteger(keys[0]?.id)
    ? keys[0]
    : undefined;
  if (!intended || !Number.isSafeInteger(intended.id)) throw new Error("Phase 2 target verification did not find exactly one read-only key");
  const verified = (await request<GithubKey>(pat, `${repoPath}/keys/${intended.id}`, userAgent)).value;
  if (!verified.key || normalizePublicKey(verified.key) !== normalizedPublicKey || verified.read_only !== true) {
    throw new Error("Phase 2 target verification did not match the local read-only key");
  }
  return {
    host: API_BASE,
    owner,
    repository,
    deployKeyId: intended.id,
    title: intended.title,
    readOnly: intended.read_only,
    repositoryPrivate: true,
    keyCount: keys.length,
  };
}

export async function writePhase2TargetEvidence(target: GithubTarget): Promise<void> {
  const evidence = {
    phase: "2",
    stage: "demo_github_target_ready",
    host: target.host,
    owner: target.owner,
    repository: target.repository,
    repository_private: target.repositoryPrivate,
    deploy_key_count: target.keyCount,
    deploy_key: { id: target.deployKeyId, title: target.title, read_only: target.readOnly },
    private_key_path: "evidence/raw/t3n-breakglass-phase2-disposable (ignored; not included)",
    github_pat_logged: false,
  };
  await mkdir(path.join(root, "evidence"), { recursive: true });
  await writeFile(path.join(root, "evidence", "phase2-demo-target.json"), JSON.stringify(evidence, null, 2) + "\n");
}

export function redactGithubError(error: unknown): string {
  return redactError(error, [process.env.GITHUB_PAT ?? ""]);
}
