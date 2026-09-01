import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import { redactError, required } from "./lib.js";

const execFileAsync = promisify(execFile);
const root = path.resolve(import.meta.dirname, "..");
const evidenceDir = path.join(root, "evidence");
const rawDir = path.join(evidenceDir, "raw");
const keyBase = path.join(rawDir, "t3n-breakglass-phase1-deploy");
const keyTitle = "breakglass-phase1-disposable";
const apiBase = "https://api.github.com";

function normalizePublicKey(value: string): string {
  const parts = value.trim().split(/\s+/);
  return parts.length >= 2 ? `${parts[0]} ${parts[1]}` : value.trim();
}

type DeployKey = {
  id?: number;
  title?: string;
  key?: string;
  read_only?: boolean;
  created_at?: string;
};

async function exists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function main() {
  const pat = required("GITHUB_PAT");
  const owner = required("GITHUB_OWNER");
  const repository = required("GITHUB_REPO");
  if (owner !== "Ticoworld") throw new Error("GITHUB_OWNER must be Ticoworld");
  if (repository !== "t3n-breakglass-sandbox") {
    throw new Error("GITHUB_REPO must be t3n-breakglass-sandbox");
  }

  const headers = {
    Authorization: `Bearer ${pat}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2026-03-10",
    "User-Agent": "breakglass-phase1-bootstrap",
  };
  const repoPath = `/repos/${owner}/${repository}`;

  async function request(pathname: string, init?: RequestInit): Promise<unknown> {
    const response = await fetch(`${apiBase}${pathname}`, {
      ...init,
      redirect: "error",
      headers: { ...headers, ...(init?.headers ?? {}) },
    });
    const body = await response.text();
    let parsed: unknown = undefined;
    if (body) {
      try {
        parsed = JSON.parse(body);
      } catch {
        parsed = undefined;
      }
    }
    if (!response.ok) throw new Error(`${init?.method ?? "GET"} ${pathname} failed with HTTP ${response.status}`);
    return parsed;
  }

  const repo = await request(repoPath) as { private?: boolean; full_name?: string };
  if (repo.private !== true || repo.full_name !== `${owner}/${repository}`) {
    throw new Error("target repository is not the expected private repository");
  }

  await mkdir(rawDir, { recursive: true });
  const privateExists = await exists(keyBase);
  const publicExists = await exists(`${keyBase}.pub`);
  if (!privateExists && !publicExists) {
    await execFileAsync("ssh-keygen", [
      "-q",
      "-t", "ed25519",
      "-N", "",
      "-C", keyTitle,
      "-f", keyBase,
    ]);
  } else if (!privateExists || !publicExists) {
    throw new Error("disposable keypair is incomplete; refusing to overwrite it");
  }

  const publicKey = (await readFile(`${keyBase}.pub`, "utf8")).trim();
  if (!/^ssh-ed25519\s+[A-Za-z0-9+/]+={0,2}(?:\s+.*)?$/.test(publicKey)) {
    throw new Error("generated public key is not an ed25519 OpenSSH key");
  }
  const normalizedPublicKey = normalizePublicKey(publicKey);

  const listKeys = async (): Promise<DeployKey[]> => {
    const keys = await request(`${repoPath}/keys`) as unknown;
    if (!Array.isArray(keys)) throw new Error("GitHub deploy-key response was not an array");
    return keys as DeployKey[];
  };

  let keys = await listKeys();
  if (keys.length === 0) {
    await request(`${repoPath}/keys`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: keyTitle, key: publicKey, read_only: true }),
    });
  } else if (keys.length === 1 && keys[0]?.title === keyTitle && keys[0]?.read_only === true && Number.isSafeInteger(keys[0]?.id)) {
    // The list endpoint may omit the key material. Fetch the individual key
    // before treating an existing entry as the exact disposable key.
    const existing = await request(`${repoPath}/keys/${keys[0].id}`) as DeployKey;
    if (!existing.key || normalizePublicKey(existing.key) !== normalizedPublicKey) {
      throw new Error("existing deploy key title does not match the local disposable key");
    }
  } else {
    throw new Error(`refusing to proceed: expected zero keys or the exact existing disposable key, found ${keys.length}`);
  }

  keys = await listKeys();
  const intended = keys.length === 1 && keys[0]?.title === keyTitle && keys[0]?.read_only === true && Number.isSafeInteger(keys[0]?.id)
    ? keys[0]
    : undefined;
  if (!intended || !Number.isSafeInteger(intended.id)) {
    throw new Error("post-setup verification did not find exactly one read-only intended deploy key");
  }
  const verified = await request(`${repoPath}/keys/${intended.id}`) as DeployKey;
  if (!verified.key || normalizePublicKey(verified.key) !== normalizedPublicKey || verified.title !== keyTitle || verified.read_only !== true) {
    throw new Error("post-setup deploy-key verification did not match the local read-only key");
  }

  const evidence = {
    phase: "1",
    status: "target_ready",
    host: "api.github.com",
    owner,
    repository,
    repository_private: true,
    deploy_key_count: keys.length,
    deploy_key: {
      id: intended.id,
      title: intended.title,
      read_only: intended.read_only,
      created_at: intended.created_at,
    },
    keypair: {
      private_path: "evidence/raw/t3n-breakglass-phase1-deploy (ignored; not included)",
      public_path: "evidence/raw/t3n-breakglass-phase1-deploy.pub",
    },
    github_pat_logged: false,
    github_pat_in_invoke_process: false,
  };
  await mkdir(evidenceDir, { recursive: true });
  await writeFile(path.join(evidenceDir, "phase1-github-target.json"), JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((error) => {
  console.error(`GitHub setup failed: ${redactError(error, [process.env.GITHUB_PAT ?? "", process.env.T3N_API_KEY ?? ""])}`);
  process.exitCode = 1;
});
