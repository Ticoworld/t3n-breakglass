import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { redactError, required } from "./lib.js";

const root = path.resolve(import.meta.dirname, "..");

type TargetEvidence = {
  owner?: string;
  repository?: string;
  deploy_key?: { id?: number; title?: string; read_only?: boolean };
};

async function main() {
  const pat = required("GITHUB_PAT");
  const owner = required("GITHUB_OWNER");
  const repository = required("GITHUB_REPO");
  if (owner !== "Ticoworld" || repository !== "t3n-breakglass-sandbox") throw new Error("unexpected GitHub target");

  const prior = JSON.parse(await readFile(path.join(root, "evidence", "phase1-github-target.json"), "utf8")) as TargetEvidence;
  const keyId = prior.deploy_key?.id;
  if (!Number.isSafeInteger(keyId) || keyId <= 0) throw new Error("prior target evidence has no valid deploy-key ID");

  const headers = {
    Authorization: `Bearer ${pat}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2026-03-10",
    "User-Agent": "breakglass-phase1-before-verification",
  };
  const base = `https://api.github.com/repos/${owner}/${repository}`;
  const repoResponse = await fetch(base, { headers, redirect: "error" });
  if (!repoResponse.ok) throw new Error(`repository verification failed with HTTP ${repoResponse.status}`);
  const repo = await repoResponse.json() as { private?: boolean; full_name?: string };
  const keyResponse = await fetch(`${base}/keys/${keyId}`, { headers, redirect: "error" });
  const listResponse = await fetch(`${base}/keys`, { headers, redirect: "error" });
  if (!keyResponse.ok || !listResponse.ok) throw new Error(`GitHub target verification failed: key ${keyResponse.status}, list ${listResponse.status}`);
  const key = await keyResponse.json() as { id?: number; title?: string; read_only?: boolean; created_at?: string };
  const keys = await listResponse.json() as Array<{ id?: number; title?: string; read_only?: boolean; created_at?: string }>;
  const intended = keys.filter((candidate) => candidate.id === keyId);
  if (repo.private !== true || repo.full_name !== `${owner}/${repository}` || keys.length !== 1 || intended.length !== 1 || key.read_only !== true) {
    throw new Error(`target precondition failed: private=${repo.private}, list_count=${keys.length}, intended_count=${intended.length}, read_only=${key.read_only}`);
  }

  const evidence = {
    phase: "1",
    stage: "current_github_before_verification",
    host: "api.github.com",
    owner,
    repository,
    repository_private: repo.private,
    deploy_key_id: keyId,
    exact_key_get_http_status: keyResponse.status,
    deploy_key_list_http_status: listResponse.status,
    deploy_key_count: keys.length,
    deploy_key: {
      id: key.id,
      title: key.title,
      read_only: key.read_only,
      created_at: key.created_at,
    },
    github_pat_logged: false,
    github_destructive_calls: 0,
  };
  await mkdir(path.join(root, "evidence"), { recursive: true });
  await writeFile(path.join(root, "evidence", "phase1-github-before-current.json"), JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((error) => {
  console.error(`current GitHub target verification failed: ${redactError(error, [process.env.GITHUB_PAT ?? "", process.env.T3N_API_KEY ?? ""])}`);
  process.exitCode = 1;
});
