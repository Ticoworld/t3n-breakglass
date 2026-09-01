import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { redactError, required } from "./lib.js";

const root = path.resolve(import.meta.dirname, "..");
const evidenceDir = path.join(root, "evidence");

async function main() {
  const pat = required("GITHUB_PAT");
  const owner = required("GITHUB_OWNER");
  const repository = required("GITHUB_REPO");
  if (owner !== "Ticoworld") throw new Error("GITHUB_OWNER must be Ticoworld");
  if (!/^[A-Za-z0-9_.-]+$/.test(repository)) throw new Error("GITHUB_REPO contains unsafe characters");

  const headers = {
    Authorization: `Bearer ${pat}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2026-03-10",
    "User-Agent": "breakglass-phase0-bootstrap",
  };
  const repoUrl = `https://api.github.com/repos/${owner}/${repository}`;
  const repoResponse = await fetch(repoUrl, { headers });
  if (!repoResponse.ok) throw new Error(`repository inspection failed with HTTP ${repoResponse.status}`);
  const repo = await repoResponse.json() as { private?: boolean; full_name?: string };
  if (repo.private !== true || repo.full_name !== `${owner}/${repository}`) {
    throw new Error("target is not the expected private repository");
  }

  const keysResponse = await fetch(`${repoUrl}/keys`, { headers });
  if (!keysResponse.ok) throw new Error(`deploy-key inspection failed with HTTP ${keysResponse.status}`);
  const keys = await keysResponse.json() as Array<{
    id?: number;
    title?: string;
    read_only?: boolean;
    created_at?: string;
  }>;
  const deployKey = keys[0];
  if (keys.length !== 1 || !deployKey || !Number.isSafeInteger(deployKey.id)) {
    throw new Error(`expected exactly one deploy key, found ${keys.length}`);
  }

  const evidence = {
    phase: "0",
    status: "target_ready",
    host: "api.github.com",
    owner,
    repository,
    repository_private: true,
    deploy_key_count: keys.length,
    deploy_key: {
      id: deployKey.id,
      title: deployKey.title,
      read_only: deployKey.read_only,
      created_at: deployKey.created_at,
    },
    github_pat_in_output: false,
  };
  await mkdir(evidenceDir, { recursive: true });
  await writeFile(path.join(evidenceDir, "github-target.json"), JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((error) => {
  console.error(`target inspection failed: ${redactError(error, [process.env.GITHUB_PAT ?? "", process.env.T3N_API_KEY ?? ""])}`);
  process.exitCode = 1;
});
