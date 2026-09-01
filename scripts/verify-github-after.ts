import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { redactError, required } from "./lib.js";

const root = path.resolve(import.meta.dirname, "..");
const evidenceDir = path.join(root, "evidence");

async function main() {
  const pat = required("GITHUB_PAT");
  const owner = required("GITHUB_OWNER");
  const repository = required("GITHUB_REPO");
  const keyId = Number(required("GITHUB_DEPLOY_KEY_ID"));
  if (owner !== "Ticoworld" || repository !== "t3n-breakglass-sandbox") throw new Error("unexpected target");
  if (!Number.isSafeInteger(keyId) || keyId <= 0) throw new Error("invalid deploy-key ID");

  const headers = {
    Authorization: `Bearer ${pat}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2026-03-10",
    "User-Agent": "breakglass-phase0-verification",
  };
  const base = `https://api.github.com/repos/${owner}/${repository}`;
  const keyResponse = await fetch(`${base}/keys/${keyId}`, { headers, redirect: "error" });
  const listResponse = await fetch(`${base}/keys`, { headers, redirect: "error" });
  if (!listResponse.ok) throw new Error(`deploy-key list verification failed with HTTP ${listResponse.status}`);
  const keys = await listResponse.json() as unknown;
  if (!Array.isArray(keys)) throw new Error("deploy-key list verification was not an array");
  if (keyResponse.status !== 404 || keys.length !== 0) {
    throw new Error(`after-state verification failed: key HTTP ${keyResponse.status}, list count ${keys.length}`);
  }

  const evidence = {
    phase: "0",
    stage: "independent_github_after_verification",
    host: "api.github.com",
    owner,
    repository,
    deploy_key_id: keyId,
    exact_key_get_http_status: keyResponse.status,
    deploy_key_list_http_status: listResponse.status,
    deploy_key_count: keys.length,
    absent: true,
    github_pat_logged: false,
    github_pat_in_invoke_process: false,
  };
  await mkdir(evidenceDir, { recursive: true });
  await writeFile(path.join(evidenceDir, "github-after.json"), JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((error) => {
  console.error(`GitHub after verification failed: ${redactError(error, [process.env.GITHUB_PAT ?? "", process.env.T3N_API_KEY ?? ""])}`);
  process.exitCode = 1;
});
