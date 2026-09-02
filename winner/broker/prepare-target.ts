import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { processMustRefusePat } from "./logic.js";
import { appConfigFromEnvironment, appJwt, createDisposableDeployKey, listInstallationRepositories, mintInstallationToken, repositoryRead, revokeInstallationToken, validateInstallation } from "./github-app.js";
import { redact } from "../scripts/t3n.js";

const root = path.resolve(import.meta.dirname, "../..");
const evidencePath = path.join(root, "winner", "evidence", "target-setup.json");

async function main() {
  if (processMustRefusePat(process.env)) throw new Error("C1 target setup refuses a GitHub PAT");
  const config = appConfigFromEnvironment(process.env);
  let token: string | null = null;
  let cleanup: (() => Promise<void>) | undefined;
  try {
    const jwt = await appJwt(config);
    const installation = await validateInstallation(config, jwt);
    if (installation.status !== 200) throw new Error(`INSTALLATION_MISMATCH: App installation GET HTTP ${installation.status}`);
    const minted = await mintInstallationToken(config, jwt);
    token = minted.token;
    if (!token) throw new Error(`TOKEN_EXCHANGE_FAILED: GitHub access-token exchange HTTP ${minted.response.status}`);
    const repositories = await listInstallationRepositories(token);
    const rows = repositories.body && typeof repositories.body === "object" ? (repositories.body as Record<string, unknown>).repositories : null;
    const targetRepo = Array.isArray(rows) ? rows.find((row) => row && typeof row === "object" && (row as Record<string, unknown>).full_name === `${config.owner}/${config.repository}`) as Record<string, unknown> | undefined : undefined;
    if (repositories.status !== 200 || !targetRepo || targetRepo.private !== true) throw new Error("TOKEN_SCOPE_INVALID: exact private repository was not in installation-token scope");
    const target = await createDisposableDeployKey(token, config);
    cleanup = target.cleanup;
    const before = await repositoryRead(token, config.owner, config.repository);
    const evidence = {
      experiment: "C1 disposable GitHub deploy-key setup via broker",
      status: "READY",
      github_api_version: "2022-11-28",
      app: { app_id: config.appId, installation_id: config.installationId },
      repository: { owner: config.owner, name: config.repository, private: true },
      target: { id: target.id, title: target.title, read_only: target.readOnly, repository: target.repository },
      setup_token: { minted: true, expires_at: minted.metadata.expires_at ?? null, repository_selection: minted.metadata.repository_selection ?? null, permissions: minted.metadata.permissions ?? null, repository_access_http_status: repositories.status, repository_read_http_status: before.status, credential_material_in_evidence: false },
      provider_mutations: { deploy_key_create_count: 1, deploy_key_delete_count: 0 },
      credential_safety: { jwt_in_evidence: false, installation_token_in_evidence: false, authorization_header_in_evidence: false, private_key_in_evidence: false, ssh_private_key_in_evidence: false, pat_used: false },
    };
    await mkdir(path.dirname(evidencePath), { recursive: true });
    await writeFile(evidencePath, JSON.stringify(evidence, null, 2) + "\n");
    console.log(JSON.stringify(evidence, null, 2));
  } finally {
    if (token) {
      const revoke = await revokeInstallationToken(token);
      if (revoke.status !== 204) throw new Error(`TOKEN_REVOKE_FAILED: target setup token revoke HTTP ${revoke.status}`);
    }
    if (cleanup) await cleanup();
  }
}

main().catch((error) => { console.error(`C1 target setup failed: ${redact(error, [process.env.GITHUB_APP_PRIVATE_KEY ?? ""])}`); process.exitCode = 1; });
