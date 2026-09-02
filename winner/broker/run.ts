import { existsSync } from "node:fs";
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { invokeC1, connectC1Principal, redact, requireValue } from "../scripts/t3n.js";
import { CONTRACT_TAIL, CONTRACT_VERSION, contractName } from "../scripts/constants.js";
import { classifyProviderOutcome, parseClaim, processMustRefusePat, type ProviderClassification } from "./logic.js";
import { appConfigFromEnvironment, appJwt, exactKey, listInstallationRepositories, listKeys, deleteKey, mintInstallationToken, repositoryContains, repositoryRead, revokeInstallationToken } from "./github-app.js";

const root = path.resolve(import.meta.dirname, "../..");

function json(raw: unknown): any { return typeof raw === "string" ? JSON.parse(raw) : raw; }
function safeError(error: unknown, secrets: string[]): Record<string, unknown> { return { message: redact(error, secrets), category: error instanceof Error ? error.name : "unknown" }; }
async function waitForFile(file: string): Promise<void> { const deadline = Date.now() + 120_000; while (!existsSync(file)) { if (Date.now() > deadline) throw new Error("common broker barrier timed out"); await new Promise((resolve) => setTimeout(resolve, 10)); } }
function readyPayload(incidentId: string, did: string) { return { incident_id: incidentId, broker_did: did, ready_at_unix_ms: Date.now(), process_id: process.pid }; }

async function finalize(principal: Awaited<ReturnType<typeof connectC1Principal>>, contractId: string, incidentId: string, claimId: string, classification: ProviderClassification) {
  return invokeC1(principal.apiKey, principal.nodeUrl, contractId, "finalize-effect", { incident_id: incidentId, claim_id: claimId, classification });
}

async function main() {
  if (processMustRefusePat(process.env)) throw new Error("C1 broker refuses to run with GITHUB_PAT");
  const incidentId = process.argv[2];
  if (!incidentId || incidentId.startsWith("-")) throw new Error("usage: run.ts <incident_id>");
  const barrier = requireValue("C1_BARRIER_FILE");
  const ready = requireValue("C1_READY_FILE");
  const broker = await connectC1Principal("EFFECT_BROKER_T3N_API_KEY", "EFFECT_BROKER_DID");
  const operatorDid = requireValue("C1_OPERATOR_DID");
  const contractId = contractName(operatorDid);
  const evidence: Record<string, unknown> = { contender: process.env.C1_CONTENDER_ID ?? "broker", broker_did: broker.did, incident_id: incidentId, input: { incident_id: incidentId }, ready: readyPayload(incidentId, broker.did), t3n_contract: { name: contractId, version: CONTRACT_VERSION }, token_minted: false, destructive_call_count: 0, delete_attempted: false, provider: { independent: true } };
  await mkdir(path.dirname(ready), { recursive: true });
  await writeFile(ready, JSON.stringify(evidence.ready));
  await waitForFile(barrier);
  evidence.started_at_unix_ms = Date.now();
  let claimRaw: unknown;
  try { claimRaw = await invokeC1(broker.apiKey, broker.nodeUrl, contractId, "claim-effect", { incident_id: incidentId }); evidence.claim = claimRaw; } catch (error) { evidence.claim_error = safeError(error, [broker.apiKey]); evidence.finished_at_unix_ms = Date.now(); process.stdout.write(JSON.stringify(evidence)); return; }
  const parsed = parseClaim(claimRaw);
  if (!parsed.won) { evidence.claim_outcome = "CLAIM_LOST"; evidence.token_minted = false; evidence.destructive_call_count = 0; evidence.finished_at_unix_ms = Date.now(); process.stdout.write(JSON.stringify(evidence)); return; }
  evidence.claim_outcome = "CLAIM_WON";
  const claim = parsed.claim!;
  evidence.authority_loaded_target = { action: claim.action, github_owner: claim.github_owner, github_repo: claim.github_repo, deploy_key_id: claim.deploy_key_id, claim_id: claim.claim_id, claim_version: claim.claim_version };
  const config = appConfigFromEnvironment(process.env);
  let token: string | null = null;
  let revoked = false;
  let classificationToFinalize: ProviderClassification | undefined;
  try {
    const jwt = await appJwt(config);
    const installation = await (await import("./github-app.js")).validateInstallation(config, jwt);
    evidence.installation_validation = { http_status: installation.status, account: installation.body && typeof installation.body === "object" ? { login: (installation.body as Record<string, unknown>).account && typeof (installation.body as Record<string, unknown>).account === "object" ? ((installation.body as Record<string, unknown>).account as Record<string, unknown>).login : null, repository_selection: (installation.body as Record<string, unknown>).repository_selection ?? null } : null };
    if (installation.status !== 200) throw new Error(`INSTALLATION_MISMATCH: App installation GET HTTP ${installation.status}`);
    const minted = await mintInstallationToken(config, jwt);
    if (!minted.token) throw new Error(`TOKEN_EXCHANGE_FAILED: GitHub returned HTTP ${minted.response.status}`);
    token = minted.token;
    evidence.token_minted = true;
    const repos = await listInstallationRepositories(token);
    const reposBody = repos.body as Record<string, unknown>;
    const repoRows = Array.isArray(reposBody?.repositories) ? reposBody.repositories : [];
    const targetRepo = repoRows.find((repo) => repo && typeof repo === "object" && (repo as Record<string, unknown>).full_name === `${config.owner}/${config.repository}`) as Record<string, unknown> | undefined;
    evidence.token_scope = { requested_repositories: [config.repository], requested_permissions: { administration: "write" }, expires_at: minted.metadata.expires_at ?? null, repository_selection: minted.metadata.repository_selection ?? null, permissions: minted.metadata.permissions ?? null, repository_access_http_status: repos.status, target_repository: targetRepo ? { full_name: targetRepo.full_name, private: targetRepo.private } : null };
    if (repos.status !== 200 || !targetRepo || targetRepo.private !== true) throw new Error("TOKEN_SCOPE_INVALID: installation token does not prove the exact private repository scope");
    const keyId = Number(claim.deploy_key_id);
    let precheckFailed = false;
    try {
      const beforeGet = await exactKey(token, config.owner, config.repository, keyId);
      const beforeList = await listKeys(token, config.owner, config.repository);
      evidence.before = { exact_get_http_status: beforeGet.status, list_http_status: beforeList.status, target_present: beforeGet.status === 200 && repositoryContains(beforeList.body, keyId), read_only: beforeGet.body && typeof beforeGet.body === "object" ? (beforeGet.body as Record<string, unknown>).read_only : null };
      precheckFailed = beforeGet.status !== 200 || beforeList.status !== 200 || (evidence.before as any).target_present !== true || (evidence.before as any).read_only !== true;
    } catch (error) {
      precheckFailed = true;
      evidence.precheck_error = safeError(error, [token]);
    }
    if (precheckFailed || process.env.C1_INJECT_PRECHECK_FAILURE === "1") {
      evidence.precheck_failure = true;
      evidence.precheck_injected_failure = process.env.C1_INJECT_PRECHECK_FAILURE === "1";
      const released = await invokeC1(broker.apiKey, broker.nodeUrl, contractId, "release-not-attempted", { incident_id: incidentId, claim_id: claim.claim_id });
      evidence.release_not_attempted = released;
      evidence.classification = "NOT_ATTEMPTED";
    } else {
      let deleted: { status: number | null; body?: unknown };
      try { const response = await deleteKey(token, config.owner, config.repository, keyId); deleted = { status: response.status, body: response.body }; } catch (error) { deleted = { status: null, body: safeError(error, [token]) }; }
      evidence.delete_attempted = true;
      evidence.destructive_call_count = 1;
      evidence.delete = { http_status: deleted.status, provider_acknowledged: deleted.status === 204 };
      const afterGet = await exactKey(token, config.owner, config.repository, keyId);
      const afterList = await listKeys(token, config.owner, config.repository);
      const containsAfter = repositoryContains(afterList.body, keyId);
      evidence.after = { exact_get_http_status: afterGet.status, list_http_status: afterList.status, target_absent: afterGet.status === 404 && !containsAfter, list_contains_target: containsAfter };
      const classification = classifyProviderOutcome(deleted.status, deleted.status === null, afterGet.status, containsAfter);
      evidence.classification = classification;
      evidence.provider_observation = { delete_contract_action: "broker-issued-one-DELETE", delete_count: 1, after_observation_is_independent_provider_read: true };
      classificationToFinalize = classification;
    }
  } catch (error) {
    evidence.effect_error = safeError(error, [broker.apiKey]);
  } finally {
    if (token) {
      try { const revoke = await revokeInstallationToken(token); revoked = revoke.status === 204; evidence.revoke = { attempted: true, http_status: revoke.status, success: revoked }; } catch (error) { evidence.revoke = { attempted: true, http_status: null, success: false, error: safeError(error, [token]) }; }
      if (revoked) { try { const probe = await repositoryRead(token, config.owner, config.repository); evidence.revoked_token_probe = { same_token: true, http_status: probe.status, refused: probe.status === 401 || probe.status === 403 }; } catch (error) { evidence.revoked_token_probe = { same_token: true, http_status: null, refused: true, transport_error: safeError(error, [token]) }; } }
    }
  }
  if (classificationToFinalize) {
    try { evidence.finalize = await finalize(broker, contractId, incidentId, claim.claim_id!, classificationToFinalize); }
    catch (error) { evidence.finalize_error = safeError(error, [broker.apiKey]); }
  }
  evidence.finished_at_unix_ms = Date.now();
  process.stdout.write(JSON.stringify(evidence));
}

main().catch((error) => { process.stderr.write(`C1 broker failed: ${redact(error, [process.env.EFFECT_BROKER_T3N_API_KEY ?? "", process.env.GITHUB_APP_PRIVATE_KEY ?? ""])}\n`); process.exitCode = 1; });
