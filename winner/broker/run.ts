import { existsSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import path from "node:path";
import { invokeC1, connectC1Principal, redact, requireValue } from "../scripts/t3n.js";
import { CONTRACT_TAIL, CONTRACT_VERSION, contractName } from "../scripts/constants.js";
import { claimTargetMatchesConfiguredRepository, classifyProviderOutcome, parseClaimConfirmation, parseClaimProposal, processMustRefusePat, type ProviderClassification } from "./logic.js";
import { appConfigFromEnvironment, appJwt, exactKey, listInstallationRepositories, listKeys, deleteKey, mintInstallationToken, repositoryContains, repositoryListIsWellFormed, repositoryRead, revokeInstallationToken, validateInstallation } from "./github-app.js";
import { writeAtomicJson } from "../scripts/result-file.js";

function json(raw: unknown): any { return typeof raw === "string" ? JSON.parse(raw) : raw; }
function safeError(error: unknown, secrets: string[]): Record<string, unknown> { return { message: redact(error, secrets), category: error instanceof Error ? error.name : "unknown" }; }
async function waitForFile(file: string): Promise<void> { const deadline = Date.now() + 120_000; while (!existsSync(file)) { if (Date.now() > deadline) throw new Error("common broker barrier timed out"); await new Promise((resolve) => setTimeout(resolve, 10)); } }
function readyPayload(incidentId: string, did: string, contenderNonce: string) { return { incident_id: incidentId, broker_did: did, contender_nonce: contenderNonce, ready_at_unix_ms: Date.now(), process_id: process.pid }; }

let evidenceForFailure: Record<string, unknown> | undefined;

async function finalize(principal: Awaited<ReturnType<typeof connectC1Principal>>, contractId: string, incidentId: string, claimId: string, effectStartId: string, classification: ProviderClassification) {
  return invokeC1(principal.apiKey, principal.nodeUrl, contractId, "finalize-effect", { incident_id: incidentId, claim_id: claimId, effect_start_id: effectStartId, classification });
}

async function main() {
  if (processMustRefusePat(process.env)) throw new Error("C1 broker refuses to run with GITHUB_PAT");
  const incidentId = process.argv[2];
  if (!incidentId || incidentId.startsWith("-")) throw new Error("usage: run.ts <incident_id>");
  const barrier = requireValue("C1_BARRIER_FILE");
  const proposalsComplete = requireValue("C1_PROPOSALS_COMPLETE_FILE");
  const ready = requireValue("C1_READY_FILE");
  const resultFile = requireValue("C1_RESULT_FILE");
  const broker = await connectC1Principal("EFFECT_BROKER_T3N_API_KEY", "EFFECT_BROKER_DID");
  const operatorDid = requireValue("C1_OPERATOR_DID");
  const contractId = contractName(operatorDid);
  const expectedClaimVersion = Number(requireValue("C1_EXPECTED_CLAIM_VERSION"));
  if (!Number.isSafeInteger(expectedClaimVersion) || expectedClaimVersion < 0) throw new Error("C1_EXPECTED_CLAIM_VERSION must be a nonnegative safe integer");
  const contenderNonce = randomBytes(16).toString("hex");
  const evidence: Record<string, unknown> = {
    contender: process.env.C1_CONTENDER_ID ?? "broker",
    broker_did: broker.did,
    incident_id: incidentId,
    input: { incident_id: incidentId, expected_claim_version: expectedClaimVersion, contender_nonce: contenderNonce },
    ready: readyPayload(incidentId, broker.did, contenderNonce),
    contender_nonce: contenderNonce,
    t3n_contract: { name: contractId, version: CONTRACT_VERSION },
    token_minted: false,
    destructive_call_count: 0,
    delete_attempted: false,
    provider: { independent: true },
  };
  evidenceForFailure = evidence;
  const persist = async () => { evidence.finished_at_unix_ms = Date.now(); await writeAtomicJson(resultFile, evidence); process.stdout.write(JSON.stringify(evidence)); };
  await mkdir(path.dirname(ready), { recursive: true });
  await writeFile(ready, JSON.stringify(evidence.ready));
  await waitForFile(barrier);
  evidence.started_at_unix_ms = Date.now();

  let proposal: { claim_id: string; claim_version: number } | undefined;
  try {
    const claimRaw = await invokeC1(broker.apiKey, broker.nodeUrl, contractId, "claim-effect", { incident_id: incidentId, expected_claim_version: expectedClaimVersion, contender_nonce: contenderNonce });
    evidence.claim = claimRaw;
    const parsed = parseClaimProposal(claimRaw);
    if (!parsed.proposed) {
      const response = json(claimRaw) as Record<string, unknown>;
      evidence.claim_outcome = response.result === "LOST" ? "CLAIM_LOST" : "CLAIM_NOT_PROPOSED";
      await persist();
      return;
    }
    proposal = parsed.claim;
    evidence.claim_outcome = "CLAIM_PROPOSED";
    evidence.claim_proposal = { claim_id: proposal.claim_id, claim_version: proposal.claim_version };
    // This document is intentionally written before the parent releases the
    // proposal-complete barrier. It contains no target or provider authority.
    await persist();
  } catch (error) {
    evidence.claim_error = safeError(error, [broker.apiKey]);
    await persist();
    return;
  }

  await waitForFile(proposalsComplete);
  if (!proposal) throw new Error("claim proposal identity was not retained");

  let target: { action: string; github_owner: string; github_repo: string; deploy_key_id: number; claim_id: string; claim_version: number };
  try {
    const confirmationRaw = await invokeC1(broker.apiKey, broker.nodeUrl, contractId, "confirm-claim", { incident_id: incidentId, claim_id: proposal.claim_id });
    evidence.claim_confirmation = confirmationRaw;
    const confirmation = parseClaimConfirmation(confirmationRaw);
    if (!confirmation.confirmed || !confirmation.target) {
      evidence.ownership_confirmation = "NOT_OWNER";
      evidence.claim_outcome = "CLAIM_LOST";
      evidence.token_minted = false;
      evidence.destructive_call_count = 0;
      await persist();
      return;
    }
    target = confirmation.target;
    if (target.claim_id !== proposal.claim_id || target.claim_version !== proposal.claim_version) throw new Error("claim confirmation identity differs from proposal");
    evidence.ownership_confirmation = "CONFIRMED";
    evidence.claim_outcome = "CLAIM_WON";
    evidence.authority_loaded_target = { action: target.action, github_owner: target.github_owner, github_repo: target.github_repo, deploy_key_id: target.deploy_key_id, claim_id: target.claim_id, claim_version: target.claim_version };
  } catch (error) {
    evidence.confirmation_error = safeError(error, [broker.apiKey]);
    await persist();
    return;
  }

  const config = appConfigFromEnvironment(process.env);
  if (!claimTargetMatchesConfiguredRepository(target, config.owner, config.repository)) {
    throw new Error("CLAIM_TARGET_MISMATCH: committed incident target differs from broker fixed repository configuration");
  }
  let token: string | null = null;
  let revoked = false;
  let classificationToFinalize: ProviderClassification | undefined;
  let deleteMayHaveBeenInitiated = false;
  let beginEffectSent = false;
  let effectStarted = false;
  let effectStartId: string | undefined;
  let releaseAttempted = false;
  const releaseClaim = async () => {
    if (releaseAttempted || beginEffectSent || deleteMayHaveBeenInitiated) return;
    releaseAttempted = true;
    try { evidence.release_not_attempted = await invokeC1(broker.apiKey, broker.nodeUrl, contractId, "release-not-attempted", { incident_id: incidentId, claim_id: target.claim_id }); }
    catch (error) { evidence.release_error = safeError(error, [broker.apiKey]); throw error; }
  };

  try {
    const jwt = await appJwt(config);
    const installation = await validateInstallation(config, jwt);
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
    const keyId = Number(target.deploy_key_id);
    let precheckFailed = false;
    try {
      const beforeGet = await exactKey(token, config.owner, config.repository, keyId);
      const beforeList = await listKeys(token, config.owner, config.repository);
      evidence.before = { exact_get_http_status: beforeGet.status, list_http_status: beforeList.status, target_present: beforeGet.status === 200 && repositoryContains(beforeList.body, keyId), read_only: beforeGet.body && typeof beforeGet.body === "object" ? (beforeGet.body as Record<string, unknown>).read_only : null };
      precheckFailed = beforeGet.status !== 200 || beforeList.status !== 200 || (evidence.before as any).target_present !== true || (evidence.before as any).read_only !== true;
    } catch (error) { precheckFailed = true; evidence.precheck_error = safeError(error, [token]); }
    if (precheckFailed || process.env.C1_INJECT_PRECHECK_FAILURE === "1") {
      evidence.precheck_failure = true;
      evidence.precheck_injected_failure = process.env.C1_INJECT_PRECHECK_FAILURE === "1";
      await releaseClaim();
      evidence.classification = "NOT_ATTEMPTED";
    } else {
      const startNonce = randomBytes(16).toString("hex");
      evidence.effect_start_input = { incident_id: incidentId, claim_id: target.claim_id, start_nonce: startNonce };
      beginEffectSent = true;
      const beginRaw = await invokeC1(broker.apiKey, broker.nodeUrl, contractId, "begin-effect", { incident_id: incidentId, claim_id: target.claim_id, start_nonce: startNonce });
      const beginResponse = json(beginRaw) as Record<string, unknown>;
      evidence.effect_start = beginRaw;
      const beginDetail = beginResponse.detail && typeof beginResponse.detail === "object" && !Array.isArray(beginResponse.detail) ? beginResponse.detail as Record<string, unknown> : {};
      effectStartId = typeof beginDetail.effect_start_id === "string" ? beginDetail.effect_start_id : undefined;
      if (beginResponse.result !== "WON" || beginResponse.function !== "begin-effect" || beginResponse.state !== "EFFECT_STARTED" || beginResponse.effect_attempts !== 1 || !effectStartId) throw new Error("begin-effect did not return a committed EFFECT_STARTED result");
      const startConfirmationRaw = await invokeC1(broker.apiKey, broker.nodeUrl, contractId, "confirm-effect-start", { incident_id: incidentId, claim_id: target.claim_id, effect_start_id: effectStartId });
      evidence.effect_start_confirmation = startConfirmationRaw;
      const startConfirmation = json(startConfirmationRaw) as Record<string, unknown>;
      if (startConfirmation.result !== "CONFIRMED" || startConfirmation.function !== "confirm-effect-start") throw new Error("effect-start confirmation did not prove persisted ownership");
      effectStarted = true;
      let deleted: { status: number | null; body?: unknown };
      deleteMayHaveBeenInitiated = true;
      try { const response = await deleteKey(token, config.owner, config.repository, keyId); deleted = { status: response.status, body: response.body }; }
      catch (error) { deleted = { status: null, body: safeError(error, [token]) }; }
      evidence.delete_attempted = true;
      evidence.destructive_call_count = 1;
      evidence.delete = { http_status: deleted.status, provider_acknowledged: deleted.status === 204 };
      const afterGet = await exactKey(token, config.owner, config.repository, keyId);
      const afterList = await listKeys(token, config.owner, config.repository);
      const containsAfter = repositoryContains(afterList.body, keyId);
      const listBodyValid = repositoryListIsWellFormed(afterList.body);
      evidence.after = { exact_get_http_status: afterGet.status, list_http_status: afterList.status, target_absent: afterGet.status === 404 && afterList.status === 200 && listBodyValid && !containsAfter, list_contains_target: containsAfter, list_body_valid: listBodyValid };
      const classification = classifyProviderOutcome(deleted.status, deleted.status === null, afterGet.status, containsAfter, afterList.status, listBodyValid);
      evidence.classification = classification;
      evidence.provider_observation = { delete_contract_action: "broker-issued-one-DELETE", delete_count: 1, after_observation_is_independent_provider_read: true };
      classificationToFinalize = classification;
    }
  } catch (error) {
    evidence.effect_error = safeError(error, [broker.apiKey]);
    if (!beginEffectSent && !deleteMayHaveBeenInitiated && !releaseAttempted) {
      try { await releaseClaim(); evidence.classification = "NOT_ATTEMPTED"; } catch { /* preserve bounded recovery state */ }
    }
  } finally {
    if (token) {
      try { const revoke = await revokeInstallationToken(token); revoked = revoke.status === 204; evidence.revoke = { attempted: true, http_status: revoke.status, success: revoked }; }
      catch (error) { evidence.revoke = { attempted: true, http_status: null, success: false, error: safeError(error, [token]) }; }
      if (revoked) {
        try { const probe = await repositoryRead(token, config.owner, config.repository); evidence.revoked_token_probe = { same_token: true, http_status: probe.status, refused: probe.status === 401 || probe.status === 403 }; }
        catch (error) { evidence.revoked_token_probe = { same_token: true, http_status: null, refused: false, transport_error: safeError(error, [token]) }; }
      }
    }
  }
  if (classificationToFinalize && effectStartId) {
    try { evidence.finalize = await finalize(broker, contractId, incidentId, target.claim_id, effectStartId, classificationToFinalize); }
    catch (error) { evidence.finalize_error = safeError(error, [broker.apiKey]); }
  }
  evidence.effect_started = effectStarted;
  evidence.effect_start_id = effectStartId ?? null;
  await persist();
}

main().catch(async (error) => {
  const resultFile = process.env.C1_RESULT_FILE;
  if (resultFile) {
    try { await writeAtomicJson(resultFile, { ...(evidenceForFailure ?? { contender: process.env.C1_CONTENDER_ID ?? "broker", incident_id: process.argv[2] ?? null, token_minted: false, destructive_call_count: 0, delete_attempted: false }), claim_outcome: evidenceForFailure?.claim_outcome ?? "CHILD_PROCESS_FAILURE", error: safeError(error, [process.env.EFFECT_BROKER_T3N_API_KEY ?? "", process.env.GITHUB_APP_PRIVATE_KEY ?? ""]), finished_at_unix_ms: Date.now() }); } catch { /* preserve the original failure on stderr */ }
  }
  process.stderr.write(`C1 broker failed: ${redact(error, [process.env.EFFECT_BROKER_T3N_API_KEY ?? "", process.env.GITHUB_APP_PRIVATE_KEY ?? ""])}\n`); process.exitCode = 1;
});
