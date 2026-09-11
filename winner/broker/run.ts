import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { pathToFileURL } from "node:url";
import { invokeC1, connectC1Principal, redact, requireValue } from "../scripts/t3n.js";
import { CONTRACT_VERSION, contractName } from "../scripts/constants.js";
import { claimTargetMatchesConfiguredRepository, classifyProviderOutcome, parseClaimConfirmation, parseClaimProposal, processMustRefusePat, type ProviderClassification } from "./logic.js";
import { appConfigFromEnvironment, appJwt, deleteKey, exactKey, listInstallationRepositories, listKeys, mintEffectInstallationToken, mintReadOnlyInstallationToken, repositoryContains, repositoryListIsWellFormed, repositoryRead, revokeInstallationToken, validateInstallation } from "./github-app.js";
import { writeAtomicJson } from "../scripts/result-file.js";

export interface BrokerRuntimeAdapters {
  connectC1Principal: (...args: string[]) => Promise<any>;
  invokeC1: (...args: any[]) => Promise<unknown>;
  appConfigFromEnvironment: (env: NodeJS.ProcessEnv) => ReturnType<typeof appConfigFromEnvironment>;
  appJwt: (config: ReturnType<typeof appConfigFromEnvironment>) => Promise<string>;
  validateInstallation: (config: ReturnType<typeof appConfigFromEnvironment>, jwt: string) => Promise<any>;
  mintEffectInstallationToken: (config: ReturnType<typeof appConfigFromEnvironment>, jwt: string) => Promise<any>;
  mintReadOnlyInstallationToken: (config: ReturnType<typeof appConfigFromEnvironment>, jwt: string, purpose: "target-preflight" | "verifier") => Promise<any>;
  listInstallationRepositories: (token: string) => Promise<any>;
  exactKey: (token: string, owner: string, repository: string, keyId: number) => Promise<any>;
  listKeys: (token: string, owner: string, repository: string) => Promise<any>;
  deleteKey: (token: string, owner: string, repository: string, keyId: number) => Promise<any>;
  repositoryRead: (token: string, owner: string, repository: string) => Promise<any>;
  revokeInstallationToken: (token: string) => Promise<any>;
}

const REAL_BROKER_ADAPTERS: BrokerRuntimeAdapters = {
  connectC1Principal,
  invokeC1,
  appConfigFromEnvironment,
  appJwt,
  validateInstallation,
  mintEffectInstallationToken,
  mintReadOnlyInstallationToken,
  listInstallationRepositories,
  exactKey,
  listKeys,
  deleteKey,
  repositoryRead,
  revokeInstallationToken,
};

async function brokerAdaptersForEnvironment(environment: NodeJS.ProcessEnv, overrides: Partial<BrokerRuntimeAdapters>): Promise<BrokerRuntimeAdapters> {
  const modulePath = environment.BREAKGLASS_TEST_TRANSPORT_MODULE;
  if (!modulePath) return { ...REAL_BROKER_ADAPTERS, ...overrides };
  if (environment.NODE_ENV !== "test" || !path.isAbsolute(modulePath)) throw new Error("offline broker transport is test-only and must use an absolute module path");
  const loaded = await import(pathToFileURL(modulePath).href) as { brokerRuntimeAdapters?: Partial<BrokerRuntimeAdapters> };
  if (!loaded.brokerRuntimeAdapters || typeof loaded.brokerRuntimeAdapters !== "object") throw new Error("offline broker transport module did not export brokerRuntimeAdapters");
  return { ...REAL_BROKER_ADAPTERS, ...loaded.brokerRuntimeAdapters, ...overrides };
}

function json(raw: unknown): any { return typeof raw === "string" ? JSON.parse(raw) : raw; }
function safeError(error: unknown, secrets: string[]): Record<string, unknown> { return { message: redact(error, secrets), category: error instanceof Error ? error.name : "unknown" }; }
async function waitForFile(file: string): Promise<void> { const deadline = Date.now() + 120_000; while (!existsSync(file)) { if (Date.now() > deadline) throw new Error(`broker barrier timed out: ${path.basename(file)}`); await new Promise((resolve) => setTimeout(resolve, 10)); } }
async function barrierAborted(file: string): Promise<boolean> { try { const parsed = JSON.parse(await readFile(file, "utf8")) as Record<string, unknown>; return parsed.abort === true; } catch { return false; } }
function readyPayload(incidentId: string, did: string, contenderNonce: string, environment: NodeJS.ProcessEnv) { return { incident_id: incidentId, broker_did: did, contender: environment.C1_CONTENDER_ID ?? "broker", contender_nonce: contenderNonce, ready_at_unix_ms: Date.now(), process_id: process.pid }; }

let evidenceForFailure: Record<string, unknown> | undefined;

async function finalize(principal: any, contractId: string, incidentId: string, claimId: string, effectStartId: string, classification: ProviderClassification, adapters: BrokerRuntimeAdapters) {
  return adapters.invokeC1(principal.apiKey, principal.nodeUrl, contractId, "finalize-effect", { incident_id: incidentId, claim_id: claimId, effect_start_id: effectStartId, classification });
}

async function reconcile(principal: any, contractId: string, incidentId: string, claimId: string, effectStartId: string, classification: ProviderClassification, adapters: BrokerRuntimeAdapters) {
  return adapters.invokeC1(principal.apiKey, principal.nodeUrl, contractId, "reconcile-effect", { incident_id: incidentId, claim_id: claimId, effect_start_id: effectStartId, classification });
}

function responseObject(raw: unknown): Record<string, unknown> {
  const response = json(raw);
  if (!response || typeof response !== "object" || Array.isArray(response)) throw new Error("provider or contract response was not an object");
  return response as Record<string, unknown>;
}

async function revokeAndRefuse(token: string, owner: string, repository: string, adapters: BrokerRuntimeAdapters): Promise<{ revoke: Record<string, unknown>; probe: Record<string, unknown>; ok: boolean }> {
  const response = await adapters.revokeInstallationToken(token);
  const revoke = { http_status: response.status, success: response.status === 204 };
  if (response.status !== 204) return { revoke, probe: { http_status: null, refused: false }, ok: false };
  const probe = await adapters.repositoryRead(token, owner, repository);
  const probeEvidence = { http_status: probe.status, refused: probe.status === 401 || probe.status === 403 };
  return { revoke, probe: probeEvidence, ok: response.status === 204 && probeEvidence.refused };
}

async function independentVerifier(config: ReturnType<typeof appConfigFromEnvironment>, evidence: Record<string, unknown>, adapters: BrokerRuntimeAdapters): Promise<boolean> {
  let token: string | null = null;
  let cleanup: { revoke: Record<string, unknown>; probe: Record<string, unknown>; ok: boolean } | undefined;
  try {
    const jwt = await adapters.appJwt(config);
    const minted = await adapters.mintReadOnlyInstallationToken(config, jwt, "verifier");
    token = minted.token;
    evidence.verifier_token = { issued: Boolean(token), ...minted.metadata, purpose: "verifier", distinct_from_effect_token: true, distinct_from_target_preflight_token: true, exchange_http_status: minted.response.status, mutation_count: 0 };
    if (!token) throw new Error(`verifier token exchange failed HTTP ${minted.response.status}`);
    const repositories = await adapters.listInstallationRepositories(token);
    const rows = repositories.body && typeof repositories.body === "object" && !Array.isArray(repositories.body) ? (repositories.body as Record<string, unknown>).repositories : null;
    const scoped = Array.isArray(rows) ? rows.find((row) => row && typeof row === "object" && (row as Record<string, unknown>).full_name === `${config.owner}/${config.repository}`) as Record<string, unknown> | undefined : undefined;
    if (repositories.status !== 200 || !scoped || scoped.private !== true) throw new Error("verifier token did not prove exact private repository scope");
    const exact = await adapters.exactKey(token, config.owner, config.repository, Number(evidence.target_id));
    const listed = await adapters.listKeys(token, config.owner, config.repository);
    const absent = exact.status === 404 && listed.status === 200 && repositoryListIsWellFormed(listed.body) && !repositoryContains(listed.body, Number(evidence.target_id));
    evidence.independent_provider_verification = { repository_scope_http_status: repositories.status, target_repository: { full_name: scoped.full_name, private: scoped.private }, exact_get_http_status: exact.status, list_get_http_status: listed.status, list_body_valid: repositoryListIsWellFormed(listed.body), target_absent: absent, list_contains_target: repositoryContains(listed.body, Number(evidence.target_id)), mutation_count: 0 };
    if (!absent) return false;
    return true;
  } finally {
    if (token) {
      cleanup = await revokeAndRefuse(token, config.owner, config.repository, adapters);
      evidence.verifier_token_cleanup = cleanup;
      if (!cleanup.ok) throw new Error("verifier token cleanup gate failed");
    }
  }
}

export async function runBroker(
  environment: NodeJS.ProcessEnv = process.env,
  argv: string[] = process.argv,
  overrides: Partial<BrokerRuntimeAdapters> = {},
): Promise<void> {
  const adapters = await brokerAdaptersForEnvironment(environment, overrides);
  if (processMustRefusePat(environment)) throw new Error("C1 broker refuses to run with GITHUB_PAT");
  const incidentId = argv[2];
  if (!incidentId || incidentId.startsWith("-")) throw new Error("usage: run.ts <incident_id>");
  const productionMode = environment.C1_RUNTIME_MODE === "production";
  const required = (name: string): string => {
    const value = environment[name];
    if (!value) throw new Error(`${name} is required`);
    return value;
  };
  const barrier = productionMode ? null : required("C1_BARRIER_FILE");
  const proposalsComplete = productionMode ? null : required("C1_PROPOSALS_COMPLETE_FILE");
  const ready = productionMode ? null : required("C1_READY_FILE");
  const resultFile = required("C1_RESULT_FILE");
  const broker = await adapters.connectC1Principal("EFFECT_BROKER_T3N_API_KEY", "EFFECT_BROKER_DID");
  const operatorDid = required("C1_OPERATOR_DID");
  const contractId = contractName(operatorDid);
  const expectedClaimVersion = Number(required("C1_EXPECTED_CLAIM_VERSION"));
  if (!Number.isSafeInteger(expectedClaimVersion) || expectedClaimVersion < 0) throw new Error("C1_EXPECTED_CLAIM_VERSION must be a nonnegative safe integer");
  const contenderNonce = randomBytes(16).toString("hex");
  const evidence: Record<string, unknown> = {
    contender: environment.C1_CONTENDER_ID ?? "broker",
    broker_did: broker.did,
    process_id: process.pid,
    incident_id: incidentId,
    input: { incident_id: incidentId, expected_claim_version: expectedClaimVersion, contender_nonce: contenderNonce },
    ready: readyPayload(incidentId, broker.did, contenderNonce, environment),
    contender_nonce: contenderNonce,
    t3n_contract: { name: contractId, version: CONTRACT_VERSION },
    token_minted: false,
    destructive_call_count: 0,
    delete_attempted: false,
    provider_credential_mint_count: 0,
    provider_calls_after_ownership_loss: 0,
  };
  evidenceForFailure = evidence;
  const persist = async () => {
    evidence.finished_at_unix_ms = Date.now();
    if (productionMode) {
      const terminal = evidence.reconcile ?? evidence.finalize;
      const terminalResponse = terminal === undefined ? {} : responseObject(terminal);
      await writeAtomicJson(resultFile, {
        runtime: "breakglass",
        schema_version: 1,
        incident_id: incidentId,
        broker_did: broker.did,
        claim_outcome: evidence.claim_outcome ?? null,
        claim_id: (evidence.claim_proposal as Record<string, unknown> | undefined)?.claim_id ?? null,
        claim_version: (evidence.claim_proposal as Record<string, unknown> | undefined)?.claim_version ?? null,
        effect_start_confirmed: evidence.effect_start_confirmed === true,
        effect_start_id: evidence.effect_start_id ?? null,
        token_minted: evidence.token_minted === true,
        destructive_call_count: evidence.destructive_call_count ?? 0,
        delete_attempted: evidence.delete_attempted === true,
        classification: evidence.classification ?? null,
        recovery_state: evidence.recovery_state ?? null,
        c1_state: typeof terminalResponse.state === "string" ? terminalResponse.state : null,
        c1_result: typeof terminalResponse.result === "string" ? terminalResponse.result : null,
        effect_error: evidence.effect_error ?? null,
        finished_at_unix_ms: evidence.finished_at_unix_ms,
      });
      return;
    }
    await writeAtomicJson(resultFile, evidence);
    process.stdout.write(JSON.stringify(evidence));
  };
  if (!productionMode && ready && barrier) {
    await mkdir(path.dirname(ready), { recursive: true });
    await writeFile(ready, JSON.stringify(evidence.ready));
    await waitForFile(barrier);
  }
  evidence.started_at_unix_ms = Date.now();
  if (!productionMode && barrier && await barrierAborted(barrier)) { evidence.claim_outcome = "DUPLICATE_NONCE_ABORT"; evidence.duplicate_nonce_abort = true; await persist(); return; }

  let proposal: { claim_id: string; claim_version: number } | undefined;
  const existingClaimId = environment.C1_EXISTING_CLAIM_ID;
  const existingClaimVersion = Number(environment.C1_EXISTING_CLAIM_VERSION ?? "");
  if (productionMode && existingClaimId) {
    if (!Number.isSafeInteger(existingClaimVersion) || existingClaimVersion <= 0) throw new Error("C1_EXISTING_CLAIM_VERSION must be a positive safe integer");
    proposal = { claim_id: existingClaimId, claim_version: existingClaimVersion };
    evidence.claim_outcome = "EXISTING_CLAIM_RECOVERY";
    evidence.claim_proposal = proposal;
  } else try {
    const claimRaw = await adapters.invokeC1(broker.apiKey, broker.nodeUrl, contractId, "claim-effect", { incident_id: incidentId, expected_claim_version: expectedClaimVersion, contender_nonce: contenderNonce });
    evidence.claim = claimRaw;
    const parsed = parseClaimProposal(claimRaw);
    if (!parsed.proposed) {
      const response = responseObject(claimRaw);
      evidence.claim_outcome = response.result === "LOST" ? "CLAIM_LOST" : response.result === "DENIED" ? "CLAIM_DENIED" : "CLAIM_NOT_PROPOSED";
      await persist();
      return;
    }
    proposal = parsed.claim;
    evidence.claim_outcome = "CLAIM_PROPOSED";
    evidence.claim_proposal = { claim_id: proposal!.claim_id, claim_version: proposal!.claim_version };
    await persist();
  } catch (error) { evidence.claim_error = safeError(error, [broker.apiKey]); await persist(); return; }

  if (!productionMode && proposalsComplete) await waitForFile(proposalsComplete);
  if (!proposal) throw new Error("claim proposal identity was not retained");
  let target: { action: string; github_owner: string; github_repo: string; deploy_key_id: number; claim_id: string; claim_version: number };
  try {
    const confirmationRaw = await adapters.invokeC1(broker.apiKey, broker.nodeUrl, contractId, "confirm-claim", { incident_id: incidentId, claim_id: proposal.claim_id });
    evidence.claim_confirmation = confirmationRaw;
    const confirmation = parseClaimConfirmation(confirmationRaw);
    if (!confirmation.confirmed || !confirmation.target) { evidence.ownership_confirmation = "NOT_OWNER"; evidence.claim_outcome = "CLAIM_LOST"; await persist(); return; }
    target = confirmation.target;
    if (target.claim_id !== proposal.claim_id || target.claim_version !== proposal.claim_version) throw new Error("claim confirmation identity differs from proposal");
    evidence.ownership_confirmation = "CONFIRMED";
    evidence.claim_outcome = "CLAIM_WON";
    evidence.authority_loaded_target = { action: target.action, github_owner: target.github_owner, github_repo: target.github_repo, deploy_key_id: target.deploy_key_id, claim_id: target.claim_id, claim_version: target.claim_version };
  } catch (error) { evidence.confirmation_error = safeError(error, [broker.apiKey]); await persist(); return; }

  const config = adapters.appConfigFromEnvironment(environment);
  let effectToken: string | null = null;
  let effectTokenCleaned = false;
  let effectStartId: string | undefined;
  let beginEffectSent = false;
  let deleteMayHaveBeenInitiated = false;
  let classification: ProviderClassification | undefined;
  try {
    if (!claimTargetMatchesConfiguredRepository(target, config.owner, config.repository)) {
      evidence.claim_target_mismatch = true;
      evidence.claim_error = { message: "CLAIM_TARGET_MISMATCH: committed incident target differs from broker fixed repository configuration", category: "ConfigurationError" };
      await persist();
      return;
    }

    const jwt = await adapters.appJwt(config);
    const installation = await adapters.validateInstallation(config, jwt);
    evidence.installation_validation = { http_status: installation.status, provider_request_id: installation.responseHeaders["x-github-request-id"] ?? null };
    if (installation.status !== 200) throw new Error(`INSTALLATION_MISMATCH: GitHub installation GET HTTP ${installation.status}`);
    const startNonce = randomBytes(16).toString("hex");
    evidence.effect_start_input = { incident_id: incidentId, claim_id: target.claim_id, start_nonce: startNonce };
    beginEffectSent = true;
    const beginRaw = await adapters.invokeC1(broker.apiKey, broker.nodeUrl, contractId, "begin-effect", { incident_id: incidentId, claim_id: target.claim_id, start_nonce: startNonce });
    evidence.effect_start = beginRaw;
    const beginResponse = responseObject(beginRaw);
    const beginDetail = beginResponse.detail && typeof beginResponse.detail === "object" && !Array.isArray(beginResponse.detail) ? beginResponse.detail as Record<string, unknown> : {};
    effectStartId = typeof beginDetail.effect_start_id === "string" ? beginDetail.effect_start_id : undefined;
    if (beginResponse.result !== "WON" || beginResponse.function !== "begin-effect" || beginResponse.state !== "EFFECT_STARTED" || beginResponse.effect_attempts !== 1 || !effectStartId) throw new Error("begin-effect did not return a committed EFFECT_STARTED result");
    const confirmationRaw = await adapters.invokeC1(broker.apiKey, broker.nodeUrl, contractId, "confirm-effect-start", { incident_id: incidentId, claim_id: target.claim_id, effect_start_id: effectStartId });
    evidence.effect_start_confirmation = confirmationRaw;
    const confirmation = responseObject(confirmationRaw);
    if (confirmation.result !== "CONFIRMED" || confirmation.function !== "confirm-effect-start") throw new Error("effect-start confirmation did not prove persisted ownership");
    evidence.effect_start_confirmed = true;

    // The destructive installation token is JIT authority. It is minted only
    // after the contract has durably committed and confirmed effect-start.
    const minted = await adapters.mintEffectInstallationToken(config, jwt);
    effectToken = minted.token;
    evidence.token_minted = Boolean(effectToken);
    evidence.provider_credential_mint_count = effectToken ? 1 : 0;
    evidence.effect_token = { issued: Boolean(effectToken), ...minted.metadata, exchange_http_status: minted.response.status, mutation_count: 0, minted_after_confirmed_effect_start: true };
    if (!effectToken) throw new Error(`TOKEN_EXCHANGE_FAILED: GitHub returned HTTP ${minted.response.status}`);
    const repos = await adapters.listInstallationRepositories(effectToken);
    const body = repos.body && typeof repos.body === "object" && !Array.isArray(repos.body) ? repos.body as Record<string, unknown> : {};
    const repoRows = Array.isArray(body.repositories) ? body.repositories : [];
    const scoped = repoRows.find((repo) => repo && typeof repo === "object" && (repo as Record<string, unknown>).full_name === `${config.owner}/${config.repository}`) as Record<string, unknown> | undefined;
    evidence.effect_token_scope = { repository_selection: minted.metadata.repository_selection ?? null, requested_permissions: { administration: "write" }, actual_permissions: minted.metadata.permissions ?? null, expires_at: minted.metadata.expires_at ?? null, repository_access_http_status: repos.status, target_repository: scoped ? { full_name: scoped.full_name, private: scoped.private } : null, minted_after_confirmed_effect_start: true };
    if (repos.status !== 200 || !scoped || scoped.private !== true) throw new Error("TOKEN_SCOPE_INVALID: effect token did not prove the exact private repository scope");

    const keyId = Number(target.deploy_key_id);
    const beforeGet = await adapters.exactKey(effectToken, config.owner, config.repository, keyId);
    const beforeList = await adapters.listKeys(effectToken, config.owner, config.repository);
    const beforeBody = beforeGet.body && typeof beforeGet.body === "object" && !Array.isArray(beforeGet.body) ? beforeGet.body as Record<string, unknown> : {};
    const beforePresent = beforeGet.status === 200 && Number(beforeBody.id) === keyId && beforeBody.title === environment.C1_EXPECTED_TARGET_TITLE && beforeBody.read_only === true && beforeList.status === 200 && repositoryListIsWellFormed(beforeList.body) && repositoryContains(beforeList.body, keyId);
    evidence.before = { exact_get_http_status: beforeGet.status, list_http_status: beforeList.status, target_id: keyId, title: beforeBody.title ?? null, read_only: beforeBody.read_only ?? null, target_present: beforePresent, list_contains_target: repositoryContains(beforeList.body, keyId), list_body_valid: repositoryListIsWellFormed(beforeList.body), read_after_confirmed_effect_start: true };
    if (!beforePresent) throw new Error("TARGET_PRECHECK_FAILED: target was not present/read-only with the frozen title");

    const readyForDelete = environment.C1_EFFECT_START_READY_FILE;
    const releaseDelete = environment.C1_PRE_DELETE_RELEASE_FILE;
    if (readyForDelete && releaseDelete) {
      await writeAtomicJson(readyForDelete, { incident_id: incidentId, claim_id: target.claim_id, effect_start_id: effectStartId, state: "EFFECT_STARTED", effect_attempts: 1, confirmed: true, provider_delete_count: 0 });
      await waitForFile(releaseDelete);
      if (await barrierAborted(releaseDelete)) throw new Error("pre-delete authority gate aborted");
    }

    deleteMayHaveBeenInitiated = true;
    let deleted: { status: number | null; body?: unknown; request_id?: string | null };
    try { const response = await adapters.deleteKey(effectToken, config.owner, config.repository, keyId); deleted = { status: response.status, body: response.body, request_id: response.responseHeaders["x-github-request-id"] ?? null }; }
    catch (error) { deleted = { status: null, body: safeError(error, [effectToken]), request_id: null }; }
    evidence.delete_attempted = true;
    evidence.destructive_call_count = 1;
    evidence.delete = { attempt_number: 1, method: "DELETE", owner: config.owner, repository: config.repository, target_id: keyId, http_status: deleted.status, provider_request_id: deleted.request_id ?? null, provider_acknowledged: deleted.status === 204 };
    let afterGet: Awaited<ReturnType<typeof exactKey>> | undefined;
    let afterList: Awaited<ReturnType<typeof listKeys>> | undefined;
    try { afterGet = await adapters.exactKey(effectToken, config.owner, config.repository, keyId); afterList = await adapters.listKeys(effectToken, config.owner, config.repository); }
    catch (error) { evidence.after_error = safeError(error, [effectToken]); }
    const containsAfter = afterList ? repositoryContains(afterList.body, keyId) : false;
    const listBodyValid = afterList ? repositoryListIsWellFormed(afterList.body) : false;
    evidence.after = { exact_get_http_status: afterGet?.status ?? null, list_http_status: afterList?.status ?? null, target_absent: afterGet?.status === 404 && afterList?.status === 200 && listBodyValid && !containsAfter, list_contains_target: containsAfter, list_body_valid: listBodyValid };
    classification = classifyProviderOutcome(deleted.status, deleted.status === null, afterGet?.status ?? null, containsAfter, afterList?.status ?? null, listBodyValid);
    evidence.classification = classification;
    evidence.provider_observation = { delete_contract_action: "broker-issued-one-DELETE", delete_count: 1, transport_ambiguity_precedence: deleted.status === null, retry_allowed: false };

    const effectCleanup = await revokeAndRefuse(effectToken, config.owner, config.repository, adapters);
    effectTokenCleaned = true;
    evidence.effect_token_cleanup = effectCleanup;
    if (!effectCleanup.ok) throw new Error("effect token cleanup gate failed");

    evidence.target_id = keyId;
    if (classification === "ATTEMPTED_OUTCOME_UNKNOWN") {
      evidence.finalize_unknown_request = { incident_id: incidentId, claim_id: target.claim_id, effect_start_id: effectStartId, classification: "ATTEMPTED_OUTCOME_UNKNOWN" };
      evidence.finalize_unknown = await finalize(broker, contractId, incidentId, target.claim_id, effectStartId, "ATTEMPTED_OUTCOME_UNKNOWN", adapters);
      evidence.recovery_state = "RECONCILE_REQUIRED";
      const absent = await independentVerifier(config, evidence, adapters);
      if (!absent) throw new Error("independent verifier did not establish target absence");
      evidence.reconcile_request = { incident_id: incidentId, claim_id: target.claim_id, effect_start_id: effectStartId, classification: "VERIFIED_ABSENT" };
      evidence.reconcile = await reconcile(broker, contractId, incidentId, target.claim_id, effectStartId, "VERIFIED_ABSENT", adapters);
      evidence.classification = "VERIFIED_ABSENT";
    } else {
      if (classification !== "VERIFIED_ABSENT") throw new Error(`same-session provider verification did not establish VERIFIED_ABSENT (${classification})`);
      const absent = await independentVerifier(config, evidence, adapters);
      if (!absent) throw new Error("independent verifier did not establish target absence");
      evidence.finalize_request = { incident_id: incidentId, claim_id: target.claim_id, effect_start_id: effectStartId, classification: "VERIFIED_ABSENT" };
      evidence.finalize = await finalize(broker, contractId, incidentId, target.claim_id, effectStartId, "VERIFIED_ABSENT", adapters);
    }
    evidence.terminal_success_gate = { effect_token_revoked: true, same_effect_token_refused: true, verifier_absent: true, verifier_token_revoked: (evidence.verifier_token_cleanup as Record<string, unknown> | undefined)?.ok === true };
    if ((evidence.terminal_success_gate as Record<string, unknown>).verifier_token_revoked !== true) throw new Error("verifier credential cleanup gate failed");
  } catch (error) {
    evidence.effect_error = safeError(error, [broker.apiKey, effectToken ?? ""]);
    if (!beginEffectSent && !deleteMayHaveBeenInitiated) evidence.classification ??= "NOT_ATTEMPTED";
  } finally {
    if (effectToken && !effectTokenCleaned) {
      try { evidence.effect_token_cleanup = await revokeAndRefuse(effectToken, config.owner, config.repository, adapters); }
      catch (error) { evidence.effect_token_cleanup = { ok: false, error: safeError(error, [effectToken]) }; }
    }
  }
  evidence.effect_started = Boolean(effectStartId);
  evidence.effect_start_id = effectStartId ?? null;
  await persist();
}

const isDirectExecution = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));
if (isDirectExecution) runBroker().catch(async (error) => {
  const resultFile = process.env.C1_RESULT_FILE;
  if (resultFile) {
    try { await writeAtomicJson(resultFile, { ...(evidenceForFailure ?? { contender: process.env.C1_CONTENDER_ID ?? "broker", incident_id: process.argv[2] ?? null, token_minted: false, destructive_call_count: 0, delete_attempted: false }), claim_outcome: evidenceForFailure?.claim_outcome ?? "CHILD_PROCESS_FAILURE", error: safeError(error, [process.env.EFFECT_BROKER_T3N_API_KEY ?? ""]), finished_at_unix_ms: Date.now() }); } catch { /* preserve original error */ }
  }
  process.stderr.write(`C1 broker failed: ${redact(error, [process.env.EFFECT_BROKER_T3N_API_KEY ?? "", process.env.GITHUB_APP_PRIVATE_KEY ?? ""])}\n`); process.exitCode = 1;
});
