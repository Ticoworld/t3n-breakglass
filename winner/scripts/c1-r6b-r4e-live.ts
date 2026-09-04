import { randomBytes } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { connectTenant } from "../../scripts/lib.js";
import { appConfigFromEnvironment, appJwt, deleteKey, exactKey, listInstallationRepositories, listKeys, mintInstallationToken, repositoryContains, repositoryListIsWellFormed, validateInstallation } from "../broker/github-app.js";
import { invokeC1, invokeC1OperatorSession, redact } from "./t3n.js";
import { CONTRACT_VERSION, RESERVATION_FUNCTION, contractName } from "./constants.js";

const root = path.resolve(import.meta.dirname, "../..");
const OPERATOR_DID = "did:t3n:adb9365ee986cc6d0cb4006580782fe6fc7a431f";
const REMEDIATION_DID = "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019";
const BROKER_DID = "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57";
const CONTRACT_ID = contractName(OPERATOR_DID);
const CONTRACT_NUMERIC_ID = 878;
const TARGET_ID = 162181065;
const TARGET_OWNER = "Ticoworld";
const TARGET_REPOSITORY = "t3n-breakglass-sandbox";
const EVIDENCE_PATH = path.join(root, "winner", "evidence", "C1-R6B-R4E-LIVE-CONTROLLED-PROVIDER-EFFECT.json");

type JsonObject = Record<string, any>;

function parseObject(raw: unknown): JsonObject {
  const value = typeof raw === "string" ? JSON.parse(raw) : raw;
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("response was not an object");
  return value as JsonObject;
}

function envFileValue(contents: string, name: string): string {
  const line = contents.split(/\r?\n/).find((entry) => entry.startsWith(`${name}=`));
  if (!line) throw new Error(`${name} missing from environment file`);
  return line.slice(name.length + 1).trim().replace(/^['"]|['"]$/g, "");
}

async function envValue(file: string, name: string): Promise<string> {
  return envFileValue(await readFile(path.join(root, file), "utf8"), name);
}

function assertResponse(response: JsonObject, functionName: string, result?: string): void {
  if (response.function !== functionName) throw new Error(`${functionName} returned an unexpected function label`);
  if (result !== undefined && response.result !== result) throw new Error(`${functionName} expected ${result}, got ${String(response.result)}`);
}

function safeProviderResponse(response: { status: number; body: unknown; responseHeaders: Record<string, string> }): JsonObject {
  const body = response.body && typeof response.body === "object" && !Array.isArray(response.body) ? response.body as JsonObject : null;
  return {
    http_status: response.status,
    response_headers: response.responseHeaders,
    body_metadata: body ? { id: body.id ?? null, title: body.title ?? null, read_only: body.read_only ?? null, private: body.private ?? null, message: body.message ?? null } : null,
  };
}

function safeActivity(value: unknown): unknown {
  const rows = Array.isArray(value) ? value : value && typeof value === "object" && Array.isArray((value as JsonObject).entries) ? (value as JsonObject).entries : [];
  return rows.map((entry: unknown) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return null;
    const row = entry as JsonObject;
    const output: JsonObject = {};
    for (const key of ["seq_no", "sequence", "hash", "timestamp_ms", "timestamp", "actor", "caller", "on_behalf_of", "org", "contract", "function", "function_name", "outcome", "result"]) if (row[key] !== undefined) output[key] = row[key];
    return output;
  });
}

async function main(): Promise<void> {
  if (process.env.GITHUB_PAT) throw new Error("R4E refuses a GitHub PAT");
  const remediationKey = await envValue(".env.replacement-agent", "REPLACEMENT_AGENT_T3N_API_KEY");
  const brokerKey = await envValue(".env.effect-broker", "EFFECT_BROKER_T3N_API_KEY");
  const remediationDid = await envValue(".env.replacement-agent", "REPLACEMENT_AGENT_DID");
  const brokerDid = await envValue(".env.effect-broker", "EFFECT_BROKER_DID");
  if (remediationDid !== REMEDIATION_DID || brokerDid !== BROKER_DID) throw new Error("effect principal identity mismatch");

  const evidence: JsonObject = {
    phase: "C1-R6B-R4E registered live controlled provider effect",
    status: "IN_PROGRESS",
    evidence_tier: "LIVE_T3N_AND_GITHUB_TESTNET",
    contract: { canonical_name: CONTRACT_ID, numeric_id: CONTRACT_NUMERIC_ID, version: CONTRACT_VERSION },
    target: { owner: TARGET_OWNER, repository: TARGET_REPOSITORY, deploy_key_id: TARGET_ID, resource_class: "private read-only disposable deploy key", creation_source: "pre-existing target-setup.json; no target was created in R4E" },
    provider_operation_counts: { installation_token_mints: 0, target_delete: 0, other_resource_mutations: 0 },
    forbidden_operations: { begin_effect_before_gate: 0, provider_delete_before_confirmed_start: 0, provider_mutations_other_than_target_delete: 0, finalize_before_verified_absent: 0, reconcile_effect: 0 },
    credentials_in_evidence: false,
  };
  let token: string | null = null;
  let incidentId: string | null = null;
  try {
    const targetSetup = JSON.parse(await readFile(path.join(root, "winner", "evidence", "target-setup.json"), "utf8")) as JsonObject;
    const recorded = targetSetup.target as JsonObject;
    if (Number(recorded?.id) !== TARGET_ID || recorded?.read_only !== true || recorded?.repository !== `${TARGET_OWNER}/${TARGET_REPOSITORY}` || typeof recorded?.title !== "string" || !recorded.title.startsWith("breakglass-c1-")) throw new Error("recorded target is not the controlled disposable read-only deploy key");
    evidence.target.recorded_title = recorded.title;
    evidence.target.setup_evidence = "winner/evidence/target-setup.json";

    const appEnv: NodeJS.ProcessEnv = {};
    const appFile = await readFile(path.join(root, ".env.c0r-github-app"), "utf8");
    for (const name of ["GITHUB_APP_ID", "GITHUB_APP_INSTALLATION_ID", "GITHUB_APP_PRIVATE_KEY_PATH", "GITHUB_OWNER", "GITHUB_REPO"]) appEnv[name] = envFileValue(appFile, name);
    const config = appConfigFromEnvironment(appEnv);
    const jwt = await appJwt(config);
    const installation = await validateInstallation(config, jwt);
    evidence.provider_preflight = { installation: safeProviderResponse(installation) };
    if (installation.status !== 200) throw new Error(`installation validation failed HTTP ${installation.status}`);
    const minted = await mintInstallationToken(config, jwt);
    evidence.provider_preflight.token_exchange = { http_status: minted.response.status, metadata: minted.metadata };
    evidence.provider_operation_counts.installation_token_mints = 1;
    if (!minted.token) throw new Error(`installation token mint failed HTTP ${minted.response.status}`);
    token = minted.token;
    const repositories = await listInstallationRepositories(token);
    const repositoryRows = repositories.body && typeof repositories.body === "object" && !Array.isArray(repositories.body) && Array.isArray((repositories.body as JsonObject).repositories) ? (repositories.body as JsonObject).repositories : [];
    const scopedTargetRepository = repositoryRows.find((row: unknown) => row && typeof row === "object" && !Array.isArray(row) && (row as JsonObject).full_name === `${TARGET_OWNER}/${TARGET_REPOSITORY}`) as JsonObject | undefined;
    evidence.provider_preflight.repository_scope = { http_status: repositories.status, target_repository: scopedTargetRepository ? { full_name: scopedTargetRepository.full_name, private: scopedTargetRepository.private } : null, metadata: minted.metadata };
    if (repositories.status !== 200 || !scopedTargetRepository || scopedTargetRepository.private !== true) throw new Error(`installation token does not prove exact private repository scope`);

    const beforeExact = await exactKey(token, TARGET_OWNER, TARGET_REPOSITORY, TARGET_ID);
    const beforeList = await listKeys(token, TARGET_OWNER, TARGET_REPOSITORY);
    const beforeBody = beforeExact.body && typeof beforeExact.body === "object" && !Array.isArray(beforeExact.body) ? beforeExact.body as JsonObject : {};
    const beforePresent = beforeExact.status === 200 && beforeBody.id === TARGET_ID && beforeBody.title === recorded.title && beforeBody.read_only === true && beforeList.status === 200 && repositoryContains(beforeList.body, TARGET_ID);
    evidence.provider_preflight.target_before = { exact_get: safeProviderResponse(beforeExact), list_get: safeProviderResponse(beforeList), target_present: beforePresent, list_body_valid: repositoryListIsWellFormed(beforeList.body) };
    if (!beforePresent) throw new Error("disposable target does not exist in the exact controlled repository");

    const { t3n, tenant, tenantDid, nodeUrl } = await connectTenant();
    if (tenantDid !== OPERATOR_DID) throw new Error("operator DID mismatch");
    const listed = (await tenant.contracts.listDetailed()).contracts?.find((item: any) => item.name === CONTRACT_ID && item.version === CONTRACT_VERSION);
    if (!listed || listed.status !== "active") throw new Error("registered 2.0.4 contract is not active");
    evidence.contract.inventory = listed;

    incidentId = `C1-R6B-R4E-${Date.now()}-${randomBytes(8).toString("hex")}`;
    evidence.incident_id = incidentId;
    const create = parseObject(await invokeC1OperatorSession(t3n, CONTRACT_ID, "create-incident", { incident_id: incidentId, remediation_agent_did: REMEDIATION_DID, effect_broker_did: BROKER_DID, deploy_key_id: TARGET_ID, ttl_secs: 900 }));
    assertResponse(create, "create-incident", "WON");
    if (create.detail?.deploy_key_id !== TARGET_ID || create.detail?.github_owner !== TARGET_OWNER || create.detail?.github_repo !== TARGET_REPOSITORY || create.detail?.max_effects !== 1) throw new Error("committed target differs from disposable target");
    evidence.creation = create;
    const reserve = parseObject(await invokeC1(remediationKey, nodeUrl, CONTRACT_ID, RESERVATION_FUNCTION, { incident_id: incidentId }));
    assertResponse(reserve, RESERVATION_FUNCTION, "WON");
    evidence.reservation = reserve;
    const claimNonce = randomBytes(16).toString("hex");
    const claim = parseObject(await invokeC1(brokerKey, nodeUrl, CONTRACT_ID, "claim-effect", { incident_id: incidentId, expected_claim_version: 0, contender_nonce: claimNonce }));
    assertResponse(claim, "claim-effect", "PROPOSED");
    const claimId = String(claim.detail?.claim_id ?? "");
    const claimVersion = Number(claim.detail?.claim_version ?? 0);
    if (!/^claim-1-[0-9a-f]{32}$/.test(claimId) || claimVersion !== 1) throw new Error("claim identity is malformed");
    const claimConfirmation = parseObject(await invokeC1(brokerKey, nodeUrl, CONTRACT_ID, "confirm-claim", { incident_id: incidentId, claim_id: claimId }));
    assertResponse(claimConfirmation, "confirm-claim", "CONFIRMED");
    if (claimConfirmation.detail?.claim_id !== claimId || claimConfirmation.detail?.claim_version !== claimVersion || claimConfirmation.detail?.deploy_key_id !== TARGET_ID) throw new Error("confirmed target identity does not match committed target");
    evidence.claim = { response: claim, confirmation: claimConfirmation, claim_id: claimId, claim_version: claimVersion };

    const preBeginExact = await exactKey(token, TARGET_OWNER, TARGET_REPOSITORY, TARGET_ID);
    const preBeginList = await listKeys(token, TARGET_OWNER, TARGET_REPOSITORY);
    const preBeginBody = preBeginExact.body && typeof preBeginExact.body === "object" && !Array.isArray(preBeginExact.body) ? preBeginExact.body as JsonObject : {};
    const preBeginPresent = preBeginExact.status === 200 && preBeginBody.id === TARGET_ID && preBeginBody.title === recorded.title && preBeginBody.read_only === true && preBeginList.status === 200 && repositoryContains(preBeginList.body, TARGET_ID);
    evidence.pre_begin_provider_recheck = { exact_get: safeProviderResponse(preBeginExact), list_get: safeProviderResponse(preBeginList), target_present: preBeginPresent };
    if (!preBeginPresent) throw new Error("provider target changed before effect-start gate");

    const startNonce = randomBytes(16).toString("hex");
    const begin = parseObject(await invokeC1(brokerKey, nodeUrl, CONTRACT_ID, "begin-effect", { incident_id: incidentId, claim_id: claimId, start_nonce: startNonce }));
    assertResponse(begin, "begin-effect", "WON");
    const effectStartId = String(begin.detail?.effect_start_id ?? "");
    if (begin.state !== "EFFECT_STARTED" || begin.effect_attempts !== 1 || !/^start-1-[0-9a-f]{32}$/.test(effectStartId)) throw new Error("effect-start did not commit the required one-shot state");
    const startConfirmation = parseObject(await invokeC1(brokerKey, nodeUrl, CONTRACT_ID, "confirm-effect-start", { incident_id: incidentId, claim_id: claimId, effect_start_id: effectStartId }));
    assertResponse(startConfirmation, "confirm-effect-start", "CONFIRMED");
    evidence.effect_start = { begin, confirmation: startConfirmation, claim_id: claimId, claim_version: claimVersion, effect_start_id: effectStartId };
    const preDeleteRead = parseObject(await invokeC1OperatorSession(t3n, CONTRACT_ID, "get-incident", { incident_id: incidentId }));
    if (preDeleteRead.state !== "EFFECT_STARTED" || preDeleteRead.effect_attempts !== 1 || preDeleteRead.detail?.effect_claim_id !== claimId || preDeleteRead.detail?.effect_start_id !== effectStartId) throw new Error("pre-delete state is not exact confirmed effect-start authority");
    evidence.pre_delete_t3n_read = preDeleteRead;

    const deleteTimestamp = new Date().toISOString();
    const deletion = await deleteKey(token, TARGET_OWNER, TARGET_REPOSITORY, TARGET_ID);
    evidence.provider_operation_counts.target_delete = 1;
    evidence.provider_delete = { requested_at: deleteTimestamp, request: { method: "DELETE", owner: TARGET_OWNER, repository: TARGET_REPOSITORY, deploy_key_id: TARGET_ID }, response: safeProviderResponse(deletion) };
    const afterExact = await exactKey(token, TARGET_OWNER, TARGET_REPOSITORY, TARGET_ID);
    const afterList = await listKeys(token, TARGET_OWNER, TARGET_REPOSITORY);
    const absent = afterExact.status === 404 && afterList.status === 200 && repositoryListIsWellFormed(afterList.body) && !repositoryContains(afterList.body, TARGET_ID);
    evidence.provider_after_delete = { exact_get: safeProviderResponse(afterExact), list_get: safeProviderResponse(afterList), target_absent: absent, independent_reads: true };
    if (deletion.status !== 204 || !absent) throw new Error("provider DELETE was not independently verified as VERIFIED_ABSENT; no retry permitted");

    const finalize = parseObject(await invokeC1(brokerKey, nodeUrl, CONTRACT_ID, "finalize-effect", { incident_id: incidentId, claim_id: claimId, effect_start_id: effectStartId, classification: "VERIFIED_ABSENT" }));
    assertResponse(finalize, "finalize-effect", "WON");
    evidence.finalization = finalize;
    const finalRead = parseObject(await invokeC1OperatorSession(t3n, CONTRACT_ID, "get-incident", { incident_id: incidentId }));
    if (finalRead.state !== "CLOSED" || finalRead.effect_attempts !== 1 || finalRead.detail?.effect_claim_id !== claimId || finalRead.detail?.effect_claim_version !== claimVersion || finalRead.detail?.effect_start_id !== effectStartId || finalRead.detail?.final_result_classification !== "VERIFIED_ABSENT") throw new Error("finalized authority is not the exact CLOSED state");
    evidence.final_t3n_read = finalRead;
    const finalExact = await exactKey(token, TARGET_OWNER, TARGET_REPOSITORY, TARGET_ID);
    const finalList = await listKeys(token, TARGET_OWNER, TARGET_REPOSITORY);
    evidence.final_provider_read = { exact_get: safeProviderResponse(finalExact), list_get: safeProviderResponse(finalList), target_absent: finalExact.status === 404 && finalList.status === 200 && repositoryListIsWellFormed(finalList.body) && !repositoryContains(finalList.body, TARGET_ID) };

    const duplicateBegin = await invokeC1(brokerKey, nodeUrl, CONTRACT_ID, "begin-effect", { incident_id: incidentId, claim_id: claimId, start_nonce: randomBytes(16).toString("hex") });
    const duplicateFinalize = await invokeC1(brokerKey, nodeUrl, CONTRACT_ID, "finalize-effect", { incident_id: incidentId, claim_id: claimId, effect_start_id: effectStartId, classification: "VERIFIED_ABSENT" });
    const releaseAfterClosed = await invokeC1(brokerKey, nodeUrl, CONTRACT_ID, "release-not-attempted", { incident_id: incidentId, claim_id: claimId });
    const reconcileAfterClosed = await invokeC1(brokerKey, nodeUrl, CONTRACT_ID, "reconcile-effect", { incident_id: incidentId, claim_id: claimId, effect_start_id: effectStartId, classification: "VERIFIED_ABSENT" });
    const replayClaim = await invokeC1(brokerKey, nodeUrl, CONTRACT_ID, "claim-effect", { incident_id: incidentId, expected_claim_version: claimVersion, contender_nonce: randomBytes(16).toString("hex") });
    const foreignConfirm = await invokeC1(brokerKey, nodeUrl, CONTRACT_ID, "confirm-claim", { incident_id: incidentId, claim_id: `claim-${claimVersion}-foreign` });
    const foreignBegin = await invokeC1(brokerKey, nodeUrl, CONTRACT_ID, "begin-effect", { incident_id: incidentId, claim_id: `claim-${claimVersion}-foreign`, start_nonce: randomBytes(16).toString("hex") });
    evidence.post_success_barriers = { duplicate_begin: parseObject(duplicateBegin), duplicate_finalize: parseObject(duplicateFinalize), release_after_closed: parseObject(releaseAfterClosed), reconcile_after_closed: parseObject(reconcileAfterClosed), replay_claim: parseObject(replayClaim), foreign_confirm: parseObject(foreignConfirm), foreign_begin: parseObject(foreignBegin) };
    const barrierResponses = Object.values(evidence.post_success_barriers) as JsonObject[];
    if (barrierResponses.some((response) => response.result === "WON" || response.result === "CONFIRMED")) throw new Error("post-success barrier unexpectedly reopened authority");
    const terminalAgain = parseObject(await invokeC1OperatorSession(t3n, CONTRACT_ID, "get-incident", { incident_id: incidentId }));
    if (terminalAgain.state !== "CLOSED" || terminalAgain.effect_attempts !== 1 || terminalAgain.detail?.effect_claim_id !== claimId || terminalAgain.detail?.effect_start_id !== effectStartId) throw new Error("post-success barriers altered terminal authority");
    evidence.post_barrier_t3n_read = terminalAgain;
    evidence.activity_log = safeActivity(await t3n.getActivityLog({ contract: CONTRACT_ID, limit: 100 }));
    evidence.provider_operation_counts.total_resource_mutations = 1;
    evidence.final_invariant = { status: "CLOSED", claim_id: claimId, claim_version: claimVersion, effect_start_id: effectStartId, effect_attempts: 1, provider_delete_count: 1, target_absent: true, provider_operations_after_delete: 0, effect_budget_reopened: false };
    evidence.status = "PASS_REGISTERED_2_0_4_CONTROLLED_PROVIDER_EFFECT_PROVEN";
    evidence.token_lifecycle = { installation_token_minted: true, token_revocation_call: false, reason: "No second GitHub DELETE was issued; token remains short-lived and no resource authority was retained in evidence." };
  } catch (error) {
    evidence.status = "FAIL_REGISTERED_2_0_4_CONTROLLED_PROVIDER_EFFECT_INCOMPLETE";
    evidence.error = redact(error, [process.env.T3N_API_KEY ?? "", remediationKey, brokerKey, token ?? ""]);
    evidence.incident_id = incidentId;
    evidence.stop_rule = "No retry, finalization, reconciliation, or provider continuation after failure.";
  }
  await writeFile(EVIDENCE_PATH, JSON.stringify(evidence, null, 2) + "\n", "utf8");
  if (evidence.status !== "PASS_REGISTERED_2_0_4_CONTROLLED_PROVIDER_EFFECT_PROVEN") {
    console.error(JSON.stringify({ status: evidence.status, incident_id: incidentId, error: evidence.error, evidence: path.relative(root, EVIDENCE_PATH).replaceAll("\\", "/") }, null, 2));
    process.exitCode = 1;
    return;
  }
  console.log(JSON.stringify({ status: evidence.status, incident_id: incidentId, target: `${TARGET_OWNER}/${TARGET_REPOSITORY}#${TARGET_ID}`, claim_id: evidence.final_invariant.claim_id, effect_start_id: evidence.final_invariant.effect_start_id, provider_delete_count: evidence.final_invariant.provider_delete_count, final_state: evidence.final_invariant.status, evidence: path.relative(root, EVIDENCE_PATH).replaceAll("\\", "/") }, null, 2));
}

main().catch((error) => { console.error(`R4E live provider effect failed: ${redact(error, [process.env.T3N_API_KEY ?? ""])}`); process.exitCode = 1; });
