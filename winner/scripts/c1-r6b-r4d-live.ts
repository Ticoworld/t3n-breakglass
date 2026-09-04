import { randomBytes } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { connectTenant } from "../../scripts/lib.js";
import { connectC1Principal, invokeC1, invokeC1OperatorSession, redact, requireValue } from "./t3n.js";
import { CONTRACT_VERSION, RESERVATION_FUNCTION, contractName } from "./constants.js";

const root = path.resolve(import.meta.dirname, "../..");
const OPERATOR_DID = "did:t3n:adb9365ee986cc6d0cb4006580782fe6fc7a431f";
const REMEDIATION_DID = "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019";
const BROKER_DID = "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57";
const CONTRACT_ID = contractName(OPERATOR_DID);
const CONTRACT_NUMERIC_ID = 878;
const EVIDENCE_PATH = path.join(root, "winner", "evidence", "C1-R6B-R4D-LIVE-EFFECT-START-OWNERSHIP.json");

function parseObject(raw: unknown): Record<string, any> {
  const value = typeof raw === "string" ? JSON.parse(raw) : raw;
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Terminal 3 response was not an object");
  return value as Record<string, any>;
}

function envFileValue(contents: string, name: string): string {
  const line = contents.split(/\r?\n/).find((entry) => entry.startsWith(`${name}=`));
  if (!line) throw new Error(`${name} missing from environment file`);
  return line.slice(name.length + 1).trim().replace(/^['"]|['"]$/g, "");
}

async function envValue(file: string, name: string): Promise<string> {
  return envFileValue(await readFile(path.join(root, file), "utf8"), name);
}

function assertResponse(response: Record<string, any>, functionName: string, result?: string): void {
  if (response.function !== functionName) throw new Error(`${functionName} returned an unexpected function label`);
  if (result !== undefined && response.result !== result) throw new Error(`${functionName} expected ${result}, got ${String(response.result)}`);
}

function noProvider(response: Record<string, any>): boolean {
  return response.provider_http?.attempted === false && Number(response.provider_http?.count ?? 0) === 0;
}

async function safeInvoke(apiKey: string, nodeUrl: string, functionName: string, input: Record<string, unknown>): Promise<Record<string, any>> {
  try {
    const response = parseObject(await invokeC1(apiKey, nodeUrl, CONTRACT_ID, functionName, input));
    return { ok: true, response };
  } catch (error) {
    return { ok: false, error: redact(error, [apiKey]), function: functionName, input_keys: Object.keys(input) };
  }
}

async function main(): Promise<void> {
  if (Object.keys(process.env).some((key) => key.startsWith("GITHUB_") && Boolean(process.env[key]))) throw new Error("R4D refuses provider credentials");
  const remediationKey = await envValue(".env.replacement-agent", "REPLACEMENT_AGENT_T3N_API_KEY");
  const brokerKey = await envValue(".env.effect-broker", "EFFECT_BROKER_T3N_API_KEY");
  const operatorKey = process.env.T3N_API_KEY;
  delete process.env.T3N_API_KEY;
  process.env.REPLACEMENT_AGENT_T3N_API_KEY = remediationKey;
  process.env.REPLACEMENT_AGENT_DID = REMEDIATION_DID;
  process.env.EFFECT_BROKER_T3N_API_KEY = brokerKey;
  process.env.EFFECT_BROKER_DID = BROKER_DID;
  const remediation = await connectC1Principal("REPLACEMENT_AGENT_T3N_API_KEY", "REPLACEMENT_AGENT_DID");
  const broker = await connectC1Principal("EFFECT_BROKER_T3N_API_KEY", "EFFECT_BROKER_DID");
  if (remediation.did !== REMEDIATION_DID || broker.did !== BROKER_DID) throw new Error("effect principals do not match frozen identities");
  if (remediation.apiKey !== remediationKey || broker.apiKey !== brokerKey) throw new Error("credential file readback mismatch");

  if (!operatorKey) throw new Error("T3N_API_KEY is required for operator session");
  process.env.T3N_API_KEY = operatorKey;
  const { t3n, tenant, tenantDid, nodeUrl } = await connectTenant();
  if (tenantDid !== OPERATOR_DID) throw new Error("operator DID mismatch");
  const listed = (await tenant.contracts.listDetailed()).contracts?.find((item: any) => item.name === CONTRACT_ID && item.version === CONTRACT_VERSION);
  if (!listed) throw new Error("registered 2.0.4 contract is not present in live inventory");

  const incidentId = `C1-R6B-R4D-${Date.now()}-${randomBytes(8).toString("hex")}`;
  const create = parseObject(await invokeC1OperatorSession(t3n, CONTRACT_ID, "create-incident", {
    incident_id: incidentId,
    remediation_agent_did: REMEDIATION_DID,
    effect_broker_did: BROKER_DID,
    deploy_key_id: 1,
    ttl_secs: 900,
  }));
  assertResponse(create, "create-incident", "WON");
  const reserve = parseObject(await invokeC1(remediationKey, nodeUrl, CONTRACT_ID, RESERVATION_FUNCTION, { incident_id: incidentId }));
  assertResponse(reserve, RESERVATION_FUNCTION, "WON");

  const claimNonce = randomBytes(16).toString("hex");
  const claim = parseObject(await invokeC1(brokerKey, nodeUrl, CONTRACT_ID, "claim-effect", {
    incident_id: incidentId,
    expected_claim_version: 0,
    contender_nonce: claimNonce,
  }));
  assertResponse(claim, "claim-effect", "PROPOSED");
  const claimId = String(claim.detail?.claim_id ?? "");
  const claimVersion = Number(claim.detail?.claim_version ?? 0);
  if (!/^claim-1-[0-9a-f]{32}$/.test(claimId) || claimVersion !== 1) throw new Error("authoritative claim identity is malformed");
  const claimConfirm = parseObject(await invokeC1(brokerKey, nodeUrl, CONTRACT_ID, "confirm-claim", { incident_id: incidentId, claim_id: claimId }));
  assertResponse(claimConfirm, "confirm-claim", "CONFIRMED");

  const preBegin = parseObject(await invokeC1OperatorSession(t3n, CONTRACT_ID, "get-incident", { incident_id: incidentId }));
  assertResponse(preBegin, "get-incident", "FOUND");
  if (preBegin.state !== "EFFECT_CLAIMED" || preBegin.effect_attempts !== 0 || preBegin.detail?.effect_start_id !== null) throw new Error("pre-begin state is not EFFECT_CLAIMED/zero/null");

  const wrongStartNonce = randomBytes(16).toString("hex");
  const wrongClaimId = `claim-1-${randomBytes(16).toString("hex")}`;
  const negative: Record<string, any> = {
    remediation_begin: await safeInvoke(remediationKey, nodeUrl, "begin-effect", { incident_id: incidentId, claim_id: claimId, start_nonce: wrongStartNonce }),
    broker_wrong_claim_begin: await safeInvoke(brokerKey, nodeUrl, "begin-effect", { incident_id: incidentId, claim_id: wrongClaimId, start_nonce: randomBytes(16).toString("hex") }),
    broker_foreign_claim_begin: await safeInvoke(brokerKey, nodeUrl, "begin-effect", { incident_id: incidentId, claim_id: "foreign-claim-id", start_nonce: randomBytes(16).toString("hex") }),
  };
  for (const [label, result] of Object.entries(negative)) {
    if (result.ok && result.response.result === "WON") throw new Error(`${label} unexpectedly began effect`);
  }
  const afterNegative = parseObject(await invokeC1OperatorSession(t3n, CONTRACT_ID, "get-incident", { incident_id: incidentId }));
  if (afterNegative.state !== "EFFECT_CLAIMED" || afterNegative.effect_attempts !== 0 || afterNegative.detail?.effect_start_id !== null) throw new Error("negative begin altered claim-only state");

  const startNonce = randomBytes(16).toString("hex");
  const begin = parseObject(await invokeC1(brokerKey, nodeUrl, CONTRACT_ID, "begin-effect", { incident_id: incidentId, claim_id: claimId, start_nonce: startNonce }));
  assertResponse(begin, "begin-effect", "WON");
  const effectStartId = String(begin.detail?.effect_start_id ?? "");
  if (!/^start-1-[0-9a-f]{32}$/.test(effectStartId) || begin.state !== "EFFECT_STARTED" || begin.effect_attempts !== 1) throw new Error("begin-effect did not commit the exact one-shot start state");

  const immediatelyAfter = parseObject(await invokeC1OperatorSession(t3n, CONTRACT_ID, "get-incident", { incident_id: incidentId }));
  if (immediatelyAfter.state !== "EFFECT_STARTED" || immediatelyAfter.effect_attempts !== 1 || immediatelyAfter.detail?.effect_claim_id !== claimId || immediatelyAfter.detail?.effect_start_id !== effectStartId) throw new Error("post-begin state is not durably bound");

  const confirmStart = parseObject(await invokeC1(brokerKey, nodeUrl, CONTRACT_ID, "confirm-effect-start", { incident_id: incidentId, claim_id: claimId, effect_start_id: effectStartId }));
  assertResponse(confirmStart, "confirm-effect-start", "CONFIRMED");
  const wrongClaimConfirm = await safeInvoke(brokerKey, nodeUrl, "confirm-effect-start", { incident_id: incidentId, claim_id: wrongClaimId, effect_start_id: effectStartId });
  const foreignClaimConfirm = await safeInvoke(brokerKey, nodeUrl, "confirm-effect-start", { incident_id: incidentId, claim_id: "foreign-claim-id", effect_start_id: effectStartId });
  const wrongStartConfirm = await safeInvoke(brokerKey, nodeUrl, "confirm-effect-start", { incident_id: incidentId, claim_id: claimId, effect_start_id: "start-1-00000000000000000000000000000000" });
  for (const [label, result] of Object.entries({ wrongClaimConfirm, foreignClaimConfirm, wrongStartConfirm })) {
    if (result.ok && result.response.result === "CONFIRMED") throw new Error(`${label} unexpectedly confirmed effect-start ownership`);
  }
  const stableConfirm = parseObject(await invokeC1(brokerKey, nodeUrl, CONTRACT_ID, "confirm-effect-start", { incident_id: incidentId, claim_id: claimId, effect_start_id: effectStartId }));
  assertResponse(stableConfirm, "confirm-effect-start", "CONFIRMED");

  const duplicateBegin = await safeInvoke(brokerKey, nodeUrl, "begin-effect", { incident_id: incidentId, claim_id: claimId, start_nonce: randomBytes(16).toString("hex") });
  if (duplicateBegin.ok && duplicateBegin.response.result === "WON") throw new Error("duplicate begin-effect succeeded");
  const releaseAfterStart = await safeInvoke(brokerKey, nodeUrl, "release-not-attempted", { incident_id: incidentId, claim_id: claimId });
  if (releaseAfterStart.ok && releaseAfterStart.response.result === "WON") throw new Error("release-not-attempted reopened an effect after start");
  const staleClaim = await safeInvoke(brokerKey, nodeUrl, "claim-effect", { incident_id: incidentId, expected_claim_version: 0, contender_nonce: randomBytes(16).toString("hex") });
  if (staleClaim.ok && staleClaim.response.result === "WON") throw new Error("stale claim version won after effect start");

  const finalRead = parseObject(await invokeC1OperatorSession(t3n, CONTRACT_ID, "get-incident", { incident_id: incidentId }));
  if (finalRead.state !== "EFFECT_STARTED" || finalRead.effect_attempts !== 1 || finalRead.detail?.effect_claim_id !== claimId || finalRead.detail?.effect_start_id !== effectStartId) throw new Error("final state changed after negative calls");
  const { t3n: freshT3n, tenantDid: freshTenantDid } = await connectTenant();
  if (freshTenantDid !== OPERATOR_DID) throw new Error("independent operator reread DID mismatch");
  const independentRead = parseObject(await invokeC1OperatorSession(freshT3n, CONTRACT_ID, "get-incident", { incident_id: incidentId }));
  if (independentRead.state !== "EFFECT_STARTED" || independentRead.effect_attempts !== 1 || independentRead.detail?.effect_claim_id !== claimId || independentRead.detail?.effect_start_id !== effectStartId) throw new Error("independent reread disagrees with persisted start");

  let activity: unknown = null;
  try { activity = await t3n.getActivityLog({ contract: CONTRACT_ID, limit: 100 }); } catch { activity = { read_failed: true }; }
  const evidence = {
    phase: "C1-R6B-R4D registered live effect-start ownership boundary",
    status: "PASS_REGISTERED_2_0_4_EFFECT_START_OWNERSHIP_PROVEN",
    evidence_tier: "LIVE_T3N_TESTNET",
    contract: { canonical_name: CONTRACT_ID, numeric_id: CONTRACT_NUMERIC_ID, version: CONTRACT_VERSION, inventory: listed },
    incident: { incident_id: incidentId, deploy_key_id: 1, ttl_secs: 900, create, reserve, claim, claim_confirm: claimConfirm },
    pre_begin: { read: preBegin, required_state: "EFFECT_CLAIMED", effect_attempts: 0, effect_start_id: null },
    negative_begin_checks: negative,
    after_negative_read: afterNegative,
    begin: { input: { claim_id: claimId, start_nonce_supplied: true }, response: begin, persisted_claim_id: claimId, persisted_claim_version: claimVersion, effect_start_id: effectStartId },
    post_begin_read: immediatelyAfter,
    confirmations: { exact: confirmStart, wrong_claim: wrongClaimConfirm, foreign_claim: foreignClaimConfirm, wrong_start: wrongStartConfirm, stable_exact: stableConfirm },
    post_start_rejections: { duplicate_begin: duplicateBegin, release_not_attempted: releaseAfterStart, stale_claim: staleClaim },
    final_read: finalRead,
    independent_read: independentRead,
    invariant: { one_effect_budget: true, exact_claim_unchanged: true, exactly_one_start_identity: true, effect_attempts: 1, provider_operations: 0 },
    forbidden_operations: { finalize_effect: 0, reconcile_effect: 0, provider_operations: 0, github_api_calls: 0 },
    activity_log_readonly: activity,
    limitations: ["Terminal 3 SDK exposes response documents and activity metadata but no separate per-invocation receipt ID.", "No provider or GitHub operation was attempted.", "The losing identity/claim race was proven in R4C and was not rerun here."],
    credentials_in_evidence: false,
  };
  await writeFile(EVIDENCE_PATH, JSON.stringify(evidence, null, 2) + "\n", "utf8");
  console.log(JSON.stringify({ status: evidence.status, incident_id: incidentId, claim_id: claimId, effect_start_id: effectStartId, effect_attempts: finalRead.effect_attempts, provider_operations: 0, evidence: path.relative(root, EVIDENCE_PATH).replaceAll("\\", "/") }, null, 2));
}

main().catch((error) => { console.error(`R4D live effect-start proof failed: ${redact(error, [process.env.T3N_API_KEY ?? "", process.env.AGENT_T3N_API_KEY ?? "", process.env.EFFECT_BROKER_T3N_API_KEY ?? "", process.env.REPLACEMENT_AGENT_T3N_API_KEY ?? ""] )}`); process.exitCode = 1; });
