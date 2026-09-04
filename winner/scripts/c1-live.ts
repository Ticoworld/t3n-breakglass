import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { connectTenant, redactError } from "../../scripts/lib.js";
import { trustedNodeTimeSeconds } from "../../scripts/product.js";
import { ACTION, BROKER_FUNCTIONS, CONTRACT_TAIL, CONTRACT_VERSION, GITHUB_OWNER, GITHUB_REPOSITORY, RESERVATION_FUNCTION, contractName } from "./constants.js";
import { parseChildJson } from "./child-protocol.js";
import { invokeC1, invokeC1OperatorSession, requireValue, redact } from "./t3n.js";
import { readChildResultBundle, readJsonFile, writeAtomicJson } from "./result-file.js";

const root = path.resolve(import.meta.dirname, "../..");
let liveRunContext: { runDir: string; incidentId: string } | undefined;

function envValue(contents: string, name: string): string { const value = contents.split(/\r?\n/).find((line) => line.startsWith(`${name}=`))?.slice(name.length + 1).trim(); if (!value) throw new Error(`${name} missing from environment file`); return value; }
async function readEnvFile(file: string, name: string): Promise<string> { return envValue(await readFile(path.join(root, file), "utf8"), name); }
async function persistParentFailure(error: unknown): Promise<void> {
  if (!liveRunContext) return;
  const runDir = liveRunContext.runDir;
  const childResults = await readChildResultBundle(runDir);
  await writeAtomicJson(path.join(root, "winner", "evidence", "C1-live-run-failure.json"), { status: "C1_FAIL", incident_id: liveRunContext.incidentId, failure: redactError(error, [process.env.T3N_API_KEY ?? "", process.env.AGENT_T3N_API_KEY ?? "", process.env.EFFECT_BROKER_T3N_API_KEY ?? "", process.env.GITHUB_PAT ?? ""]), persisted_child_results: childResults, child_result_directory: runDir, credentials_in_evidence: false, provider_mutations: "not_inferred_from_missing_parent_state" });
}
function objectResult(raw: unknown): Record<string, unknown> {
  const value = typeof raw === "string" ? JSON.parse(raw) : raw;
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("C1 contract result was not a JSON object");
  return value as Record<string, unknown>;
}
function authorityFromResult(raw: unknown, expectedResult: string, functionName: string, incidentId: string): Record<string, unknown> {
  const response = objectResult(raw);
  if (response.result !== expectedResult || response.function !== functionName) throw new Error(`C1 ${functionName} returned an unexpected result`);
  const detail = response.detail;
  if (!detail || typeof detail !== "object" || Array.isArray(detail)) throw new Error(`C1 ${functionName} did not return authority detail`);
  const authority = detail as Record<string, unknown>;
  if (authority.incident_id !== incidentId || authority.action !== ACTION || authority.github_owner !== GITHUB_OWNER || authority.github_repo !== GITHUB_REPOSITORY || authority.max_effects !== 1) throw new Error(`C1 ${functionName} returned an unexpected authority target`);
  return authority;
}
function requireActiveAuthority(authority: Record<string, unknown>): void {
  if (authority.effect_attempts !== 0 || authority.status !== "ACTIVE" || authority.reservation_id !== null || authority.reservation_version !== 0 || authority.effect_claim_id !== null || authority.effect_claim_version !== 0 || authority.final_result_classification !== null) throw new Error("C1 initial authority is not the exact ACTIVE shape");
}
function requireReplayTerminal(authority: Record<string, unknown>): void {
  if (authority.status !== "CLOSED" || authority.effect_attempts !== 1 || authority.final_result_classification !== "VERIFIED_ABSENT") throw new Error("replay is forbidden before independently verified CLOSED authority");
}
function isPlatformRefusal(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /\b(401|403)\b|forbidden|unauthori[sz]ed|delegat|permission|capabilit|not allowed/i.test(message);
}
async function wrongRoleProbe(apiKey: string, nodeUrl: string, contractId: string, functionName: string, input: Record<string, unknown>, expectedNote: string): Promise<Record<string, unknown>> {
  try {
    const raw = await invokeC1(apiKey, nodeUrl, contractId, functionName, input);
    const response = objectResult(raw);
    if (response.result !== "DENIED" || response.function !== functionName || response.note !== expectedNote) throw new Error(`unexpected wrong-role response for ${functionName}`);
    return { transport_refusal: false, routing_recognized: true, guest_reached: true, application_result: response.result, application_note: response.note, response: raw, state_mutation: false, provider_operation: false };
  } catch (error) {
    if (!isPlatformRefusal(error)) throw error;
    return { transport_refusal: true, routing_recognized: true, guest_reached: false, refusal: redactError(error, [apiKey]), state_mutation: false, provider_operation: false };
  }
}
function exactGrantEvidence(grant: unknown, functions: readonly string[]): boolean {
  if (!grant || typeof grant !== "object" || Array.isArray(grant)) return false;
  const value = grant as Record<string, unknown>;
  return Array.isArray(value.functions) && value.functions.length === functions.length && functions.every((name) => value.functions?.includes(name)) && Array.isArray(value.scopes) && value.scopes.length === 0 && Array.isArray(value.allowed_hosts) && value.allowed_hosts.length === 0 && value.version_req === CONTRACT_VERSION && value.provider_http === false;
}
function run(command: string, args: string[], env: NodeJS.ProcessEnv): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => { const child = spawn(command, args, { cwd: root, env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] }); let stdout = ""; let stderr = ""; child.stdout.on("data", (chunk) => { stdout += String(chunk); }); child.stderr.on("data", (chunk) => { stderr += String(chunk); }); child.on("close", (code) => resolve({ stdout, stderr, code: code ?? 1 })); });
}
function childEnv(base: NodeJS.ProcessEnv, additions: Record<string, string>, remove: string[]): NodeJS.ProcessEnv { const env = { ...base }; for (const name of remove) delete env[name]; Object.assign(env, additions); return env; }

async function main() {
  if (process.env.GITHUB_PAT) throw new Error("C1 live runner refuses a GitHub PAT");
  const operatorDid = requireValue("C1_OPERATOR_DID");
  const remediationKey = await readEnvFile(".env.replacement-agent", "REPLACEMENT_AGENT_T3N_API_KEY");
  const remediationDid = await readEnvFile(".env.replacement-agent", "REPLACEMENT_AGENT_DID");
  const brokerKey = await readEnvFile(".env.effect-broker", "EFFECT_BROKER_T3N_API_KEY");
  const brokerDid = await readEnvFile(".env.effect-broker", "EFFECT_BROKER_DID");
  const actualBarrierDir = path.join(os.tmpdir(), `breakglass-c1-${Date.now()}`);
  await mkdir(actualBarrierDir, { recursive: true });
  const barrier = path.join(actualBarrierDir, "release");
  const proposalsComplete = path.join(actualBarrierDir, "proposals-complete");
  const { tenantDid, nodeUrl, t3n } = await connectTenant();
  if (tenantDid !== operatorDid) throw new Error("live runner authenticated as unexpected operator");
  const incidentId = `C1-${Date.now()}`;
  liveRunContext = { runDir: actualBarrierDir, incidentId };
  const registration = JSON.parse(await readFile(path.join(root, "winner", "evidence", "contract-registration.json"), "utf8")) as { operator_did?: string; contract?: { name?: string; version?: string; contract_id?: number; expected_functions_from_local_component?: string[]; locally_verified_component_exports?: string[]; node_routing_verified_functions?: string[] }; map?: { private?: boolean; acl_contract_id?: number } };
  const config = JSON.parse(await readFile(path.join(root, "winner", "evidence", "delegation-configuration.json"), "utf8")) as { status?: string; operator_did?: string; contract?: string; contract_version?: string; contract_id?: number; remediation_agent_did?: string; effect_broker_did?: string; exact_authority?: { remediation?: unknown; broker?: unknown } };
  const contractId = contractName(operatorDid);
  const requiredFunctions = ["create-incident", "get-incident", RESERVATION_FUNCTION, ...BROKER_FUNCTIONS];
  if (registration.operator_did !== operatorDid || registration.contract?.name !== contractId || registration.contract.version !== CONTRACT_VERSION || !Number.isSafeInteger(registration.contract.contract_id) || registration.contract.contract_id <= 0 || registration.map?.private !== true || registration.map.acl_contract_id !== registration.contract.contract_id) throw new Error("live registration evidence does not match the repaired C1 contract");
  if (config.status !== "CONFIGURED_VERIFIED" || config.operator_did !== operatorDid || config.contract !== contractId || config.contract_version !== CONTRACT_VERSION || config.contract_id !== registration.contract.contract_id || config.remediation_agent_did !== remediationDid || config.effect_broker_did !== brokerDid || new Set([operatorDid, remediationDid, brokerDid]).size !== 3 || !Array.isArray(registration.contract.node_routing_verified_functions) || registration.contract.node_routing_verified_functions.length !== requiredFunctions.length || !requiredFunctions.every((name) => registration.contract?.node_routing_verified_functions?.includes(name)) || !exactGrantEvidence(config.exact_authority?.remediation, [RESERVATION_FUNCTION]) || !exactGrantEvidence(config.exact_authority?.broker, BROKER_FUNCTIONS)) throw new Error("live identity/configuration does not match the registered C1 contract");
  const trustedTimeBeforeCreate = await trustedNodeTimeSeconds(nodeUrl);
  const targetChildEnv = childEnv(process.env, {}, ["T3N_API_KEY", "AGENT_T3N_API_KEY", "EFFECT_BROKER_T3N_API_KEY", "GITHUB_PAT"]);
  const targetRun = await run(process.execPath, ["--import", "tsx", path.join(root, "winner", "broker", "prepare-target.ts")], targetChildEnv);
  if (targetRun.code !== 0) throw new Error(`target setup failed: ${redact(targetRun.stderr, [brokerKey])}`);
  const targetSetup = parseChildJson(targetRun.stdout);
  const target = targetSetup.target as { id: number; title: string; read_only: boolean; repository?: string };
  if (!Number.isSafeInteger(target.id) || target.id <= 0 || target.read_only !== true || target.repository !== `${GITHUB_OWNER}/${GITHUB_REPOSITORY}`) throw new Error("target setup did not prove the exact private read-only repository target");
  const createResponse = await invokeC1OperatorSession(t3n, contractId, "create-incident", { incident_id: incidentId, remediation_agent_did: remediationDid, effect_broker_did: brokerDid, deploy_key_id: target.id, ttl_secs: 900 });
  const createdAuthority = authorityFromResult(createResponse, "WON", "create-incident", incidentId);
  requireActiveAuthority(createdAuthority);
  if (createdAuthority.remediation_agent_did !== remediationDid || createdAuthority.effect_broker_did !== brokerDid || createdAuthority.deploy_key_id !== target.id) throw new Error("create-incident returned unexpected effect principals or target");
  const initialReadbackResponse = await invokeC1OperatorSession(t3n, contractId, "get-incident", { incident_id: incidentId });
  const initialAuthority = authorityFromResult(initialReadbackResponse, "FOUND", "get-incident", incidentId);
  requireActiveAuthority(initialAuthority);
  if (JSON.stringify(initialAuthority) !== JSON.stringify(createdAuthority)) throw new Error("contract-mediated authority readback mismatch");
  const wrongRoleChecks: Record<string, unknown> = {};
  wrongRoleChecks.broker_attempts_reserve = await wrongRoleProbe(brokerKey, nodeUrl, contractId, RESERVATION_FUNCTION, { incident_id: incidentId }, "caller is not the remediation agent");
  const afterBrokerWrongRole = authorityFromResult(await invokeC1OperatorSession(t3n, contractId, "get-incident", { incident_id: incidentId }), "FOUND", "get-incident", incidentId);
  requireActiveAuthority(afterBrokerWrongRole);
  if (JSON.stringify(afterBrokerWrongRole) !== JSON.stringify(initialAuthority)) throw new Error("broker wrong-role reserve changed the ACTIVE authority");
  wrongRoleChecks.after_broker_readback = afterBrokerWrongRole;
  wrongRoleChecks.remediation_attempts_claim = await wrongRoleProbe(remediationKey, nodeUrl, contractId, "claim-effect", { incident_id: incidentId, expected_claim_version: 0 }, "caller is not the effect broker");
  const afterRemediationWrongRole = authorityFromResult(await invokeC1OperatorSession(t3n, contractId, "get-incident", { incident_id: incidentId }), "FOUND", "get-incident", incidentId);
  requireActiveAuthority(afterRemediationWrongRole);
  if (JSON.stringify(afterRemediationWrongRole) !== JSON.stringify(initialAuthority)) throw new Error("remediation wrong-role claim changed the ACTIVE authority");
  wrongRoleChecks.after_remediation_readback = afterRemediationWrongRole;
  const reserveEnv = childEnv(process.env, { AGENT_T3N_API_KEY: remediationKey, AGENT_DID: remediationDid, C1_OPERATOR_DID: operatorDid, C1_INCIDENT_ID: incidentId }, ["T3N_API_KEY", "GITHUB_PAT", "EFFECT_BROKER_T3N_API_KEY"]);
  const reserveChild = await run(process.execPath, ["--import", "tsx", path.join(root, "winner", "scripts", "reserve-agent.ts")], reserveEnv);
  if (reserveChild.code !== 0) throw new Error(`reserve failed: ${reserveChild.stderr.slice(0, 500)}`);
  const reserveResult = parseChildJson(reserveChild.stdout);
  const reserveResponse = objectResult(reserveResult.result);
  if (reserveResponse.result !== "WON" || reserveResponse.function !== RESERVATION_FUNCTION) throw new Error("remediation agent did not commit the expected reservation");
  const childA = path.join(actualBarrierDir, "broker-a.ready");
  const childB = path.join(actualBarrierDir, "broker-b.ready");
  const common = { C1_BARRIER_FILE: barrier, C1_PROPOSALS_COMPLETE_FILE: proposalsComplete, C1_OPERATOR_DID: operatorDid, C1_INCIDENT_ID: incidentId, C1_EXPECTED_CLAIM_VERSION: "0" };
  const brokerBase = childEnv(process.env, { EFFECT_BROKER_T3N_API_KEY: brokerKey, EFFECT_BROKER_DID: brokerDid, ...common }, ["T3N_API_KEY", "AGENT_T3N_API_KEY", "GITHUB_PAT"]);
  const brokerAResultFile = path.join(actualBarrierDir, "broker-a.result.json");
  const brokerBResultFile = path.join(actualBarrierDir, "broker-b.result.json");
  const aPromise = run(process.execPath, ["--import", "tsx", path.join(root, "winner", "broker", "run.ts"), incidentId], { ...brokerBase, C1_READY_FILE: childA, C1_RESULT_FILE: brokerAResultFile, C1_CONTENDER_ID: "broker-a" });
  const bPromise = run(process.execPath, ["--import", "tsx", path.join(root, "winner", "broker", "run.ts"), incidentId], { ...brokerBase, C1_READY_FILE: childB, C1_RESULT_FILE: brokerBResultFile, C1_CONTENDER_ID: "broker-b" });
  const deadline = Date.now() + 120_000;
  while ((!existsSync(childA) || !existsSync(childB)) && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 25));
  if (!existsSync(childA) || !existsSync(childB)) throw new Error("broker race children did not reach the common barrier");
  await writeFile(barrier, JSON.stringify({ released_at_unix_ms: Date.now(), incident_id: incidentId }));
  const proposalDeadline = Date.now() + 120_000;
  while ((!existsSync(brokerAResultFile) || !existsSync(brokerBResultFile)) && Date.now() < proposalDeadline) await new Promise((resolve) => setTimeout(resolve, 25));
  if (!existsSync(brokerAResultFile) || !existsSync(brokerBResultFile)) throw new Error("broker proposals were not durably persisted");
  await writeFile(proposalsComplete, JSON.stringify({ released_at_unix_ms: Date.now(), incident_id: incidentId }));
  const [a, b] = await Promise.all([aPromise, bPromise]);
  const brokers = [await readJsonFile<Record<string, unknown>>(brokerAResultFile), await readJsonFile<Record<string, unknown>>(brokerBResultFile)];
  if (a.code !== 0 || b.code !== 0) throw new Error(`broker child failed after durable result capture: ${a.stderr.slice(0, 500)} ${b.stderr.slice(0, 500)}`);
  const preReplayReadbackResponse = await invokeC1OperatorSession(t3n, contractId, "get-incident", { incident_id: incidentId });
  const preReplayAuthority = authorityFromResult(preReplayReadbackResponse, "FOUND", "get-incident", incidentId);
  requireReplayTerminal(preReplayAuthority);
  const replayProposalComplete = path.join(actualBarrierDir, "replay.proposals-complete");
  const replayEnv = childEnv(process.env, { EFFECT_BROKER_T3N_API_KEY: brokerKey, EFFECT_BROKER_DID: brokerDid, C1_OPERATOR_DID: operatorDid, C1_EXPECTED_CLAIM_VERSION: String(preReplayAuthority.effect_claim_version), C1_PROPOSALS_COMPLETE_FILE: replayProposalComplete, C1_RESULT_FILE: path.join(actualBarrierDir, "replay.result.json"), C1_READY_FILE: path.join(actualBarrierDir, "replay.ready"), C1_BARRIER_FILE: path.join(actualBarrierDir, "replay.release"), C1_CONTENDER_ID: "replay" }, ["T3N_API_KEY", "AGENT_T3N_API_KEY", "GITHUB_PAT"]);
  const replayReady = path.join(actualBarrierDir, "replay.ready");
  const replayRelease = path.join(actualBarrierDir, "replay.release");
  const replayPromise = run(process.execPath, ["--import", "tsx", path.join(root, "winner", "broker", "run.ts"), incidentId], replayEnv);
  const replayDeadline = Date.now() + 60_000;
  while (!existsSync(replayReady) && Date.now() < replayDeadline) await new Promise((resolve) => setTimeout(resolve, 25));
  if (!existsSync(replayReady)) throw new Error("replay broker did not reach the common barrier");
  await writeFile(replayRelease, "release");
  await writeFile(replayProposalComplete, JSON.stringify({ released_at_unix_ms: Date.now(), incident_id: incidentId }));
  const replay = await replayPromise;
  if (replay.code !== 0) throw new Error(`replay broker failed: ${redact(replay.stderr, [brokerKey])}`);
  const replayObservation = await readJsonFile<Record<string, unknown>>(path.join(actualBarrierDir, "replay.result.json"));
  const postReplayReadbackResponse = await invokeC1OperatorSession(t3n, contractId, "get-incident", { incident_id: incidentId });
  const finalAuthority = authorityFromResult(postReplayReadbackResponse, "FOUND", "get-incident", incidentId);
  requireReplayTerminal(finalAuthority);
  let activity: unknown;
  try { activity = await t3n.getActivityLog({ contract: CONTRACT_TAIL, limit: 100 }); } catch (error) { activity = { error: redactError(error, [process.env.T3N_API_KEY ?? ""]) }; }
  const totalDelete = brokers.reduce((sum, item) => sum + Number(item.destructive_call_count ?? 0), 0);
  const totalTokens = brokers.filter((item) => item.token_minted === true).length;
  const statuses = brokers.map((item) => item.claim_outcome);
  const winner = brokers.find((item) => item.ownership_confirmation === "CONFIRMED");
  const loser = brokers.find((item) => item.ownership_confirmation === "NOT_OWNER");
  if (statuses.filter((status) => status === "CLAIM_WON").length !== 1 || statuses.filter((status) => status === "CLAIM_LOST").length !== 1 || brokers.filter((item) => item.ownership_confirmation === "CONFIRMED").length !== 1 || brokers.filter((item) => item.ownership_confirmation === "NOT_OWNER").length !== 1 || totalDelete !== 1 || totalTokens !== 1 || !winner || !loser || loser.token_minted !== false || Number(loser.destructive_call_count ?? -1) !== 0 || loser.delete_attempted !== false || Object.hasOwn(loser, "installation_validation") || Object.hasOwn(loser, "token_scope") || Object.hasOwn(loser, "before") || Object.hasOwn(loser, "delete") || Object.hasOwn(loser, "after") || finalAuthority.status !== "CLOSED" || finalAuthority.effect_attempts !== 1 || finalAuthority.final_result_classification !== "VERIFIED_ABSENT" || replayObservation.claim_outcome !== "CLAIM_LOST" || replayObservation.token_minted !== false || Number(replayObservation.destructive_call_count ?? -1) !== 0 || replayObservation.delete_attempted !== false || winner.token_minted !== true || Number(winner.destructive_call_count ?? -1) !== 1 || winner.delete_attempted !== true || winner.classification !== "VERIFIED_ABSENT" || (winner.revoke as Record<string, unknown> | undefined)?.success !== true || (winner.revoked_token_probe as Record<string, unknown> | undefined)?.refused !== true) throw new Error("C1 kill condition: effect-safe race or replay did not meet the brutal pass criteria");
  const evidence = { experiment: "C1 effect-safe T3N reservation + JIT GitHub remediation", status: "C1_PASS", date_utc: new Date().toISOString(), branch: "winner-v2-core", tested_git_head: process.env.C1_TESTED_GIT_HEAD ?? null, main_sha: process.env.C1_MAIN_SHA ?? null, t3n: { environment: "testnet", node: nodeUrl, sdk: "@terminal3/t3n-sdk 5.2.0", contract: registration.contract.name, version: registration.contract.version, contract_id: registration.contract.contract_id, trusted_time_before_create: trustedTimeBeforeCreate }, principals: { remediation_agent_did: remediationDid, effect_broker_did: brokerDid, operator_did: operatorDid }, incident_id: incidentId, operator_direct_map_access: false, creation: { request_fields: ["incident_id", "remediation_agent_did", "effect_broker_did", "deploy_key_id", "ttl_secs"], result: createResponse, operator_readback: initialReadbackResponse, exact_readback: true, provider_mutations: 0 }, target: { owner: GITHUB_OWNER, repository: GITHUB_REPOSITORY, deploy_key_id: target.id, title: target.title, read_only: target.read_only, private: true }, initial_authority: initialAuthority, wrong_role_checks: wrongRoleChecks, reservation: { result: reserveResult, provider_mutations: 0 }, broker_race: { common_barrier: { both_ready: true, released: true }, contenders: brokers, winner: winner.contender, loser: loser.contender, token_minted_total: totalTokens, destructive_delete_total: totalDelete }, github_before_after: { independent_provider_observation: brokers.map((item) => ({ contender: item.contender, before: item.before, delete: item.delete, after: item.after, classification: item.classification })) }, final_t3n_authority: finalAuthority, replay: replayObservation, activity, credential_safety: { pat_used: false, jwt_in_evidence: false, installation_token_in_evidence: false, authorization_header_in_evidence: false, private_key_in_evidence: false, ssh_private_key_in_evidence: false, t3n_api_key_in_evidence: false }, classifications: { t3n_contract_claims: "LIVE_T3N", github_state: "LIVE_GITHUB independent-provider-GET/list", token_scope: "GitHub-response metadata", activity: "host-stamped activity metadata" }, allowed_claims: ["one committed C1 effect-claim winner under the demonstrated two-process race", "non-winner performed no provider credential mint or mutation in this run", "one broker-issued GitHub DELETE in this run", "independent provider reads verified final absence", "installation token was repository/permission scoped and explicitly revoked", "replay did not regain effect authority"], limitations: ["No real GitHub webhook ingress was used in C1.", "The GitHub App private key remains a standing trust root.", "The one-effect result is an observed C1 architecture/run property, not a provider-side exactly-once guarantee.", "This is not an atomic GitHub plus T3N transaction or a complete causal/Merkle receipt."] };
  const setupToken = targetSetup.setup_token && typeof targetSetup.setup_token === "object" ? targetSetup.setup_token as Record<string, unknown> : {};
  const setupMutations = targetSetup.provider_mutations && typeof targetSetup.provider_mutations === "object" ? targetSetup.provider_mutations as Record<string, unknown> : {};
  Object.assign(evidence, {
    fixture_setup: {
      repository: `${GITHUB_OWNER}/${GITHUB_REPOSITORY}`,
      deploy_key_create_count: Number(setupMutations.deploy_key_create_count ?? 1),
      setup_installation_token_count: setupToken.minted === true ? 1 : 0,
      setup_token_revoked: true,
      token_scope: { repository_selection: setupToken.repository_selection ?? null, permissions: setupToken.permissions ?? null, expires_at: setupToken.expires_at ?? null },
    },
    effect_authority: {
      winner_installation_token_count: winner.token_minted === true ? 1 : 0,
      loser_installation_token_count: loser.token_minted === true ? 1 : 0,
      replay_installation_token_count: replayObservation.token_minted === true ? 1 : 0,
      repository: `${GITHUB_OWNER}/${GITHUB_REPOSITORY}`,
      requested_permissions: { administration: "write" },
    },
    provider_effect: {
      winner_delete_count: Number(winner.destructive_call_count ?? 0),
      loser_delete_count: Number(loser.destructive_call_count ?? 0),
      replay_delete_count: Number(replayObservation.destructive_call_count ?? 0),
      total_broker_delete_count: totalDelete,
    },
    token_revocation: {
      winner_effect_token_revoked: (winner.revoke as Record<string, unknown> | undefined)?.success === true,
      same_token_probe_refused: (winner.revoked_token_probe as Record<string, unknown> | undefined)?.refused === true,
    },
  });
  await mkdir(path.join(root, "winner", "evidence"), { recursive: true });
  await writeFile(path.join(root, "winner", "evidence", "C1-live-proof.json"), JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify({ status: "C1_PASS", incident_id: incidentId, deploy_key_id: target.id, broker_race: { statuses, token_minted_total: totalTokens, destructive_delete_total: totalDelete }, evidence: "winner/evidence/C1-live-proof.json" }, null, 2));
}

main().catch(async (error) => { try { await persistParentFailure(error); } catch { /* retain the original bounded failure below */ } console.error(`C1 live proof failed: ${redactError(error, [process.env.T3N_API_KEY ?? "", process.env.AGENT_T3N_API_KEY ?? "", process.env.EFFECT_BROKER_T3N_API_KEY ?? "", process.env.GITHUB_PAT ?? ""])}`); process.exitCode = 1; });
