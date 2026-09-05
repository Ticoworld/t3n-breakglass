import { readFileSync } from "node:fs";

const TARGET_ID = 162351194;
const TARGET_TITLE = "breakglass-r4e-disposable-20260904";
const OWNER = "Ticoworld";
const REPOSITORY = "t3n-breakglass-sandbox";
const CONTRACT_VERSION = "2.0.4";
const CONTRACT_ID = "z:adb9365ee986cc6d0cb4006580782fe6fc7a431f:breakglass-winner-c1";
const CONTRACT_NUMERIC_ID = 878;

export type VerificationResult = { ok: boolean; errors: string[]; checks: Record<string, boolean>; network_calls: 0 };

function object(value: unknown): Record<string, any> { return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, any> : {}; }
function has(value: unknown, key: string): boolean { return Object.prototype.hasOwnProperty.call(object(value), key); }
function equalJson(a: unknown, b: unknown): boolean { return JSON.stringify(a) === JSON.stringify(b); }
function strings(value: unknown, output: string[] = [], seen = new WeakSet<object>()): string[] {
  if (typeof value === "string") output.push(value);
  else if (value && typeof value === "object") {
    if (seen.has(value)) return output;
    seen.add(value);
    if (Array.isArray(value)) for (const entry of value) strings(entry, output, seen);
    else for (const entry of Object.values(value)) strings(entry, output, seen);
  }
  return output;
}

export function verifyBundle(source: string | Record<string, unknown>): VerificationResult {
  let bundle: Record<string, any>;
  try { bundle = typeof source === "string" ? JSON.parse(readFileSync(source, "utf8")) : source as Record<string, any>; }
  catch (error) { return { ok: false, errors: [`bundle could not be read: ${error instanceof Error ? error.message : String(error)}`], checks: {}, network_calls: 0 }; }
  const checks: Record<string, boolean> = {};
  const check = (name: string, value: unknown, message = name) => { checks[name] = value === true; };
  const target = object(bundle.target);
  const preflight = object(bundle.target_preflight);
  const preflightProof = object(preflight.target_preflight);
  const preflightCleanup = object(preflight.token_cleanup);
  const incident = object(bundle.incident);
  const create = object(incident.create);
  const createDetail = object(create.detail);
  const brokers = object(bundle.brokers);
  const brokerA = object(brokers.broker_a);
  const brokerB = object(brokers.broker_b);
  const winner = brokers.winner === brokerA.contender ? brokerA : brokers.winner === brokerB.contender ? brokerB : {};
  const loser = brokers.loser === brokerA.contender ? brokerA : brokers.loser === brokerB.contender ? brokerB : {};
  const before = object(winner.before);
  const deletion = object(winner.delete);
  const after = object(winner.after);
  const effectCleanup = object(winner.effect_token_cleanup);
  const verifier = object(winner.verifier_token);
  const verifierCleanup = object(winner.verifier_token_cleanup);
  const independent = object(winner.independent_provider_verification);
  const terminal = object(bundle.terminal);
  const terminalDetail = object(terminal.detail);
  const preDelete = object(bundle.pre_delete_authority);
  const preDeleteReadback = object(preDelete.operator_readback);
  const winnerTarget = object(winner.authority_loaded_target);
  const replay = object(bundle.replay);
  const replayBroker = object(replay.broker);
  const expectedOrder = ["provider_before", "begin-effect", "confirm-effect-start", "pre-delete-authority", "DELETE", "provider_after", "effect_token_revoke", "verifier_issue", "verifier_after", "verifier_revoke", "finalize-effect"];

  check("target_id", target.id === TARGET_ID);
  check("target_title", target.title === TARGET_TITLE);
  check("target_read_only", target.read_only === true);
  check("target_repository", target.repository === `${OWNER}/${REPOSITORY}`);
  check("preflight_present", preflightProof.target_present === true && preflightProof.exact_get?.http_status === 200 && preflightProof.list_get?.http_status === 200 && preflightProof.list_contains_target === true);
  check("preflight_token_revoked_refused", preflightCleanup.revoked === true && preflightCleanup.same_token_refused === true && preflightCleanup.revoke_http_status === 204);
  check("one_incident", bundle.incident_id !== null && typeof bundle.incident_id === "string" && bundle.incident_count === 1);
  check("incident_target", createDetail.action === "revoke_github_deploy_key" && createDetail.github_owner === OWNER && createDetail.github_repo === REPOSITORY && createDetail.deploy_key_id === TARGET_ID && winnerTarget.action === "revoke_github_deploy_key" && winnerTarget.github_owner === OWNER && winnerTarget.github_repo === REPOSITORY && winnerTarget.deploy_key_id === TARGET_ID);
  check("contract_frozen", bundle.contract?.version === CONTRACT_VERSION && bundle.contract?.numeric_id === CONTRACT_NUMERIC_ID && bundle.contract?.name === CONTRACT_ID && bundle.contract?.wasm_bytes === 227011 && bundle.contract?.wasm_sha256 === "ca7032b112b837b06e4334c10bca8820447f6ea1756b74db9bccd3181ad4d5d0");
  check("two_physical_contenders", brokerA.process_id > 0 && brokerB.process_id > 0 && brokerA.process_id !== brokerB.process_id && typeof brokerA.contender_nonce === "string" && typeof brokerB.contender_nonce === "string" && brokerA.contender_nonce !== brokerB.contender_nonce);
  check("one_confirmed_owner", brokers.confirmed_owner_count === 1 && winner.ownership_confirmation === "CONFIRMED" && loser.ownership_confirmation === "NOT_OWNER");
  check("loser_provider_boundary", loser.token_minted === false && loser.provider_credential_mint_count === 0 && loser.destructive_call_count === 0 && loser.delete_attempted === false && loser.provider_calls_after_ownership_loss === 0 && !has(loser, "installation_validation") && !has(loser, "effect_token") && !has(loser, "before") && !has(loser, "delete") && !has(loser, "after") && !has(loser, "verifier_token"));
  check("winner_effect_token_only", winner.token_minted === true && winner.provider_credential_mint_count === 1 && verifier.issued === true && verifier.mutation_count === 0 && loser.token_minted === false && replayBroker.token_minted === false);
  check("provider_before", before.target_present === true && before.exact_get_http_status === 200 && before.list_http_status === 200 && before.read_only === true && before.target_id === TARGET_ID);
  check("effect_start_before_delete", winner.effect_start?.function === "begin-effect" && winner.effect_start?.result === "WON" && winner.effect_start_confirmed === true && deletion.attempt_number === 1 && equalJson(bundle.protocol_order?.slice(0, 5), expectedOrder.slice(0, 5)));
  check("pre_delete_authority", preDeleteReadback.state === "EFFECT_STARTED" && preDeleteReadback.detail?.effect_attempts === 1 && preDeleteReadback.detail?.effect_claim_id === winnerTarget.claim_id && preDeleteReadback.detail?.effect_start_id === winner.effect_start_id && preDelete.delete_allowed_after_this_read === true);
  check("exactly_one_delete", winner.destructive_call_count === 1 && winner.delete_attempted === true && deletion.http_status === 204 && deletion.target_id === TARGET_ID && bundle.provider_counters?.deploy_key_deletes === 1);
  check("provider_after_absent", after.exact_get_http_status === 404 && after.list_http_status === 200 && after.list_body_valid === true && after.target_absent === true && after.list_contains_target === false);
  check("effect_cleanup", effectCleanup.ok === true && effectCleanup.revoke?.success === true && effectCleanup.revoke?.http_status === 204 && effectCleanup.probe?.refused === true);
  check("fresh_verifier", verifier.issued === true && verifier.purpose === "verifier" && verifier.mutation_count === 0 && verifier.distinct_from_effect_token === true && verifier.distinct_from_target_preflight_token === true && winner.verifier_token_reused_effect_token !== true);
  check("independent_absence", independent.target_absent === true && independent.exact_get_http_status === 404 && independent.list_get_http_status === 200 && independent.mutation_count === 0);
  check("verifier_cleanup", verifierCleanup.ok === true && verifierCleanup.revoke?.success === true && verifierCleanup.revoke?.http_status === 204 && verifierCleanup.probe?.refused === true);
  check("finalize_after_all_verification", equalJson(bundle.protocol_order, expectedOrder) && winner.finalize?.function === "finalize-effect" && winner.finalize?.result === "WON" && winner.finalize_request?.incident_id === bundle.incident_id && winner.finalize_request?.claim_id === winnerTarget.claim_id && winner.finalize_request?.effect_start_id === winner.effect_start_id && winner.finalize_request?.classification === "VERIFIED_ABSENT");
  check("closed_terminal", terminal.state === "CLOSED" && terminalDetail.effect_attempts === 1 && terminalDetail.final_result_classification === "VERIFIED_ABSENT");
  check("independent_terminal_reread", equalJson(bundle.independent_terminal_reread, bundle.terminal));
  check("replay_no_provider", replay.remediation_reserve?.result !== "WON" && replayBroker.token_minted === false && replayBroker.provider_credential_mint_count === 0 && replayBroker.destructive_call_count === 0 && replayBroker.delete_attempted === false && replayBroker.provider_calls_after_ownership_loss === 0);
  check("replay_authority_unchanged", equalJson(replay.final_readback, bundle.terminal) && bundle.terminal?.state === "CLOSED");
  check("provider_counters", bundle.provider_counters?.preflight_token_mints === 1 && bundle.provider_counters?.effect_token_mints === 1 && bundle.provider_counters?.verifier_token_mints === 1 && bundle.provider_counters?.deploy_key_posts === 0 && bundle.provider_counters?.deploy_key_deletes === 1 && bundle.provider_counters?.provider_mutations === 1);
  check("no_credential_material", !strings(bundle).some((value) => /t3n_key_|github_pat_|ghs_|ghp_|-----BEGIN|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/i.test(value)));
  const errors = Object.entries(checks).filter(([, passed]) => !passed).map(([name]) => name);
  return { ok: errors.length === 0, errors, checks, network_calls: 0 };
}

if (process.argv[1] && process.argv[1].endsWith("c1-r6b-r4e-r1-evidence-verify.ts")) {
  const file = process.argv[2];
  if (!file) { console.error("usage: c1-r6b-r4e-r1-evidence-verify.ts <bundle.json>"); process.exitCode = 1; }
  else { const result = verifyBundle(file); console.log(JSON.stringify(result, null, 2)); if (!result.ok) process.exitCode = 1; }
}
