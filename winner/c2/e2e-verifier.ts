import { readFileSync } from "node:fs";
import { adjudicateBrokerResults } from "./broker-adjudication.js";

export interface E2EVerificationResult {
  ok: boolean;
  errors: string[];
  checks: Record<string, boolean>;
  network_calls: 0;
}

export interface E2EVerificationContext {
  expectedStartingSha: string;
  expectedMainSha: string;
  expectedBeforeSha: string;
}

type JsonObject = Record<string, any>;

const REPOSITORY = "Ticoworld/t3n-breakglass-sandbox";
const REPOSITORY_ID = 1350596128;
const REF = "refs/heads/c2-breakglass-demo";
const SECRET_PATH = ".breakglass-c2/exposed-deploy-key";
const REMEDIATION_DID = "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019";
const BROKER_DID = "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57";
const HISTORICAL_B1_POLICY = "c2-policy:github-push-c2-b1-1788654034105-84ba7889df89";
const HISTORICAL_R1_POLICY = "c2-policy:github-push-c2-e2e-r1-1788700798113-e96754eec44a";

function object(value: unknown): JsonObject {
  return value && typeof value === "object" && !Array.isArray(value) ? value as JsonObject : {};
}

function has(value: unknown, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(object(value), key);
}

function equalJson(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

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

function noSensitiveMaterial(value: unknown): boolean {
  return !strings(value).some((entry) => /-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----|t3n_key_|github_pat_|gh[pousr]_|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|X-Hub-Signature-256:\s*sha256=/i.test(entry));
}

function status(value: unknown, expected: number): boolean {
  return object(value).http_status === expected || object(value).status === expected;
}

export function verifyE2EBundle(source: string | Record<string, unknown>, context?: E2EVerificationContext): E2EVerificationResult {
  let bundle: JsonObject;
  try {
    bundle = typeof source === "string" ? JSON.parse(readFileSync(source, "utf8")) as JsonObject : source as JsonObject;
  } catch (error) {
    return { ok: false, errors: [`bundle could not be read: ${error instanceof Error ? error.message : String(error)}`], checks: {}, network_calls: 0 };
  }

  const checks: Record<string, boolean> = {};
  if (!context) return { ok: false, errors: ["explicit E2E verification context is required"], checks, network_calls: 0 };
  const validSha = (value: unknown): value is string => typeof value === "string" && /^[0-9a-f]{40}$/i.test(value);
  if (!validSha(context.expectedStartingSha) || !validSha(context.expectedMainSha) || !validSha(context.expectedBeforeSha)) {
    return { ok: false, errors: ["E2E verification context contains an invalid SHA"], checks, network_calls: 0 };
  }
  const check = (name: string, condition: unknown) => { checks[name] = condition === true; };
  const target = object(bundle.fresh_target);
  const targetSetup = object(target.setup_token);
  const policy = object(bundle.policy);
  const authority = object(policy.authority_fields);
  const retired = object(bundle.historical_policy_retirement);
  const retiredList = Array.isArray(bundle.historical_policy_retirements)
    ? bundle.historical_policy_retirements.map((entry: unknown) => object(entry))
    : [];
  const delivery = object(bundle.real_delivery);
  const trigger = object(bundle.secret_trigger_commit);
  const before = object(bundle.immutable_before);
  const after = object(bundle.immutable_after);
  const b1 = object(bundle.b1_verifier);
  const request = object(bundle.derived_c1_request);
  const t3n = object(bundle.t3n);
  const create = object(t3n.create);
  const createDetail = object(create.detail);
  const active = object(t3n.active_readback);
  const reservation = object(t3n.reservation);
  const reserved = object(t3n.reserved_readback);
  const brokers = object(t3n.brokers);
  const brokerA = object(brokers.broker_a);
  const brokerB = object(brokers.broker_b);
  const brokerAdjudication = adjudicateBrokerResults([brokerA, brokerB]);
  const winner = brokerAdjudication.owner_contender === brokerA.contender ? brokerA : brokerAdjudication.owner_contender === brokerB.contender ? brokerB : {};
  const loser = brokerAdjudication.owner_contender === brokerA.contender ? brokerB : brokerAdjudication.owner_contender === brokerB.contender ? brokerA : {};
  const loserOutcome = brokerAdjudication.outcomes.find((outcome) => outcome.contender === loser.contender);
  const effectStart = object(winner.effect_start);
  const effectStartConfirmation = object(winner.effect_start_confirmation);
  const effectToken = object(winner.effect_token);
  const deletion = object(winner.delete);
  const afterDelete = object(winner.after);
  const effectCleanup = object(winner.effect_token_cleanup);
  const verifierToken = object(winner.verifier_token);
  const verifierAfter = object(winner.independent_provider_verification);
  const verifierCleanup = object(winner.verifier_token_cleanup);
  const terminal = object(t3n.closed_readback);
  const terminalDetail = object(terminal.detail);
  const c2Replay = object(bundle.c2_replay);
  const c1Replay = object(bundle.c1_replay);
  const counters = object(bundle.mutation_counters);

  const isR1 = bundle.classification === "C2_E2E_R1_FULL_CAUSAL_REMEDIATION_PASS";
  const isR2 = bundle.classification === "C2_E2E_R2_FULL_CAUSAL_REMEDIATION_PASS";
  check("classification", isR1 || isR2);
  check("starting_sha", bundle.starting_sha === context.expectedStartingSha);
  check("main_sha", bundle.main_sha === context.expectedMainSha);
  check("sandbox_before_sha", bundle.sandbox_before_sha === context.expectedBeforeSha);
  check("target_fresh", Number.isSafeInteger(target.id) && target.id > 0 && typeof target.title === "string" && /^(?:breakglass-c2-b1-e2e-r1-|breakglass-c2-b1-e2e-r2-)/.test(target.title));
  check("target_exact", target.repository === REPOSITORY && target.read_only === true && target.provider_readback_exact === true);
  check("private_public_target_relation", target.private_public_relation_proven === true && target.generated_public_key_fingerprint === target.provider_public_key_fingerprint && target.provider_public_key_fingerprint === authority.expected_public_key_fingerprint);
  check("target_setup_once", targetSetup.create_http_status === 201 && targetSetup.exact_get_http_status === 200 && targetSetup.list_contains_target === true && targetSetup.revoke_http_status === 204 && targetSetup.refusal_http_status >= 401 && targetSetup.refusal_http_status <= 403);
  check("private_digest_binding", /^[0-9a-f]{64}$/.test(String(bundle.private_material_sha256 ?? "")) && authority.expected_private_material_sha256 === bundle.private_material_sha256);
  check("policy_identity", typeof policy.registry_identity === "string" && /^(?:c2-policy:github-push-c2-e2e-r1-|c2-policy:github-push-c2-e2e-r2-)/.test(policy.registry_identity) && policy.policy_version === 2 && authority.policy_id === policy.registry_identity);
  check("policy_exact_binding", authority.repository_id === REPOSITORY_ID && authority.repository_full_name === REPOSITORY && authority.ref === REF && authority.secret_path === SECRET_PATH && authority.deploy_key_id === target.id && authority.expected_deploy_key_title === target.title && authority.expected_read_only === true && authority.ttl_secs === 900 && authority.enabled === true);
  check("policy_live_remote", authority.provenance?.classification === "LIVE_PROVENANCE" && policy.remote_readback?.success === true && typeof policy.content_sha256 === "string");
  const b1Retired = retired.historical_policy_id === HISTORICAL_B1_POLICY && retired.retired === true && retired.cleanup_proven === true;
  const r1Retired = retiredList.some((entry: JsonObject) => entry.historical_policy_id === HISTORICAL_R1_POLICY && entry.retired === true && entry.cleanup_proven === true);
  const listedB1Retired = retiredList.some((entry: JsonObject) => entry.historical_policy_id === HISTORICAL_B1_POLICY && entry.retired === true && entry.cleanup_proven === true);
  check("historical_policy_retired", b1Retired && (!isR2 || (listedB1Retired && r1Retired)));
  check("policy_before_event", object(bundle.policy_before_event).remote_policy_readback_before_trigger === true && object(bundle.policy_before_event).marker_persisted_before_trigger === true && object(bundle.policy_before_event).trigger_issued_after_marker === true);
  check("real_delivery", delivery.event_type === "push" && delivery.repository_id === REPOSITORY_ID && delivery.repository_full_name === REPOSITORY && delivery.ref === REF && delivery.created === false && delivery.forced === false && delivery.deleted === false && delivery.signature_verified === true && delivery.hmac_verified === true && typeof delivery.delivery_id === "string" && delivery.dedupe_status === "NEW");
  check("trigger_exact", trigger.parent_sha === context.expectedBeforeSha && trigger.only_changed_path === SECRET_PATH && trigger.fast_forward === true && delivery.before === context.expectedBeforeSha && delivery.after === trigger.sha && /^[0-9a-f]{40}$/i.test(String(trigger.sha ?? "")));
  check("immutable_transition", before.status === 404 && before.commit_sha === context.expectedBeforeSha && before.path === SECRET_PATH && after.status === 200 && after.commit_sha === trigger.sha && after.path === SECRET_PATH && after.content_sha256 === bundle.private_material_sha256 && bundle.transition_classification === "CAUSAL_SECRET_INTRODUCED");
  check("b1_verifier", b1.valid === true && Array.isArray(b1.reasons) && b1.reasons.length === 0 && b1.context?.expectedStartingSha === context.expectedStartingSha && b1.context?.expectedMainSha === context.expectedMainSha && b1.context?.expectedBeforeSha === context.expectedBeforeSha);
  check("derived_request_shape", equalJson(Object.keys(request).sort(), ["deploy_key_id", "effect_broker_did", "incident_id", "remediation_agent_did", "ttl_secs"].sort()) && request.deploy_key_id === target.id && request.remediation_agent_did === REMEDIATION_DID && request.effect_broker_did === BROKER_DID && request.ttl_secs === 900);
  check("create_once", create.result === "WON" && create.function === "create-incident" && create.state === "ACTIVE" && createDetail.deploy_key_id === target.id && createDetail.remediation_agent_did === REMEDIATION_DID && createDetail.effect_broker_did === BROKER_DID && createDetail.action === "revoke_github_deploy_key");
  check("active_readback", active.state === "ACTIVE" && active.detail?.deploy_key_id === target.id && active.detail?.effect_attempts === 0);
  check("reservation", reservation.result === "WON" && reservation.function === "reserve-incident" && reservation.state === "RESERVED" && reserved.state === "RESERVED" && reserved.detail?.effect_attempts === 0);
  check("one_confirmed_owner", brokerAdjudication.valid && brokerAdjudication.confirmed_owner_count === 1 && brokers.confirmed_owner_count === 1 && brokers.winner === brokerAdjudication.owner_contender && winner.ownership_confirmation === "CONFIRMED" && (loserOutcome?.state === "NON_OWNER_EARLY_CLAIM_LOST" || loserOutcome?.state === "NON_OWNER_CONFIRM_REJECTED"));
  check("loser_zero_authority", loserOutcome !== undefined && loserOutcome.state !== "INVALID_INDETERMINATE" && loser.token_minted === false && loser.provider_credential_mint_count === 0 && (loser.destructive_call_count ?? loser.delete_count) === 0 && (loser.delete_attempted === undefined || loser.delete_attempted === false) && loser.provider_calls_after_ownership_loss === 0 && !has(loser, "effect_token") && !has(loser, "before") && !has(loser, "delete"));
  check("effect_start", effectStart.result === "WON" && effectStart.function === "begin-effect" && effectStart.state === "EFFECT_STARTED" && effectStart.effect_attempts === 1 && effectStartConfirmation.result === "CONFIRMED" && winner.effect_start_confirmed === true);
  check("effect_token_order", effectToken.issued === true && effectToken.minted_after_confirmed_effect_start === true && winner.provider_credential_mint_count === 1);
  check("pre_delete_target", object(winner.before).target_present === true && object(winner.before).exact_get_http_status === 200 && object(winner.before).read_after_confirmed_effect_start === true);
  check("one_delete", deletion.attempt_number === 1 && deletion.method === "DELETE" && deletion.http_status === 204 && deletion.target_id === target.id && winner.destructive_call_count === 1);
  check("effect_cleanup", effectCleanup.ok === true && effectCleanup.revoke?.http_status === 204 && effectCleanup.probe?.refused === true);
  check("independent_verifier", verifierToken.issued === true && verifierToken.distinct_from_effect_token === true && verifierToken.mutation_count === 0 && verifierAfter.target_absent === true && verifierAfter.exact_get_http_status === 404 && verifierAfter.mutation_count === 0 && verifierCleanup.ok === true && verifierCleanup.revoke?.http_status === 204 && verifierCleanup.probe?.refused === true);
  check("closed", terminal.state === "CLOSED" && terminalDetail.effect_attempts === 1 && terminalDetail.final_result_classification === "VERIFIED_ABSENT" && terminalDetail.effect_claim_id === winner.authority_loaded_target?.claim_id && terminalDetail.effect_start_id === winner.effect_start_id);
  check("c2_replay", c2Replay.classification === "DUPLICATE_SAME" && c2Replay.incident_id === request.incident_id && equalJson(c2Replay.create_request, request) && c2Replay.new_immutable_source_reads === 0 && c2Replay.new_t3n_incident_creations === 0 && c2Replay.provider_authority_count === 0 && c2Replay.provider_mutations === 0);
  check("c1_replay", c1Replay.closed_replay_rejected === true && c1Replay.new_effect_token_mints === 0 && c1Replay.new_delete_count === 0 && c1Replay.effect_attempts === 1 && c1Replay.target_absent === true);
  check("policy_retired_after_success", object(bundle.successful_policy_retirement).policy_id === policy.registry_identity && object(bundle.successful_policy_retirement).deploy_key_id === target.id && object(bundle.successful_policy_retirement).retired === true && object(bundle.successful_policy_retirement).terminal_classification === "VERIFIED_ABSENT");
  check("mutation_accounting", counters.fixture_setup?.ssh_key_generations === 1 && counters.fixture_setup?.deploy_key_creates === 1 && counters.causal_source?.secret_trigger_pushes === 1 && counters.t3n_protocol?.incident_creates === 1 && counters.t3n_protocol?.reservations === 1 && counters.t3n_protocol?.effect_attempts === 1 && counters.provider_effect?.deploy_key_deletes === 1 && counters.independent_verification?.provider_mutations === 0 && counters.replay?.provider_token_mints === 0 && counters.replay?.provider_mutations === 0 && counters.replay?.deploy_key_deletes === 0);
  check("sensitive_hygiene", bundle.sensitive_value_hygiene?.private_material_in_evidence === false && bundle.sensitive_value_hygiene?.private_material_in_policy === false && bundle.sensitive_value_hygiene?.raw_webhook_body_in_evidence === false && bundle.sensitive_value_hygiene?.app_private_key_in_evidence === false && bundle.sensitive_value_hygiene?.installation_token_in_evidence === false && bundle.sensitive_value_hygiene?.webhook_secret_in_evidence === false && noSensitiveMaterial(bundle));
  const errors = Object.entries(checks).filter(([, passed]) => !passed).map(([name]) => name);
  return { ok: errors.length === 0, errors, checks, network_calls: 0 };
}

if (process.argv[1] && process.argv[1].endsWith("e2e-verifier.ts")) {
  const file = process.argv[2];
  if (!file) { console.error("usage: e2e-verifier.ts <bundle.json>"); process.exitCode = 1; }
  else { console.error("the CLI requires an explicit execution context; import verifyE2EBundle and provide it"); process.exitCode = 1; }
}
