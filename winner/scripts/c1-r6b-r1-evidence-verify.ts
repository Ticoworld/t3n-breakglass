import { readFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

type JsonObject = Record<string, any>;

const root = path.resolve(import.meta.dirname, "../..");
const CONTEXT_PATH = path.join(root, "winner", "evidence", "C1-R6B-R1-RUN-CONTEXT.json");
const FAILURE_PATH = path.join(root, "winner", "evidence", "C1-R6B-R1-STATE-FAILURE.json");
const EXPECTED_INCIDENT = "C1-R6B-STATE-state-1788511505884-4208ecd3";
const EXPECTED_CONTRACT = "z:adb9365ee986cc6d0cb4006580782fe6fc7a431f:breakglass-winner-c1";
const EXPECTED_VERSION = "2.0.3";
const EXPECTED_CONTRACT_ID = 877;
const EXPECTED_OPERATOR = "did:t3n:adb9365ee986cc6d0cb4006580782fe6fc7a431f";
const EXPECTED_REMEDIATION = "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019";
const EXPECTED_BROKER = "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57";

function isObject(value: unknown): value is JsonObject {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function at(value: unknown, ...keys: string[]): any {
  let current: any = value;
  for (const key of keys) {
    if (!isObject(current) && !Array.isArray(current)) return undefined;
    current = current?.[key];
  }
  return current;
}

function present(value: unknown): boolean {
  return value !== undefined && value !== null && value !== "";
}

function safe(value: unknown, depth = 0): unknown {
  if (depth > 5) return "[DEPTH_LIMIT]";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean" || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, 20).map((entry) => safe(entry, depth + 1));
  if (!isObject(value)) return String(value);
  const result: JsonObject = {};
  for (const [key, entry] of Object.entries(value)) {
    result[key] = /api[_-]?key|authorization|bearer|token|jwt|private[_-]?key|pat|secret|credential/i.test(key) ? "[REDACTED]" : safe(entry, depth + 1);
  }
  return result;
}

export type VerificationResult = {
  pass: boolean;
  status: "PASS" | "R6B_R2_EVIDENCE_INSUFFICIENT";
  incident_id: string | null;
  errors: string[];
  checked: JsonObject;
};

export function verifyR6BRun(context: unknown, failure: unknown = null): VerificationResult {
  const errors: string[] = [];
  const checked: JsonObject = {};
  const c = isObject(context) ? context : {};
  const f = isObject(failure) ? failure : {};

  const requireValue = (label: string, condition: boolean): void => {
    checked[label] = condition;
    if (!condition) errors.push(label);
  };

  requireValue("incident_id_exact", c.incident_id === EXPECTED_INCIDENT);
  requireValue("run_context_persisted_before_create", c.run_context_persisted_before_create === true);
  requireValue("contract_exact", c.contract?.name === EXPECTED_CONTRACT && c.contract?.version === EXPECTED_VERSION && c.contract?.numeric_contract_id === EXPECTED_CONTRACT_ID);
  requireValue("principals_distinct", c.principals?.all_distinct === true && new Set([c.principals?.operator, c.principals?.remediation_agent, c.principals?.effect_broker]).size === 3);
  requireValue("create_won_active", c.creation?.result?.result === "WON" && c.creation?.result?.state === "ACTIVE");
  requireValue("initial_readback_active", c.creation?.operator_readback?.result === "FOUND" && c.creation?.operator_readback?.state === "ACTIVE");
  requireValue("initial_authority_fields", c.creation?.result?.detail?.effect_attempts === 0 && c.creation?.result?.detail?.effect_claim_version === 0 && c.creation?.result?.detail?.reservation_id === null && c.creation?.result?.detail?.effect_claim_id === null && c.creation?.result?.detail?.final_result_classification === null);
  requireValue("creation_provider_free", c.creation?.result?.provider_http?.attempted === false && c.creation?.result?.provider_http?.count === 0);
  requireValue("reservation_won", c.reservation?.function === "reserve-incident" && c.reservation?.did === EXPECTED_REMEDIATION && c.reservation?.response?.result === "WON" && c.reservation?.response?.state === "RESERVED");
  requireValue("reservation_readback", c.after_reservation?.state === "RESERVED" && c.after_reservation?.detail?.effect_attempts === 0 && c.after_reservation?.detail?.reservation_version === 1 && present(c.after_reservation?.detail?.reservation_id) && c.after_reservation?.detail?.effect_claim_version === 0 && c.after_reservation?.detail?.effect_claim_id === null);

  const contenders = Array.isArray(c.race?.contenders) ? c.race.contenders : [];
  const winners = contenders.filter((entry: JsonObject) => entry?.claim_outcome === "CLAIM_WON");
  const losers = contenders.filter((entry: JsonObject) => entry?.claim_outcome === "CLAIM_LOST");
  const readyFiles = Array.isArray(c.race?.common_barrier?.ready_files) ? c.race.common_barrier.ready_files : [];
  requireValue("two_contenders", contenders.length === 2);
  requireValue("distinct_contender_pids", contenders.length === 2 && new Set(contenders.map((entry: JsonObject) => entry.pid)).size === 2);
  requireValue("both_ready_before_release", c.race?.common_barrier?.both_ready === true && c.race?.common_barrier?.released === true && readyFiles.length === 2 && readyFiles.every((entry: JsonObject) => present(entry.ready_at_unix_ms)));
  requireValue("generation_zero_inputs", contenders.length === 2 && contenders.every((entry: JsonObject) => entry.expected_claim_version === 0));
  requireValue("one_claim_winner_one_loser", winners.length === 1 && losers.length === 1);
  requireValue("winner_zero_effect", winners.length === 1 && winners[0].claim_version === 1 && present(winners[0].claim_id) && winners[0].token_minted === false && winners[0].destructive_call_count === 0 && winners[0].provider_operations === 0);
  requireValue("loser_zero_effect", losers.length === 1 && losers[0].claim_id === null && losers[0].token_minted === false && losers[0].destructive_call_count === 0 && losers[0].provider_operations === 0);
  requireValue("post_race_authority", Boolean(c.after_race) && c.after_race?.state === "EFFECT_CLAIMED" && c.after_race?.detail?.effect_attempts === 0 && c.after_race?.detail?.effect_claim_version === 1 && c.after_race?.detail?.effect_claim_id === winners[0]?.claim_id);

  requireValue("release_won", c.release?.function === "release-not-attempted" && c.release?.did === EXPECTED_BROKER && c.release?.response?.result === "WON");
  requireValue("post_release_authority", c.after_release?.state === "READY_RETRY" && c.after_release?.detail?.effect_attempts === 0 && c.after_release?.detail?.effect_claim_id === null && c.after_release?.detail?.effect_claim_version === 1);
  requireValue("stale_generation_lost", c.stale_contender?.result?.expected_claim_version === 0 && c.stale_contender?.result?.claim_outcome === "CLAIM_LOST" && c.stale_contender?.result?.token_minted === false && c.stale_contender?.result?.destructive_call_count === 0 && c.stale_contender?.result?.provider_operations === 0);
  requireValue("post_stale_authority", c.after_stale?.state === "READY_RETRY" && c.after_stale?.detail?.effect_attempts === 0 && c.after_stale?.detail?.effect_claim_version === 1 && c.after_stale?.detail?.effect_claim_id === null);

  const generationOneClaimId = winners[0]?.claim_id;
  const freshClaimId = c.fresh_claim?.response?.detail?.claim_id;
  requireValue("fresh_generation_won", c.fresh_claim?.did === EXPECTED_BROKER && c.fresh_claim?.function === "claim-effect" && c.fresh_claim?.request_fields?.includes("expected_claim_version") && c.fresh_claim?.response?.result === "WON" && c.fresh_claim?.response?.detail?.claim_version === 2 && present(freshClaimId) && freshClaimId !== generationOneClaimId);
  requireValue("fresh_claim_readback", c.after_fresh_claim?.state === "EFFECT_CLAIMED" && c.after_fresh_claim?.detail?.effect_attempts === 0 && c.after_fresh_claim?.detail?.effect_claim_version === 2 && c.after_fresh_claim?.detail?.effect_claim_id === freshClaimId);
  requireValue("remediation_begin_refused", c.remediation_begin_negative?.did === EXPECTED_REMEDIATION && c.remediation_begin_negative?.function === "begin-effect" && c.remediation_begin_negative?.guest_reached === true && c.remediation_begin_negative?.application_result === "DENIED" && c.remediation_begin_negative?.application_note === "caller is not the effect broker");
  requireValue("pre_broker_begin_authority", c.after_fresh_claim?.state === "EFFECT_CLAIMED" && c.after_fresh_claim?.detail?.effect_attempts === 0 && c.after_fresh_claim?.detail?.effect_claim_version === 2 && c.after_fresh_claim?.detail?.effect_claim_id === freshClaimId);
  requireValue("broker_begin_won", c.begin?.did === EXPECTED_BROKER && c.begin?.function === "begin-effect" && c.begin?.response?.result === "WON" && c.begin?.response?.state === "EFFECT_STARTED" && c.begin?.response?.effect_attempts === 1);
  requireValue("begin_readback", c.after_begin?.state === "EFFECT_STARTED" && c.after_begin?.detail?.effect_attempts === 1 && c.after_begin?.detail?.max_effects === 1 && c.after_begin?.detail?.effect_claim_version === 2 && c.after_begin?.detail?.effect_claim_id === freshClaimId && c.after_begin?.detail?.final_result_classification === null);
  requireValue("post_begin_denials", isObject(c.post_begin_denials) && c.post_begin_denials.release?.application_result !== "WON" && c.post_begin_denials.begin_again?.application_result !== "WON" && c.post_begin_denials.claim_again?.application_result !== "WON" && c.post_begin_denials.reserve_again?.application_result !== "WON");
  requireValue("final_authority", c.final_state?.state === "EFFECT_STARTED" && c.final_state?.detail?.effect_attempts === 1 && c.final_state?.detail?.max_effects === 1 && c.final_state?.detail?.effect_claim_version === 2 && c.final_state?.detail?.effect_claim_id === freshClaimId && c.final_state?.detail?.reservation_id === c.after_begin?.detail?.reservation_id && c.final_state?.detail?.final_result_classification === null);
  requireValue("quota_and_pacing", c.quota_readiness?.successful_application_denial === true && c.quota_errors === 0 && Array.isArray(c.pacing) && c.pacing.length === 6 && c.pacing.every((entry: JsonObject) => entry.completed_at_unix_ms && entry.wait_ms === 70000));
  requireValue("host_activity_retained", isObject(c.activity) && c.activity.classification === "HOST_ACTIVITY");
  requireValue("provider_counters_zero", c.provider_counters?.github_api_calls === 0 && c.provider_counters?.github_installation_tokens === 0 && c.provider_counters?.deploy_key_creates === 0 && c.provider_counters?.deploy_key_deletes === 0 && c.provider_counters?.provider_mutations === 0);
  requireValue("credentials_not_in_evidence", c.credential_safety?.credentials_in_evidence === false && f.credentials_in_evidence === false);

  return {
    pass: errors.length === 0,
    status: errors.length === 0 ? "PASS" : "R6B_R2_EVIDENCE_INSUFFICIENT",
    incident_id: typeof c.incident_id === "string" ? c.incident_id : null,
    errors,
    checked,
  };
}

async function main(): Promise<void> {
  const context = JSON.parse(await readFile(CONTEXT_PATH, "utf8"));
  const failure = JSON.parse(await readFile(FAILURE_PATH, "utf8"));
  const result = verifyR6BRun(context, failure);
  process.stdout.write(JSON.stringify({
    verifier: "C1-R6B-R1 offline evidence verifier",
    ...result,
    source_run_context: "winner/evidence/C1-R6B-R1-RUN-CONTEXT.json",
    secondary_failure_artifact: "winner/evidence/C1-R6B-R1-STATE-FAILURE.json",
    live_calls_during_closure: 0,
    provider_operations_during_closure: 0,
  }));
  if (!result.pass) process.exitCode = 1;
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  main().catch((error) => {
    process.stdout.write(JSON.stringify({ verifier: "C1-R6B-R1 offline evidence verifier", status: "R6B_R2_EVIDENCE_INSUFFICIENT", errors: [error instanceof Error ? error.message : String(error)], live_calls_during_closure: 0, provider_operations_during_closure: 0 }));
    process.exitCode = 1;
  });
}
