import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

type JsonObject = Record<string, any>;

export const REQUIRED_FILES = [
  "00-run-context.json",
  "01-quota-readiness.json",
  "02-create.json",
  "03-initial-active-read.json",
  "04-reserve.json",
  "05-reserved-read.json",
  "06-race-barrier.json",
  "07-race-broker-a.json",
  "08-race-broker-b.json",
  "09-post-race-read.json",
  "10-release.json",
  "11-post-release-read.json",
  "12-stale-claim.json",
  "13-post-stale-read.json",
  "14-fresh-claim.json",
  "15-post-fresh-read.json",
  "16-remediation-begin.json",
  "17-post-remediation-begin-read.json",
  "18-broker-begin.json",
  "19-post-begin-read.json",
  "20-release-after-begin.json",
  "21-begin-after-begin.json",
  "22-claim-after-begin.json",
  "23-reserve-after-begin.json",
  "24-final-authority-read.json",
  "25-host-activity.json",
  "26-provider-counters.json",
  "27-run-complete.json",
] as const;

const EXPECTED_CONTRACT = "z:adb9365ee986cc6d0cb4006580782fe6fc7a431f:breakglass-winner-c1";
const EXPECTED_VERSION = "2.0.3";
const EXPECTED_CONTRACT_ID = 877;
const EXPECTED_OPERATOR = "did:t3n:adb9365ee986cc6d0cb4006580782fe6fc7a431f";
const EXPECTED_REMEDIATION = "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019";
const EXPECTED_BROKER = "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57";

function isObject(value: unknown): value is JsonObject {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function present(value: unknown): boolean {
  return value !== undefined && value !== null && value !== "";
}

function safe(value: unknown, depth = 0): unknown {
  if (depth > 5) return "[DEPTH_LIMIT]";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean" || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, 30).map((entry) => safe(entry, depth + 1));
  if (!isObject(value)) return String(value);
  const result: JsonObject = {};
  for (const [key, entry] of Object.entries(value)) {
    result[key] = /api[_-]?key|authorization|bearer|token|jwt|private[_-]?key|pat|secret|credential/i.test(key) ? "[REDACTED]" : safe(entry, depth + 1);
  }
  return result;
}

function response(doc: JsonObject | undefined): JsonObject {
  return isObject(doc?.response) ? doc.response : {};
}

function detail(doc: JsonObject | undefined): JsonObject {
  const value = response(doc).detail;
  return isObject(value) ? value : {};
}

function appResult(doc: JsonObject | undefined): unknown {
  return doc?.application_result ?? response(doc).result;
}

function appState(doc: JsonObject | undefined): unknown {
  return response(doc).state;
}

function appGuestReached(doc: JsonObject | undefined): unknown {
  return doc?.guest_reached;
}

function appNote(doc: JsonObject | undefined): unknown {
  return doc?.application_note ?? response(doc).note;
}

function docProviderFree(doc: JsonObject | undefined): boolean {
  if (!doc) return false;
  const provider = response(doc).provider_http;
  return doc.provider_operations === 0 &&
    (!isObject(provider) || (provider.attempted === false && provider.count === 0));
}

export type BundleVerification = {
  pass: boolean;
  status: "PASS" | "R6B_R3_EVIDENCE_INSUFFICIENT";
  run_directory: string;
  incident_id: string | null;
  errors: string[];
  checked: JsonObject;
  file_count: number;
};

export async function verifyR6BRunBundle(directory: string): Promise<BundleVerification> {
  const errors: string[] = [];
  const checked: JsonObject = {};
  const docs: Record<string, JsonObject | undefined> = {};
  const root = path.resolve(directory);

  const check = (name: string, value: boolean): void => {
    checked[name] = value;
    if (!value) errors.push(name);
  };

  for (const file of REQUIRED_FILES) {
    try {
      const parsed = JSON.parse(await readFile(path.join(root, file), "utf8")) as unknown;
      docs[file] = isObject(parsed) ? parsed : undefined;
    } catch {
      docs[file] = undefined;
    }
    check(`file:${file}`, Boolean(docs[file]));
  }

  const context = docs["00-run-context.json"];
  const incidentId = typeof context?.incident_id === "string" ? context.incident_id : null;
  check("run_context_incident_present", Boolean(incidentId));
  check("run_context_phase", context?.phase === "C1-R6B-R3");
  check("run_context_persisted_before_create", context?.persisted_before_create === true);
  check("run_context_identity", context?.contract?.name === EXPECTED_CONTRACT && context.contract.version === EXPECTED_VERSION && context.contract.numeric_contract_id === EXPECTED_CONTRACT_ID);
  check("run_context_principals", context?.principals?.operator === EXPECTED_OPERATOR && context.principals.remediation_agent === EXPECTED_REMEDIATION && context.principals.effect_broker === EXPECTED_BROKER && context.principals.all_distinct === true);
  check("run_context_provider_zero", context?.provider_counters?.github_api_calls === 0 && context.provider_counters?.github_installation_tokens === 0 && context.provider_counters?.deploy_key_creates === 0 && context.provider_counters?.deploy_key_deletes === 0 && context.provider_counters?.provider_mutations === 0);

  for (const file of REQUIRED_FILES.slice(1).filter((name) => name !== "01-quota-readiness.json")) {
    const doc = docs[file];
    if (doc && incidentId) check(`incident:${file}`, doc.incident_id === incidentId);
  }

  const quota = docs["01-quota-readiness.json"];
  check("quota_readiness_incident_distinct", typeof quota?.incident_id === "string" && quota.incident_id.length > 0 && quota.incident_id !== incidentId);
  check("quota_readiness_denied_not_found", response(quota).result === "DENIED" && response(quota).note === "incident authority does not exist");
  check("quota_readiness_provider_free", docProviderFree(quota));

  const create = docs["02-create.json"];
  check("create_won_active", response(create).result === "WON" && response(create).state === "ACTIVE");
  check("create_authority_shape", detail(create).effect_attempts === 0 && detail(create).effect_claim_version === 0 && detail(create).reservation_id === null && detail(create).effect_claim_id === null && detail(create).final_result_classification === null);
  check("create_provider_free", docProviderFree(create));

  const initial = docs["03-initial-active-read.json"];
  check("initial_active_read", response(initial).result === "FOUND" && response(initial).state === "ACTIVE" && detail(initial).effect_attempts === 0 && detail(initial).effect_claim_version === 0 && detail(initial).reservation_id === null && detail(initial).effect_claim_id === null && detail(initial).final_result_classification === null);
  check("initial_read_provider_free", docProviderFree(initial));

  const reserve = docs["04-reserve.json"];
  check("reservation_won", reserve?.did === EXPECTED_REMEDIATION && reserve.function === "reserve-incident" && appResult(reserve) === "WON" && appState(reserve) === "RESERVED");
  check("reservation_provider_free", docProviderFree(reserve));

  const reserved = docs["05-reserved-read.json"];
  check("reserved_read", response(reserved).result === "FOUND" && response(reserved).state === "RESERVED" && detail(reserved).reservation_version === 1 && present(detail(reserved).reservation_id) && detail(reserved).effect_attempts === 0 && detail(reserved).effect_claim_version === 0 && detail(reserved).effect_claim_id === null);
  check("reserved_read_provider_free", docProviderFree(reserved));

  const barrier = docs["06-race-barrier.json"];
  const contenders = [docs["07-race-broker-a.json"], docs["08-race-broker-b.json"]];
  check("race_barrier_ready", barrier?.common_barrier_ready === true && Array.isArray(barrier.contenders) && barrier.contenders.length === 2 && present(barrier.released_at_unix_ms));
  check("race_barrier_distinct_pids", contenders.every((doc) => present(doc?.pid)) && new Set(contenders.map((doc) => doc?.pid)).size === 2);
  check("race_barrier_expected_generation", contenders.every((doc) => doc?.expected_claim_version === 0));
  const winners = contenders.filter((doc) => doc?.claim_outcome === "CLAIM_WON");
  const losers = contenders.filter((doc) => doc?.claim_outcome === "CLAIM_LOST");
  check("race_one_winner_one_loser", winners.length === 1 && losers.length === 1);
  check("race_winner_zero_effect", winners.length === 1 && winners[0].claim_version === 1 && present(winners[0].claim_id) && winners[0].token_minted === false && winners[0].destructive_call_count === 0 && winners[0].provider_operations === 0);
  check("race_loser_zero_effect", losers.length === 1 && losers[0].claim_id === null && losers[0].token_minted === false && losers[0].destructive_call_count === 0 && losers[0].provider_operations === 0);
  check("race_child_contract_identity", contenders.every((doc) => doc?.did === EXPECTED_BROKER && doc.contract === EXPECTED_CONTRACT && doc.version === EXPECTED_VERSION));

  const postRace = docs["09-post-race-read.json"];
  check("post_race_authority", response(postRace).state === "EFFECT_CLAIMED" && detail(postRace).effect_attempts === 0 && detail(postRace).effect_claim_version === 1 && detail(postRace).effect_claim_id === winners[0]?.claim_id);
  check("post_race_provider_free", docProviderFree(postRace));

  const release = docs["10-release.json"];
  check("release_won_retry", release?.did === EXPECTED_BROKER && release.function === "release-not-attempted" && appResult(release) === "WON" && appState(release) === "READY_RETRY");
  const postRelease = docs["11-post-release-read.json"];
  check("post_release_generation_retained", response(postRelease).state === "READY_RETRY" && detail(postRelease).effect_attempts === 0 && detail(postRelease).effect_claim_id === null && detail(postRelease).effect_claim_version === 1);

  const stale = docs["12-stale-claim.json"];
  check("stale_generation_lost", stale?.did === EXPECTED_BROKER && stale.expected_claim_version === 0 && stale.claim_outcome === "CLAIM_LOST" && stale.token_minted === false && stale.provider_operations === 0 && stale.destructive_call_count === 0);
  const postStale = docs["13-post-stale-read.json"];
  check("post_stale_generation_fence", response(postStale).state === "READY_RETRY" && detail(postStale).effect_attempts === 0 && detail(postStale).effect_claim_version === 1 && detail(postStale).effect_claim_id === null);

  const fresh = docs["14-fresh-claim.json"];
  const freshClaimId = detail(fresh).claim_id;
  const generationOneClaimId = winners[0]?.claim_id;
  check("fresh_generation_won", fresh?.did === EXPECTED_BROKER && fresh.function === "claim-effect" && fresh.expected_claim_version === 1 && appResult(fresh) === "WON" && detail(fresh).claim_version === 2 && present(freshClaimId) && freshClaimId !== generationOneClaimId);
  const postFresh = docs["15-post-fresh-read.json"];
  check("post_fresh_authority", response(postFresh).state === "EFFECT_CLAIMED" && detail(postFresh).effect_attempts === 0 && detail(postFresh).effect_claim_version === 2 && detail(postFresh).effect_claim_id === freshClaimId);

  const remediationBegin = docs["16-remediation-begin.json"];
  check("remediation_begin_refused", remediationBegin?.did === EXPECTED_REMEDIATION && remediationBegin.function === "begin-effect" && appResult(remediationBegin) !== "WON" && appGuestReached(remediationBegin) === true && appNote(remediationBegin) === "caller is not the effect broker");
  const postRemediation = docs["17-post-remediation-begin-read.json"];
  check("post_remediation_unchanged", response(postRemediation).state === "EFFECT_CLAIMED" && detail(postRemediation).effect_attempts === 0 && detail(postRemediation).effect_claim_version === 2 && detail(postRemediation).effect_claim_id === freshClaimId);

  const brokerBegin = docs["18-broker-begin.json"];
  check("broker_begin_started", brokerBegin?.did === EXPECTED_BROKER && brokerBegin.function === "begin-effect" && appResult(brokerBegin) === "WON" && appState(brokerBegin) === "EFFECT_STARTED" && response(brokerBegin).effect_attempts === 1);
  const postBegin = docs["19-post-begin-read.json"];
  check("post_begin_authority", response(postBegin).state === "EFFECT_STARTED" && detail(postBegin).effect_attempts === 1 && detail(postBegin).max_effects === 1 && detail(postBegin).effect_claim_version === 2 && detail(postBegin).effect_claim_id === freshClaimId && present(detail(postBegin).reservation_id) && detail(postBegin).final_result_classification === null);

  const releaseAfter = docs["20-release-after-begin.json"];
  const beginAfter = docs["21-begin-after-begin.json"];
  const claimAfter = docs["22-claim-after-begin.json"];
  const reserveAfter = docs["23-reserve-after-begin.json"];
  check("release_after_begin_not_won", appResult(releaseAfter) !== "WON" && releaseAfter?.did === EXPECTED_BROKER);
  check("begin_after_begin_not_won", appResult(beginAfter) !== "WON" && beginAfter?.did === EXPECTED_BROKER);
  check("claim_after_begin_not_won", appResult(claimAfter) !== "WON" && claimAfter?.did === EXPECTED_BROKER);
  check("reserve_after_begin_not_won", appResult(reserveAfter) !== "WON" && reserveAfter?.did === EXPECTED_REMEDIATION);

  const final = docs["24-final-authority-read.json"];
  check("final_authority_exact", response(final).state === "EFFECT_STARTED" && detail(final).effect_attempts === 1 && detail(final).max_effects === 1 && detail(final).effect_claim_version === 2 && detail(final).effect_claim_id === freshClaimId && detail(final).reservation_id === detail(postBegin).reservation_id && detail(final).final_result_classification === null);
  check("final_provider_free", docProviderFree(final));

  const activity = docs["25-host-activity.json"];
  check("host_activity_retained", activity?.classification === "HOST_ACTIVITY" && present(activity.observed_at_unix_ms));
  const provider = docs["26-provider-counters.json"];
  check("provider_counters_zero", provider?.incident_id === incidentId && provider.github_api_calls === 0 && provider.github_installation_tokens === 0 && provider.deploy_key_creates === 0 && provider.deploy_key_deletes === 0 && provider.provider_mutations === 0 && provider.provider_helpers_imported === false);
  const complete = docs["27-run-complete.json"];
  check("run_complete_marker", complete?.live_sequence_complete === true && complete.all_required_primary_files_present === true && complete.incident_id === incidentId && complete.claim_version_final === 2 && complete.effect_attempts_final === 1 && complete.provider_operations === 0);

  const fileCount = (await readdir(root)).filter((entry) => entry.endsWith(".json")).length;
  check("directory_contains_required_file_count", fileCount >= REQUIRED_FILES.length);

  return { pass: errors.length === 0, status: errors.length === 0 ? "PASS" : "R6B_R3_EVIDENCE_INSUFFICIENT", run_directory: root, incident_id: incidentId, errors, checked, file_count: fileCount };
}

async function main(): Promise<void> {
  const directory = process.argv[2];
  if (!directory) throw new Error("usage: c1-r6b-r3-evidence-verify.ts <evidence-directory>");
  const result = await verifyR6BRunBundle(directory);
  process.stdout.write(JSON.stringify({ verifier: "C1-R6B-R3 evidence verifier", ...result, network_calls: 0, provider_operations: 0 }));
  if (!result.pass) process.exitCode = 1;
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  main().catch((error) => {
    process.stdout.write(JSON.stringify({ verifier: "C1-R6B-R3 evidence verifier", status: "R6B_R3_EVIDENCE_INSUFFICIENT", errors: [error instanceof Error ? error.message : String(error)], network_calls: 0, provider_operations: 0 }));
    process.exitCode = 1;
  });
}
