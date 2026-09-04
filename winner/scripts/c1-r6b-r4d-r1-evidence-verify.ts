import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const CONTRACT_NAME = "z:adb9365ee986cc6d0cb4006580782fe6fc7a431f:breakglass-winner-c1";
const CONTRACT_VERSION = "2.0.4";
const CONTRACT_ID = 878;
const BROKER_DID = "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57";
const REMEDIATION_DID = "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019";
const OPERATOR_DID = "did:t3n:adb9365ee986cc6d0cb4006580782fe6fc7a431f";
const ORG_DID = "did:t3n:3c63f09271c0d9184abbcccbfae28698a8f4a912";
const BROKER_FUNCTIONS = ["claim-effect", "confirm-claim", "release-not-attempted", "begin-effect", "confirm-effect-start", "finalize-effect", "reconcile-effect"];

type JsonObject = Record<string, any>;

function objectAt(value: unknown): JsonObject | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as JsonObject : null;
}

function responseAt(value: unknown): JsonObject | null {
  const object = objectAt(value);
  return objectAt(object?.response) ?? object;
}

function nonemptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function emptyOrAbsent(value: unknown): boolean {
  return value === undefined || value === null || (Array.isArray(value) && value.length === 0);
}

function exactArray(value: unknown, expected: string[]): boolean {
  return Array.isArray(value) && value.length === expected.length && [...value].sort().every((entry, index) => entry === [...expected].sort()[index]);
}

function noProvider(document: unknown): boolean {
  const object = objectAt(document);
  const providerHttpAbsentOrZero = object?.provider_http === undefined
    || (object?.provider_http?.attempted === false && Number(object?.provider_http?.count ?? 0) === 0);
  return providerHttpAbsentOrZero
    && Number(object?.provider_operations ?? 0) === 0
    && object?.token_minted !== true
    && Number(object?.destructive_call_count ?? 0) === 0;
}

export function verifyBundle(bundle: JsonObject): { ok: boolean; errors: string[] } {
  const errors: string[] = [];
  const require = (condition: unknown, message: string) => { if (!condition) errors.push(message); };
  const authority = (value: unknown, label: string, state: string, attempts: number, claimVersion: number, claimId: string | null, startId: string | null) => {
    const object = objectAt(value);
    const detail = objectAt(object?.detail) ?? objectAt(object?.authority);
    require(object?.result === "FOUND" || object?.application_result === "FOUND" || object?.status === state, `${label}: read did not report FOUND/status`);
    require((object?.state ?? object?.status) === state, `${label}: state is not ${state}`);
    require((object?.effect_attempts ?? detail?.effect_attempts) === attempts, `${label}: effect_attempts mismatch`);
    if (claimVersion !== undefined) require((object?.effect_claim_version ?? detail?.effect_claim_version) === claimVersion, `${label}: claim version mismatch`);
    require((detail?.effect_claim_id ?? object?.effect_claim_id ?? null) === claimId, `${label}: claim identity mismatch`);
    require((detail?.effect_start_id ?? object?.effect_start_id ?? null) === startId, `${label}: start identity mismatch`);
    return detail;
  };

  const active = objectAt(bundle.active_contract);
  require(active?.name === CONTRACT_NAME && active?.version === CONTRACT_VERSION && active?.numeric_id === CONTRACT_ID && active?.status === "active", "active contract mismatch");
  const principals = objectAt(bundle.principals);
  require(principals?.operator === OPERATOR_DID && principals?.remediation_agent === REMEDIATION_DID && principals?.effect_broker === BROKER_DID && principals?.organization === ORG_DID, "principal identity mismatch");
  require(principals?.all_distinct === true, "principals are not marked distinct");

  const configuration = objectAt(bundle.configuration);
  const map = objectAt(configuration?.map_acl);
  require(map?.private === true && map?.contract_id === CONTRACT_ID, "map ACL is not private/878");
  const remediation = objectAt(configuration?.delegations?.remediation);
  const broker = objectAt(configuration?.delegations?.broker);
  require(remediation?.did === REMEDIATION_DID && exactArray(remediation?.functions, ["reserve-incident"]) && remediation?.version_req === CONTRACT_VERSION && emptyOrAbsent(remediation?.scopes) && emptyOrAbsent(remediation?.allowed_hosts), "remediation delegation mismatch");
  require(broker?.did === BROKER_DID && exactArray(broker?.functions, BROKER_FUNCTIONS) && broker?.version_req === CONTRACT_VERSION && emptyOrAbsent(broker?.scopes) && emptyOrAbsent(broker?.allowed_hosts), "broker delegation mismatch");

  const quota = objectAt(bundle.quota_readiness);
  require(quota?.success === true && quota?.quota_error === false, "quota readiness was not successful");
  require(bundle.provider_helpers_imported === false, "provider helper import flag is not false");
  const counters = objectAt(bundle.provider_counters);
  for (const key of ["github_api_calls", "installation_tokens", "deploy_key_creates", "deploy_key_deletes", "provider_mutations"]) require(counters?.[key] === 0, `provider counter ${key} is nonzero`);

  const context = objectAt(bundle.run_context);
  const incidentId = context?.incident_id;
  require(nonemptyString(incidentId) && incidentId.startsWith("C1-R6B-R4D-R1-"), "fresh incident context is missing");
  require(context?.persisted_before_create === true, "run context was not persisted before create");
  require(context?.contract === CONTRACT_NAME && context?.version === CONTRACT_VERSION && context?.numeric_id === CONTRACT_ID, "run context contract mismatch");

  const create = responseAt(bundle.create);
  const createDetail = objectAt(create?.detail);
  require(create?.function === "create-incident" && create?.result === "WON" && create?.state === "ACTIVE", "create did not commit ACTIVE");
  require(createDetail?.incident_id === incidentId && createDetail?.effect_attempts === 0 && createDetail?.effect_claim_version === 0 && createDetail?.reservation_id === null && createDetail?.effect_claim_id === null && createDetail?.effect_start_id === null && createDetail?.max_effects === 1, "create authority is not exact");
  const initial = responseAt(bundle.initial_active_readback);
  require(initial?.function === "get-incident" && initial?.result === "FOUND", "initial active readback missing");
  authority(initial, "initial active readback", "ACTIVE", 0, 0, null, null);

  const reserve = responseAt(bundle.reservation?.response ?? bundle.reservation);
  const reservedRead = responseAt(bundle.reservation?.readback);
  require(reserve?.function === "reserve-incident" && reserve?.result === "WON" && reserve?.state === "RESERVED", "reservation did not commit");
  const reservationDetail = authority(reservedRead, "reserved readback", "RESERVED", 0, 0, null, null);
  require(nonemptyString(reservationDetail?.reservation_id) && reservationDetail?.reservation_version === 1, "reservation identity/version missing");

  const claim = objectAt(bundle.claim_owner);
  const proposal = responseAt(claim?.proposal);
  const proposalDetail = objectAt(proposal?.detail);
  const claimId = proposalDetail?.claim_id;
  require(proposal?.function === "claim-effect" && proposal?.result === "PROPOSED" && proposalDetail?.claim_version === 1 && nonemptyString(claimId), "claim proposal is not exact");
  const claimConfirmation = responseAt(claim?.confirmation);
  const confirmationDetail = objectAt(claimConfirmation?.detail);
  require(claimConfirmation?.function === "confirm-claim" && claimConfirmation?.result === "CONFIRMED" && confirmationDetail?.claim_id === claimId && confirmationDetail?.claim_version === 1, "claim owner confirmation is not exact");
  require(confirmationDetail?.github_owner === "Ticoworld" && confirmationDetail?.github_repo === "t3n-breakglass-sandbox" && confirmationDetail?.deploy_key_id === 1, "confirmed claim target mismatch");
  const claimRead = responseAt(claim?.readback);
  authority(claimRead, "claim readback", "EFFECT_CLAIMED", 0, 1, claimId, null);

  const contenders = Array.isArray(bundle.start_contenders) ? bundle.start_contenders : [];
  require(contenders.length === 2, "exactly two start contenders are required");
  const pids = contenders.map((entry: unknown) => objectAt(entry)?.ready?.pid);
  const nonces = contenders.map((entry: unknown) => objectAt(entry)?.ready?.start_nonce);
  require(new Set(pids).size === 2 && pids.every((pid: unknown) => Number.isSafeInteger(pid) && pid > 0), "start contender PIDs are not distinct/valid");
  require(new Set(nonces).size === 2 && nonces.every((nonce: unknown) => typeof nonce === "string" && /^[0-9a-f]{32}$/.test(nonce)), "start nonces are not distinct/valid");
  for (const contender of contenders) {
    const item = objectAt(contender);
    const ready = objectAt(item?.ready);
    const result = objectAt(item?.result);
    require(ready?.incident_id === incidentId && ready?.claim_id === claimId, "start contender identity does not bind incident/claim");
    require(result?.incident_id === incidentId && result?.claim_id === claimId && result?.function === "begin-effect", "start result identity mismatch");
    require(result?.result_file_hash && result.result_file_hash.length > 0, "start result is not durably hashed");
    require(noProvider(result), "start contender reports provider activity");
    const expectedStart = `start-1-${ready?.start_nonce}`;
    require(result?.effect_start_id === null || result?.effect_start_id === expectedStart, "raw start identity does not match nonce");
  }
  const barrier = objectAt(bundle.start_barrier);
  require(barrier?.both_ready === true && barrier?.identities_valid === true && barrier?.released_once === true && barrier?.incident_id === incidentId && barrier?.claim_id === claimId, "start barrier is incomplete");
  require(typeof barrier?.ready_file_hash_a === "string" && typeof barrier?.ready_file_hash_b === "string", "ready-file hashes are missing");
  const complete = objectAt(bundle.start_proposals_complete);
  require(complete?.all_completed === true && complete?.confirmations_allowed_after_marker === true && complete?.incident_id === incidentId, "start-complete marker is missing or unsafe");
  require(Array.isArray(complete?.result_file_hashes) && complete.result_file_hashes.length === 2, "start-complete result hashes missing");

  const startConfirmations = Array.isArray(bundle.start_confirmations) ? bundle.start_confirmations : [];
  require(startConfirmations.length === 2, "both physical start identities were not confirmed");
  require(startConfirmations.every((entry: unknown) => objectAt(entry)?.called_after_complete_marker === true), "confirmation occurred before completion marker");
  const confirmed = startConfirmations.filter((entry: unknown) => responseAt(entry)?.result === "CONFIRMED");
  require(confirmed.length === 1, "effect-start confirmed-owner count is not exactly one");
  require(startConfirmations.every((entry: unknown) => responseAt(entry)?.result !== "CONFIRMED" || responseAt(entry)?.function === "confirm-effect-start"), "invalid start confirmation function");
  const ownerConfirmation = objectAt(confirmed[0]);
  const confirmedStartId = ownerConfirmation?.effect_start_id;
  require(nonemptyString(confirmedStartId) && /^start-1-[0-9a-f]{32}$/.test(confirmedStartId), "confirmed start identity is missing/invalid");
  require(startConfirmations.some((entry: unknown) => responseAt(entry)?.result !== "CONFIRMED"), "non-owner start confirmation missing");

  const started = responseAt(bundle.effect_started_readback);
  const startedDetail = authority(started, "effect-start readback", "EFFECT_STARTED", 1, 1, claimId, confirmedStartId);
  require(startedDetail?.max_effects === 1 && startedDetail?.final_result_classification === null, "effect-start readback budget/classification mismatch");
  const independent = responseAt(bundle.independent_readback);
  authority(independent, "independent readback", "EFFECT_STARTED", 1, 1, claimId, confirmedStartId);

  const post = objectAt(bundle.post_start);
  const release = responseAt(post?.release);
  require(release?.function === "release-not-attempted" && release?.result !== "WON", "release reopened effect authority");
  const secondBegin = responseAt(post?.new_begin);
  require(secondBegin?.function === "begin-effect" && secondBegin?.result !== "WON", "second begin unexpectedly succeeded");
  const secondBeginConfirmation = responseAt(post?.new_begin_confirmation);
  if (secondBeginConfirmation) require(secondBeginConfirmation.result !== "CONFIRMED", "second begin established another owner");
  const freshClaim = responseAt(post?.fresh_claim);
  require(freshClaim?.function === "claim-effect" && freshClaim?.result !== "WON", "fresh claim established another owner");
  const freshClaimConfirmation = responseAt(post?.fresh_claim_confirmation);
  if (freshClaim?.result === "PROPOSED") require(freshClaimConfirmation?.result !== "CONFIRMED", "fresh claim established another owner");
  if (freshClaimConfirmation) require(freshClaimConfirmation.result !== "CONFIRMED", "fresh claim established another owner");
  const reserveAfter = responseAt(post?.reserve_after);
  require(reserveAfter?.function === "reserve-incident" && reserveAfter?.result !== "WON", "reserve restored eligibility");
  const final = responseAt(post?.final_readback);
  authority(final, "final readback", "EFFECT_STARTED", 1, 1, claimId, confirmedStartId);
  require((objectAt(final?.detail) ?? {})?.final_result_classification === null, "final state has an invented provider classification");

  const role = responseAt(bundle.role_separation?.remediation_confirm_start);
  require(role?.function === "confirm-effect-start" && role?.result !== "CONFIRMED", "remediation gained start-confirmation authority");
  require(noProvider(bundle.role_separation?.remediation_confirm_start), "role-separation check reports provider activity");
  require(bundle.historical_incidents_untouched === true, "historical incidents are not marked untouched");
  return { ok: errors.length === 0, errors };
}

export async function verifyDirectory(directory: string): Promise<{ ok: boolean; errors: string[] }> {
  const bundle = JSON.parse(await readFile(path.join(directory, "bundle.json"), "utf8")) as JsonObject;
  return verifyBundle(bundle);
}

async function main(): Promise<void> {
  const directory = process.argv[2];
  if (!directory) throw new Error("usage: c1-r6b-r4d-r1-evidence-verify.ts <run-directory>");
  const verdict = await verifyDirectory(directory);
  console.log(JSON.stringify(verdict, null, 2));
  if (!verdict.ok) process.exitCode = 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 1; });
}
