import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { REQUIRED_FILES, verifyR6BRunBundle } from "../scripts/c1-r6b-r3-evidence-verify.ts";

const stateSource = await readFile(new URL("../scripts/c1-r6b-r3-state.ts", import.meta.url), "utf8");
const verifierSource = await readFile(new URL("../scripts/c1-r6b-r3-evidence-verify.ts", import.meta.url), "utf8");

const incidentId = "C1-R6B-R3-STATE-test-0001";
const operator = "did:t3n:adb9365ee986cc6d0cb4006580782fe6fc7a431f";
const remediation = "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019";
const broker = "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57";
const contract = "z:adb9365ee986cc6d0cb4006580782fe6fc7a431f:breakglass-winner-c1";
const reservationId = "reservation-test-1";
const generationOneClaim = "claim-test-1";
const generationTwoClaim = "claim-test-2";

function authority(state: string, detail: Record<string, unknown>): Record<string, unknown> {
  return { phase: "operator observation", incident_id: incidentId, response: { result: "FOUND", state, detail }, provider_operations: 0 };
}

function roleResult(role: string, did: string, functionName: string, result: string, state?: string, detail: Record<string, unknown> = {}, expectedClaimVersion?: number): Record<string, unknown> {
  return {
    phase: "role observation",
    role,
    did,
    function: functionName,
    contract,
    version: "2.0.3",
    incident_id: incidentId,
    guest_reached: true,
    application_result: result,
    application_note: result === "DENIED" ? "bounded application denial" : null,
    response: { result, state, detail, effect_attempts: state === "EFFECT_STARTED" ? detail.effect_attempts : undefined, provider_http: { attempted: false, count: 0 } },
    provider_operations: 0,
    ...(expectedClaimVersion === undefined ? {} : { expected_claim_version: expectedClaimVersion }),
  };
}

function completeBundle(): Record<string, Record<string, unknown>> {
  const active = { status: "ACTIVE", effect_attempts: 0, effect_claim_version: 0, reservation_id: null, effect_claim_id: null, final_result_classification: null };
  const reserved = { status: "RESERVED", reservation_version: 1, reservation_id: reservationId, effect_attempts: 0, effect_claim_version: 0, effect_claim_id: null };
  const claimedOne = { status: "EFFECT_CLAIMED", effect_attempts: 0, effect_claim_version: 1, effect_claim_id: generationOneClaim };
  const retry = { status: "READY_RETRY", effect_attempts: 0, effect_claim_version: 1, effect_claim_id: null };
  const claimedTwo = { status: "EFFECT_CLAIMED", effect_attempts: 0, effect_claim_version: 2, effect_claim_id: generationTwoClaim };
  const started = { status: "EFFECT_STARTED", effect_attempts: 1, max_effects: 1, effect_claim_version: 2, effect_claim_id: generationTwoClaim, reservation_id: reservationId, final_result_classification: null };
  return {
    "00-run-context.json": {
      phase: "C1-R6B-R3", run_id: "C1-R6B-R3-test", incident_id: incidentId, persisted_before_create: true,
      contract: { name: contract, version: "2.0.3", numeric_contract_id: 877 },
      principals: { operator, remediation_agent: remediation, effect_broker: broker, all_distinct: true },
      provider_counters: { github_api_calls: 0, github_installation_tokens: 0, deploy_key_creates: 0, deploy_key_deletes: 0, provider_mutations: 0 },
    },
    "01-quota-readiness.json": { incident_id: "C1-R6B-R3-STATE-quota-test-0001", response: { result: "DENIED", note: "incident authority does not exist" }, provider_operations: 0 },
    "02-create.json": { incident_id: incidentId, response: { result: "WON", state: "ACTIVE", detail: active }, provider_operations: 0 },
    "03-initial-active-read.json": { incident_id: incidentId, response: { result: "FOUND", state: "ACTIVE", detail: active }, provider_operations: 0 },
    "04-reserve.json": roleResult("remediation", remediation, "reserve-incident", "WON", "RESERVED", reserved),
    "05-reserved-read.json": authority("RESERVED", reserved),
    "06-race-barrier.json": { incident_id: incidentId, common_barrier_ready: true, released_at_unix_ms: 1002, contenders: [{ name: "broker-a", pid: 101 }, { name: "broker-b", pid: 102 }], provider_operations: 0 },
    "07-race-broker-a.json": { incident_id: incidentId, pid: 101, did: broker, contract, version: "2.0.3", expected_claim_version: 0, claim_outcome: "CLAIM_WON", claim_id: generationOneClaim, claim_version: 1, token_minted: false, destructive_call_count: 0, provider_operations: 0 },
    "08-race-broker-b.json": { incident_id: incidentId, pid: 102, did: broker, contract, version: "2.0.3", expected_claim_version: 0, claim_outcome: "CLAIM_LOST", claim_id: null, token_minted: false, destructive_call_count: 0, provider_operations: 0 },
    "09-post-race-read.json": authority("EFFECT_CLAIMED", claimedOne),
    "10-release.json": roleResult("broker", broker, "release-not-attempted", "WON", "READY_RETRY", retry),
    "11-post-release-read.json": authority("READY_RETRY", retry),
    "12-stale-claim.json": { incident_id: incidentId, did: broker, expected_claim_version: 0, claim_outcome: "CLAIM_LOST", claim_id: null, token_minted: false, destructive_call_count: 0, provider_operations: 0 },
    "13-post-stale-read.json": authority("READY_RETRY", retry),
    "14-fresh-claim.json": roleResult("broker", broker, "claim-effect", "WON", "EFFECT_CLAIMED", { ...claimedTwo, claim_id: generationTwoClaim, claim_version: 2 }, 1),
    "15-post-fresh-read.json": authority("EFFECT_CLAIMED", claimedTwo),
    "16-remediation-begin.json": { ...roleResult("remediation", remediation, "begin-effect", "DENIED"), application_note: "caller is not the effect broker", response: { result: "DENIED", note: "caller is not the effect broker" } },
    "17-post-remediation-begin-read.json": authority("EFFECT_CLAIMED", claimedTwo),
    "18-broker-begin.json": roleResult("broker", broker, "begin-effect", "WON", "EFFECT_STARTED", { ...started, effect_attempts: 1 }),
    "19-post-begin-read.json": authority("EFFECT_STARTED", started),
    "20-release-after-begin.json": roleResult("broker", broker, "release-not-attempted", "DENIED"),
    "21-begin-after-begin.json": roleResult("broker", broker, "begin-effect", "DENIED"),
    "22-claim-after-begin.json": roleResult("broker", broker, "claim-effect", "LOST"),
    "23-reserve-after-begin.json": roleResult("remediation", remediation, "reserve-incident", "DENIED"),
    "24-final-authority-read.json": authority("EFFECT_STARTED", started),
    "25-host-activity.json": { incident_id: incidentId, classification: "HOST_ACTIVITY", observed_at_unix_ms: 2000, response: { entries: [] }, provider_operations: 0 },
    "26-provider-counters.json": { incident_id: incidentId, github_api_calls: 0, github_installation_tokens: 0, deploy_key_creates: 0, deploy_key_deletes: 0, provider_mutations: 0, provider_helpers_imported: false },
    "27-run-complete.json": { incident_id: incidentId, live_sequence_complete: true, all_required_primary_files_present: true, claim_version_final: 2, effect_attempts_final: 1, provider_operations: 0 },
  };
}

async function withFixture(mutate: (bundle: Record<string, Record<string, unknown>>) => void): Promise<Awaited<ReturnType<typeof verifyR6BRunBundle>>> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "c1-r6b-r3-verifier-"));
  try {
    const bundle = completeBundle();
    mutate(bundle);
    for (const file of REQUIRED_FILES) {
      if (bundle[file] !== undefined) await writeFile(path.join(directory, file), `${JSON.stringify(bundle[file], null, 2)}\n`, "utf8");
    }
    return await verifyR6BRunBundle(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test("R3 runner persists context before create and stays provider-free", () => {
  assert.equal(stateSource.includes("github-app"), false);
  assert.equal(stateSource.includes("prepare-target"), false);
  assert.equal(stateSource.includes("broker/run"), false);
  assert.equal(stateSource.includes("GITHUB_APP_PRIVATE_KEY_PATH"), true);
  const contextWrite = stateSource.indexOf('persistPrimary("00-run-context.json", activeRun, false)');
  const createCall = stateSource.indexOf('operatorCall("02-create.json", "create-incident"');
  assert.ok(contextWrite >= 0 && createCall > contextWrite);
  for (const file of REQUIRED_FILES) assert.equal(stateSource.includes(file), true, file);
});

test("R3 verifier has no network or connector dependency", () => {
  assert.doesNotMatch(verifierSource, /@terminal3|connectTenant|invokeC1|fetch\(|github-app|prepare-target|broker\/run/);
  assert.match(verifierSource, /export async function verifyR6BRunBundle/);
});

test("complete evidence-first R3 bundle passes independent verification", async () => {
  const result = await withFixture(() => undefined);
  assert.equal(result.pass, true, result.errors.join(", "));
  assert.equal(result.status, "PASS");
});

const negativeCases: Array<[string, (bundle: Record<string, Record<string, unknown>>) => void]> = [
  ["two winners", (bundle) => { bundle["08-race-broker-b.json"].claim_outcome = "CLAIM_WON"; bundle["08-race-broker-b.json"].claim_id = "second"; }],
  ["loser token minted", (bundle) => { bundle["08-race-broker-b.json"].token_minted = true; }],
  ["stale generation won", (bundle) => { bundle["12-stale-claim.json"].claim_outcome = "CLAIM_WON"; }],
  ["remediation begin won", (bundle) => { bundle["16-remediation-begin.json"].application_result = "WON"; bundle["16-remediation-begin.json"].response = { result: "WON" }; }],
  ["broker begin denied", (bundle) => { bundle["18-broker-begin.json"].application_result = "DENIED"; bundle["18-broker-begin.json"].response = { result: "DENIED" }; }],
  ["effect budget reset", (bundle) => { (bundle["24-final-authority-read.json"].response as Record<string, any>).detail.effect_attempts = 0; }],
  ["post-begin claim won", (bundle) => { bundle["22-claim-after-begin.json"].application_result = "WON"; }],
  ["provider counter nonzero", (bundle) => { bundle["26-provider-counters.json"].provider_mutations = 1; }],
  ["final authority missing", (bundle) => { delete bundle["24-final-authority-read.json"]; }],
  ["provider operation nonzero", (bundle) => { bundle["03-initial-active-read.json"].provider_operations = 1; }],
];

for (const [label, mutate] of negativeCases) {
  test(`R3 verifier rejects ${label}`, async () => {
    const result = await withFixture(mutate);
    assert.equal(result.pass, false);
    assert.equal(result.status, "R6B_R3_EVIDENCE_INSUFFICIENT");
  });
}
