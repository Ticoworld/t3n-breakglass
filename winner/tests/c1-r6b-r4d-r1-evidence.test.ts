import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { verifyBundle } from "../scripts/c1-r6b-r4d-r1-evidence-verify.js";

const incidentId = "C1-R6B-R4D-R1-test-0001";
const claimId = "claim-1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const secondClaimId = "claim-2-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const nonceA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const nonceB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const startA = `start-1-${nonceA}`;
const startB = `start-1-${nonceB}`;

function authority(state: string, attempts: number, claimVersion: number, effectClaimId: string | null, effectStartId: string | null, extra: Record<string, unknown> = {}) {
  return {
    function: "get-incident",
    result: "FOUND",
    state,
    detail: {
      incident_id: incidentId,
      effect_attempts: attempts,
      max_effects: 1,
      effect_claim_version: claimVersion,
      effect_claim_id: effectClaimId,
      effect_start_id: effectStartId,
      final_result_classification: null,
      ...extra,
    },
  };
}

function denied(functionName: string, note = "incident authority does not exist") {
  return { function: functionName, result: "DENIED", note, provider_operations: 0, token_minted: false, destructive_call_count: 0 };
}

function fixture(): Record<string, any> {
  const create = {
    function: "create-incident",
    result: "WON",
    state: "ACTIVE",
    detail: { incident_id: incidentId, effect_attempts: 0, max_effects: 1, effect_claim_version: 0, reservation_id: null, effect_claim_id: null, effect_start_id: null },
  };
  const claimConfirmation = {
    function: "confirm-claim",
    result: "CONFIRMED",
    detail: { claim_id: claimId, claim_version: 1, github_owner: "Ticoworld", github_repo: "t3n-breakglass-sandbox", deploy_key_id: 1 },
  };
  return {
    active_contract: { name: "z:adb9365ee986cc6d0cb4006580782fe6fc7a431f:breakglass-winner-c1", version: "2.0.4", numeric_id: 878, status: "active", wasm_bytes: 227011, wasm_sha256: "ca7032b112b837b06e4334c10bca8820447f6ea1756b74db9bccd3181ad4d5d0" },
    principals: { operator: "did:t3n:adb9365ee986cc6d0cb4006580782fe6fc7a431f", remediation_agent: "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019", effect_broker: "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57", organization: "did:t3n:3c63f09271c0d9184abbcccbfae28698a8f4a912", all_distinct: true },
    configuration: {
      map_acl: { private: true, contract_id: 878 },
      delegations: {
        remediation: { did: "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019", functions: ["reserve-incident"], scopes: [], allowed_hosts: [], version_req: "2.0.4" },
        broker: { did: "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57", functions: ["claim-effect", "confirm-claim", "release-not-attempted", "begin-effect", "confirm-effect-start", "finalize-effect", "reconcile-effect"], scopes: [], allowed_hosts: [], version_req: "2.0.4" },
      },
    },
    quota_readiness: { success: true, quota_error: false },
    provider_helpers_imported: false,
    provider_counters: { github_api_calls: 0, installation_tokens: 0, deploy_key_creates: 0, deploy_key_deletes: 0, provider_mutations: 0 },
    run_context: { incident_id: incidentId, persisted_before_create: true, contract: "z:adb9365ee986cc6d0cb4006580782fe6fc7a431f:breakglass-winner-c1", version: "2.0.4", numeric_id: 878 },
    create,
    initial_active_readback: authority("ACTIVE", 0, 0, null, null),
    reservation: { response: { function: "reserve-incident", result: "WON", state: "RESERVED", detail: { reservation_id: "reservation-1", reservation_version: 1, effect_attempts: 0, effect_claim_version: 0, effect_claim_id: null, effect_start_id: null } }, readback: authority("RESERVED", 0, 0, null, null, { reservation_id: "reservation-1", reservation_version: 1 }) },
    claim_owner: { proposal: { function: "claim-effect", result: "PROPOSED", detail: { claim_id: claimId, claim_version: 1 } }, confirmation: claimConfirmation, readback: authority("EFFECT_CLAIMED", 0, 1, claimId, null) },
    start_barrier: { both_ready: true, identities_valid: true, released_once: true, incident_id: incidentId, claim_id: claimId, ready_file_hash_a: "hash-a", ready_file_hash_b: "hash-b" },
    start_contenders: [
      { ready: { pid: 101, incident_id: incidentId, claim_id: claimId, start_nonce: nonceA }, result: { incident_id: incidentId, claim_id: claimId, function: "begin-effect", result: "WON", effect_start_id: startA, result_file_hash: "result-a" } },
      { ready: { pid: 102, incident_id: incidentId, claim_id: claimId, start_nonce: nonceB }, result: { incident_id: incidentId, claim_id: claimId, function: "begin-effect", result: "DENIED", effect_start_id: null, result_file_hash: "result-b" } },
    ],
    start_proposals_complete: { all_completed: true, confirmations_allowed_after_marker: true, incident_id: incidentId, result_file_hashes: ["result-a", "result-b"] },
    start_confirmations: [
      { effect_start_id: startA, called_after_complete_marker: true, response: { function: "confirm-effect-start", result: "CONFIRMED" } },
      { effect_start_id: startB, called_after_complete_marker: true, response: { function: "confirm-effect-start", result: "NOT_OWNER" } },
    ],
    effect_started_readback: authority("EFFECT_STARTED", 1, 1, claimId, startA),
    independent_readback: authority("EFFECT_STARTED", 1, 1, claimId, startA),
    post_start: {
      release: denied("release-not-attempted", "effect already started"),
      new_begin: denied("begin-effect", "effect already started"),
      fresh_claim: { function: "claim-effect", result: "LOST", provider_operations: 0, token_minted: false, destructive_call_count: 0 },
      reserve_after: denied("reserve-incident", "effect already started"),
      final_readback: authority("EFFECT_STARTED", 1, 1, claimId, startA),
    },
    role_separation: { remediation_confirm_start: denied("confirm-effect-start", "caller is not the effect broker") },
    historical_incidents_untouched: true,
  };
}

test("complete synthetic R4D-R1 bundle passes the offline verifier", () => {
  const verdict = verifyBundle(fixture());
  assert.deepEqual(verdict, { ok: true, errors: [] });
});

const negativeCases: Array<[string, (bundle: Record<string, any>) => void]> = [
  ["duplicate start nonces", (b) => { b.start_contenders[1].ready.start_nonce = nonceA; }],
  ["same PID", (b) => { b.start_contenders[1].ready.pid = 101; }],
  ["confirmation before completion marker", (b) => { b.start_confirmations[0].called_after_complete_marker = false; }],
  ["zero confirmed owners", (b) => { b.start_confirmations[0].response.result = "NOT_OWNER"; }],
  ["two confirmed owners", (b) => { b.start_confirmations[1].response.result = "CONFIRMED"; }],
  ["final attempts zero", (b) => { b.post_start.final_readback.detail.effect_attempts = 0; }],
  ["final start ID mismatch", (b) => { b.post_start.final_readback.detail.effect_start_id = startB; }],
  ["release after start WON", (b) => { b.post_start.release.result = "WON"; }],
  ["second begin establishes owner", (b) => { b.post_start.new_begin.result = "WON"; }],
  ["fresh claim establishes owner", (b) => { b.post_start.fresh_claim.result = "WON"; }],
  ["reserve restores eligibility", (b) => { b.post_start.reserve_after.result = "WON"; }],
  ["provider counter nonzero", (b) => { b.provider_counters.provider_mutations = 1; }],
  ["missing final authority", (b) => { b.post_start.final_readback = null; }],
];

for (const [label, mutate] of negativeCases) {
  test(`offline verifier rejects ${label}`, () => {
    const candidate = structuredClone(fixture());
    mutate(candidate);
    assert.equal(verifyBundle(candidate).ok, false);
  });
}

test("R4D-R1 harness is provider-free and confirms only after both results persist", async () => {
  const [runner, contender, verifier] = await Promise.all([
    readFile(new URL("../scripts/c1-r6b-r4d-r1-live.ts", import.meta.url), "utf8"),
    readFile(new URL("../scripts/c1-r6b-r4d-r1-start-contender.ts", import.meta.url), "utf8"),
    readFile(new URL("../scripts/c1-r6b-r4d-r1-evidence-verify.ts", import.meta.url), "utf8"),
  ]);
  assert.doesNotMatch(runner, /github-app|prepare-target|mintInstallationToken|deleteKey/);
  assert.doesNotMatch(contender, /github-app|prepare-target|mintInstallationToken|deleteKey/);
  assert.doesNotMatch(verifier, /fetch\(|https?:\/\/|@terminal3|github-app/);
  assert.match(runner, /start-proposals-complete\.json/);
  assert.ok(runner.indexOf("start-proposals-complete.json") < runner.indexOf('"confirm-effect-start"'));
  assert.match(contender, /randomBytes\(16\)\.toString\("hex"\)/);
  assert.match(contender, /writeAtomicJson\(readyFile/);
  assert.match(contender, /writeAtomicJson\(resultFile/);
});
