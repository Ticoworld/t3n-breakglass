import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { adjudicateBrokerResult, adjudicateBrokerResults } from "../c2/broker-adjudication.js";
import { adjudicateClosedReplayBrokerResult, closedTerminalAuthorityUnchanged } from "../c2/closed-replay-adjudication.js";

const TARGET_ID = 162525303;
const INCIDENT_ID = "C2-c2-policy:github-push-c2-e2e-r2-1788774247501-aac76008bd86-a342e0161cb466d736e34bb3";
const EXPIRY_NOTE = "incident expired according to cluster time";

function terminal(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    result: "FOUND",
    state: "CLOSED",
    effect_attempts: 1,
    final_result_classification: "VERIFIED_ABSENT",
    deploy_key_id: TARGET_ID,
    detail: {
      action: "revoke_github_deploy_key",
      github_owner: "Ticoworld",
      github_repo: "t3n-breakglass-sandbox",
      deploy_key_id: TARGET_ID,
      remediation_agent_did: "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019",
      effect_broker_did: "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57",
      effect_attempts: 1,
      reservation_id: "reservation-1",
      reservation_version: 1,
      effect_claim_id: "claim-1",
      effect_claim_version: 1,
      effect_start_id: "start-1",
      final_result_classification: "VERIFIED_ABSENT",
    },
    ...overrides,
  };
}

function denied(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    contender: "r2b-r3-closed-replay",
    incident_id: INCIDENT_ID,
    claim_outcome: "CLAIM_DENIED",
    claim: { result: "DENIED", function: "claim-effect", state: "CLOSED", incident_id: INCIDENT_ID, detail: {}, note: EXPIRY_NOTE },
    token_minted: false,
    provider_credential_mint_count: 0,
    destructive_call_count: 0,
    delete_attempted: false,
    provider_calls_after_ownership_loss: 0,
    ...overrides,
  };
}

test("historical R2 denial is invalid in a normal race but safe in CLOSED replay", () => {
  const result = denied();
  assert.equal(adjudicateBrokerResult(result).state, "INVALID_INDETERMINATE");
  assert.equal(adjudicateBrokerResults([{ contender: "owner", claim_outcome: "CLAIM_WON", ownership_confirmation: "CONFIRMED", authority_loaded_target: { claim_id: "claim-owner", claim_version: 1 }, token_minted: true, provider_credential_mint_count: 1, destructive_call_count: 1, delete_attempted: true, provider_calls_after_ownership_loss: 0 }, result]).valid, false);
  const adjudication = adjudicateClosedReplayBrokerResult(terminal(), result);
  assert.deepEqual(adjudication, { valid: true, state: "SAFE_CLOSED_REPLAY_DENIED", reason: EXPIRY_NOTE });
});

test("closed replay supports a safe LOST result without widening normal races", () => {
  const result = denied({ claim_outcome: "CLAIM_LOST", claim: { result: "LOST", function: "claim-effect", state: "CLOSED", incident_id: INCIDENT_ID, detail: {}, note: "effect budget is not exactly one" } });
  assert.equal(adjudicateClosedReplayBrokerResult(terminal(), result).state, "SAFE_CLOSED_REPLAY_LOST");
  // The raw CLAIM_LOST shape remains the existing normal early-loss state;
  // the new SAFE_CLOSED_REPLAY_LOST label is produced only by the
  // context-specific adjudicator and is never added to the global race law.
  assert.equal(adjudicateBrokerResult(result).state, "NON_OWNER_EARLY_CLAIM_LOST");
});

test("closed replay fails closed for invalid terminal snapshots and unsafe broker results", () => {
  const terminalFailures: Array<Record<string, unknown>> = [
    { state: "RESERVED" },
    { state: "EFFECT_STARTED" },
    { effect_attempts: 0 },
    { final_result_classification: "PROVIDER_ACKNOWLEDGED" },
    { deploy_key_id: TARGET_ID + 1 },
    { detail: { effect_claim_id: undefined } },
    { detail: { effect_start_id: undefined } },
  ];
  for (const change of terminalFailures) assert.equal(adjudicateClosedReplayBrokerResult(terminal(change), denied()).valid, false);

  const brokerFailures: Array<Record<string, unknown>> = [
    { claim: undefined },
    { claim: { result: "DENIED", function: "claim-effect", state: "CLOSED", detail: {}, note: "caller is not the effect broker" } },
    { claim: { result: "DENIED", function: "claim-effect", state: "CLOSED", detail: {}, note: "contender_nonce is invalid" } },
    { claim: { result: "DENIED", function: "claim-effect", state: "ACTIVE", detail: {}, note: EXPIRY_NOTE } },
    { claim: { result: "DENIED", function: "claim-effect", state: "CLOSED", detail: { claim_id: "proposal", claim_version: 1 }, note: EXPIRY_NOTE } },
    { claim_proposal: { claim_id: "proposal", claim_version: 1 } },
    { authority_loaded_target: { claim_id: "claim", claim_version: 1 } },
    { ownership_confirmation: "CONFIRMED" },
    { token_minted: true },
    { provider_credential_mint_count: 1 },
    { destructive_call_count: 1 },
    { delete_count: 1 },
    { delete_attempted: true },
    { provider_calls_after_ownership_loss: 1 },
    { claim_outcome: undefined },
    { claim_outcome: "CLAIM_MAYBE" },
  ];
  for (const change of brokerFailures) assert.equal(adjudicateClosedReplayBrokerResult(terminal(), denied(change)).valid, false);
});

test("terminal-after authority changes are detected", () => {
  const before = terminal();
  const after = terminal({ effect_attempts: 2 });
  assert.equal(closedTerminalAuthorityUnchanged(before, after), false);
  assert.equal(closedTerminalAuthorityUnchanged(before, terminal()), true);
});

test("broker production runner labels DENIED distinctly and does not confirm it", async () => {
  const source = await readFile(new URL("../broker/run.ts", import.meta.url), "utf8");
  assert.match(source, /response\.result === "DENIED" \? "CLAIM_DENIED"/);
  assert.match(source, /if \(!parsed\.proposed\)/);
});
