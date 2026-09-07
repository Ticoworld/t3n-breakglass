import assert from "node:assert/strict";
import test from "node:test";
import { adjudicateBrokerResult, adjudicateBrokerResults } from "../c2/broker-adjudication.js";

function owner(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    contender: "broker-a",
    claim_outcome: "CLAIM_WON",
    ownership_confirmation: "CONFIRMED",
    authority_loaded_target: { claim_id: "claim-a", claim_version: 1 },
    token_minted: true,
    provider_credential_mint_count: 1,
    destructive_call_count: 1,
    delete_attempted: true,
    provider_calls_after_ownership_loss: 0,
    ...overrides,
  };
}

function earlyLost(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    contender: "broker-b",
    claim: { result: "LOST" },
    claim_outcome: "CLAIM_LOST",
    token_minted: false,
    provider_credential_mint_count: 0,
    destructive_call_count: 0,
    delete_attempted: false,
    provider_calls_after_ownership_loss: 0,
    ...overrides,
  };
}

function confirmRejected(): Record<string, unknown> {
  return {
    ...earlyLost(),
    claim_proposal: { claim_id: "claim-b", claim_version: 1 },
    claim_confirmation: { result: "LOST", detail: {} },
    ownership_confirmation: "NOT_OWNER",
  };
}

test("normalizes the exact R2 broker documents and enforces one owner", () => {
  assert.equal(adjudicateBrokerResult(owner()).state, "CONFIRMED_OWNER");
  assert.equal(adjudicateBrokerResult(earlyLost({ ownership_confirmation: undefined })).state, "NON_OWNER_EARLY_CLAIM_LOST");
  assert.equal(adjudicateBrokerResult(confirmRejected()).state, "NON_OWNER_CONFIRM_REJECTED");
  const race = adjudicateBrokerResults([owner(), earlyLost()]);
  assert.equal(race.valid, true);
  assert.equal(race.confirmed_owner_count, 1);
  assert.equal(race.safe_non_owner_count, 1);
  assert.equal(race.owner_contender, "broker-a");
});

test("early claim loss does not require confirmation-stage NOT_OWNER", () => {
  const result = adjudicateBrokerResults([owner(), earlyLost({ ownership_confirmation: undefined })]);
  assert.deepEqual(result.outcomes.map((item) => item.state), ["CONFIRMED_OWNER", "NON_OWNER_EARLY_CLAIM_LOST"]);
  assert.equal(result.valid, true);
});

test("the historical sanitized early-loss marker normalizes only as an explicit no-confirmation state", () => {
  const result = adjudicateBrokerResults([owner(), earlyLost({ ownership_confirmation: "NOT_EMITTED_AFTER_EARLY_LOSS" })]);
  assert.equal(result.valid, true);
  assert.equal(result.outcomes[1].state, "NON_OWNER_EARLY_CLAIM_LOST");
  assert.equal(adjudicateBrokerResult(earlyLost({ ownership_confirmation: "NOT_OWNERISH" })).state, "INVALID_INDETERMINATE");
});

test("non-owner provider-boundary violations fail closed", () => {
  for (const mutation of [
    { token_minted: true },
    { destructive_call_count: 1 },
    { destructive_call_count: 0, delete_count: 1 },
    { provider_calls_after_ownership_loss: 1 },
    { delete_attempted: true },
  ]) {
    assert.equal(adjudicateBrokerResults([owner(), earlyLost(mutation)]).valid, false);
    assert.equal(adjudicateBrokerResult(earlyLost(mutation)).state, "INVALID_INDETERMINATE");
  }
});

test("duplicate, absent, contradictory, and indeterminate ownership fail closed", () => {
  const cases: Array<Record<string, unknown>[]> = [
    [owner(), owner({ contender: "broker-b", authority_loaded_target: { claim_id: "claim-b", claim_version: 1 } })],
    [earlyLost(), { ...earlyLost({ contender: "broker-c" }), ownership_confirmation: undefined }],
    [owner({ ownership_confirmation: undefined }) , earlyLost()],
    [owner({ claim_outcome: "CLAIM_LOST" }), earlyLost()],
    [owner({ claim_outcome: "CLAIM_WON", claim: { result: "LOST" } }), earlyLost()],
    [owner({ authority_loaded_target: undefined, claim_confirmation: undefined }), earlyLost()],
    [owner(), earlyLost({ contender: "broker-a" })],
    [{ contender: "broker-b", claim: { result: "LOST" }, token_minted: false, provider_credential_mint_count: 0, destructive_call_count: 0, provider_calls_after_ownership_loss: 0 }, owner()],
    [{ contender: "broker-b", claim: { result: "ERROR" }, claim_outcome: "CLAIM_LOST", claim_proposal: { claim_id: "claim-b", claim_version: 1 }, claim_confirmation: { error: "unclear" }, token_minted: false, provider_credential_mint_count: 0, destructive_call_count: 0, provider_calls_after_ownership_loss: 0 }, owner()],
    [{ contender: "broker-b", claim_outcome: "MAYBE", token_minted: false, provider_credential_mint_count: 0, destructive_call_count: 0, provider_calls_after_ownership_loss: 0 }, owner()],
  ];
  for (const documents of cases) assert.equal(adjudicateBrokerResults(documents).valid, false);
});

test("input order cannot change owner adjudication", () => {
  const forward = adjudicateBrokerResults([owner(), earlyLost()]);
  const reversed = adjudicateBrokerResults([earlyLost(), owner()]);
  assert.equal(reversed.valid, forward.valid);
  assert.equal(reversed.confirmed_owner_count, forward.confirmed_owner_count);
  assert.deepEqual(reversed.outcomes.map((item) => item.state).sort(), forward.outcomes.map((item) => item.state).sort());
});
