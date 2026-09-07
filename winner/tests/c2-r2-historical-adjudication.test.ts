import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { adjudicateBrokerResults } from "../c2/broker-adjudication.js";

test("the committed R2 failure facts normalize to one owner and one early loser", async () => {
  const historical = JSON.parse(await readFile(new URL("../evidence/C2-E2E-R2-FAILURE.json", import.meta.url), "utf8")) as Record<string, any>;
  const retirement = JSON.parse(await readFile(new URL("../evidence/C2-E2E-R2-POLICY-RETIREMENT.json", import.meta.url), "utf8")) as Record<string, any>;
  assert.equal(retirement.policy_id, "c2-policy:github-push-c2-e2e-r2-1788774247501-aac76008bd86");
  assert.equal(retirement.retired, true);
  const brokers = historical.brokers as Record<string, any>;
  // The high-level historical artifact intentionally omitted claim identity
  // values.  Supply only the shape-complete, non-secret identity fields that
  // the generic adjudicator requires; this test does not promote R2 to PASS.
  const brokerA = {
    ...brokers.broker_a,
    contender: "broker-a",
    authority_loaded_target: { claim_id: "historical-r2-claim-a", claim_version: 1 },
    token_minted: true,
    delete_attempted: true,
    provider_calls_after_ownership_loss: 0,
  };
  const brokerB = {
    ...brokers.broker_b,
    contender: "broker-b",
    claim: { result: "LOST" },
    ownership_confirmation: "NOT_EMITTED_AFTER_EARLY_LOSS",
    token_minted: false,
    destructive_call_count: brokers.broker_b.delete_count,
    delete_attempted: false,
    provider_calls_after_ownership_loss: brokers.broker_b.provider_calls_after_loss,
  };
  const result = adjudicateBrokerResults([brokerA, brokerB]);
  assert.equal(result.valid, true);
  assert.equal(result.confirmed_owner_count, 1);
  assert.equal(result.safe_non_owner_count, 1);
  assert.deepEqual(result.outcomes.map((outcome) => outcome.state), ["CONFIRMED_OWNER", "NON_OWNER_EARLY_CLAIM_LOST"]);
});
