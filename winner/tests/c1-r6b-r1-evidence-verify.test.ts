import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { verifyR6BRun } from "../scripts/c1-r6b-r1-evidence-verify.ts";

const context = JSON.parse(await readFile(new URL("../evidence/C1-R6B-R1-RUN-CONTEXT.json", import.meta.url), "utf8")) as Record<string, any>;
const failure = JSON.parse(await readFile(new URL("../evidence/C1-R6B-R1-STATE-FAILURE.json", import.meta.url), "utf8")) as Record<string, any>;

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function completeFixture(): Record<string, any> {
  const fixture = clone(context);
  const winner = fixture.race.contenders.find((entry: Record<string, any>) => entry.claim_outcome === "CLAIM_WON");
  const freshClaimId = fixture.fresh_claim.response.detail.claim_id;
  fixture.race.common_barrier.released_at_unix_ms = fixture.race.common_barrier.ready_files.reduce((max: number, entry: Record<string, any>) => Math.max(max, entry.ready_at_unix_ms), 0) + 1;
  fixture.after_race = { state: "EFFECT_CLAIMED", detail: { effect_attempts: 0, effect_claim_version: 1, effect_claim_id: winner.claim_id } };
  fixture.post_begin_denials = {
    release: { application_result: "DENIED" },
    begin_again: { application_result: "DENIED" },
    claim_again: { application_result: "LOST" },
    reserve_again: { application_result: "DENIED" },
  };
  fixture.final_state = {
    state: "EFFECT_STARTED",
    detail: {
      effect_attempts: 1,
      max_effects: 1,
      effect_claim_version: 2,
      effect_claim_id: freshClaimId,
      reservation_id: fixture.after_begin.detail.reservation_id,
      final_result_classification: null,
    },
  };
  fixture.activity = { classification: "HOST_ACTIVITY", data: { entries: [] } };
  return fixture;
}

test("exact retained R6B-R1 evidence is rejected when primary result objects are missing", () => {
  const result = verifyR6BRun(context, failure);
  assert.equal(result.pass, false);
  assert.equal(result.status, "R6B_R2_EVIDENCE_INSUFFICIENT");
  assert.ok(result.errors.includes("post_race_authority"));
  assert.ok(result.errors.includes("post_begin_denials"));
  assert.ok(result.errors.includes("final_authority"));
  assert.ok(result.errors.includes("host_activity_retained"));
});

test("a complete offline fixture passes the underlying R6B-R1 checks", () => {
  const result = verifyR6BRun(completeFixture(), failure);
  assert.equal(result.pass, true, result.errors.join(", "));
  assert.equal(result.status, "PASS");
});

const negativeCases: Array<[string, (fixture: Record<string, any>) => void]> = [
  ["two winners", (fixture) => {
    const loser = fixture.race.contenders.find((entry: Record<string, any>) => entry.claim_outcome === "CLAIM_LOST");
    loser.claim_outcome = "CLAIM_WON";
    loser.claim_id = "second-claim";
    loser.claim_version = 1;
  }],
  ["loser token minted", (fixture) => {
    const loser = fixture.race.contenders.find((entry: Record<string, any>) => entry.claim_outcome === "CLAIM_LOST");
    loser.token_minted = true;
  }],
  ["stale generation won", (fixture) => { fixture.stale_contender.result.claim_outcome = "CLAIM_WON"; }],
  ["remediation begin won", (fixture) => {
    fixture.remediation_begin_negative.application_result = "WON";
    fixture.remediation_begin_negative.response.result = "WON";
  }],
  ["broker begin denied", (fixture) => { fixture.begin.response.result = "DENIED"; }],
  ["final effect budget reset", (fixture) => { fixture.final_state.detail.effect_attempts = 0; }],
  ["post-begin claim won", (fixture) => { fixture.post_begin_denials.claim_again.application_result = "WON"; }],
  ["provider counter nonzero", (fixture) => { fixture.provider_counters.provider_mutations = 1; }],
  ["final authority missing", (fixture) => { delete fixture.final_state; }],
];

for (const [label, mutate] of negativeCases) {
  test(`offline verifier rejects ${label}`, () => {
    const fixture = completeFixture();
    mutate(fixture);
    assert.equal(verifyR6BRun(fixture, failure).pass, false);
  });
}
