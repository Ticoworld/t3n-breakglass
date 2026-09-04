import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const state = await readFile(new URL("../scripts/c1-r6b-state.ts", import.meta.url), "utf8");
const principal = await readFile(new URL("../scripts/c1-r6b-principal-call.ts", import.meta.url), "utf8");
const contender = await readFile(new URL("../scripts/c1-r6b-claim-contender.ts", import.meta.url), "utf8");

test("R6B state proof is provider-free and fixed to the registered 2.0.3/877 contract", () => {
  assert.match(state, /CONTRACT_VERSION/);
  assert.match(state, /CONTRACT_NUMERIC_ID = 877/);
  assert.match(state, /provider_counters/);
  assert.doesNotMatch(state, /github-app|prepare-target|broker\/run|mintInstallationToken|deleteKey/);
  assert.match(state, /create-incident/);
  assert.match(state, /begin-effect/);
  assert.match(state, /C1-R6B-R1 quota-aware/);
  assert.match(state, /PACING_MS = 70_000/);
  assert.match(state, /R6B_R1_QUOTA_NOT_READY/);
  assert.match(state, /quota-readiness/);
  assert.doesNotMatch(state, /routeChecks|routeIdsBeforeState|state_absence_before/);
  assert.match(state, /C1-R6B-R1-STATE-FAILURE\.json/);
  assert.match(state, /C1-R6B-R1-STATE-PROOF\.json/);
  assert.doesNotMatch(state, /C1-R6B-STATE-(FAILURE|PROOF)\.json/);
});

test("R6B state proof enforces fenced race, release, stale loss, and committed begin", () => {
  assert.match(state, /C1_R6B_EXPECTED_CLAIM_VERSION: "0"/);
  assert.match(state, /expected_claim_version: 1/);
  assert.match(state, /expected_claim_version: 2/);
  assert.match(state, /status: "EFFECT_CLAIMED"/);
  assert.match(state, /status: "READY_RETRY"/);
  assert.match(state, /status: "EFFECT_STARTED"/);
  assert.match(state, /effect_attempts: 1/);
  assert.match(state, /activeRunContext = context/);
  assert.match(state, /\.\.\.\(activeRunContext \?\? /);
  assert.match(state, /after_quota_readiness/);
  assert.match(state, /after_reservation/);
  assert.match(state, /after_generation_zero_race/);
  assert.match(state, /after_stale_generation_check/);
  assert.match(state, /after_fresh_claim_and_remediation_denial/);
  assert.match(state, /after_committed_begin_effect/);
  assert.match(state, /application_result !== "WON"/);
  const create = state.indexOf('operatorCall("create-incident"');
  const persisted = state.indexOf("context.run_context_persisted_before_create = true");
  const contextWrite = state.indexOf("await writeAtomicJson(RUN_CONTEXT_PATH, context);", persisted);
  assert.ok(create >= 0 && persisted >= 0 && contextWrite > persisted && contextWrite < create, "run context must be persisted before create-incident");
});

test("R6B principal helper has no credential fallback and no provider imports", () => {
  assert.match(principal, /role === "remediation"/);
  assert.match(principal, /role === "broker"/);
  assert.match(principal, /refuses operator\/provider credentials/);
  assert.doesNotMatch(principal, /github-app|fetch\(/);
  assert.match(contender, /connectC1Principal\("EFFECT_BROKER_T3N_API_KEY", "EFFECT_BROKER_DID"\)/);
  assert.match(contender, /provider_operations: 0/);
});
