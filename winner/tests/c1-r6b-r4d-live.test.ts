import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);
const read = (relative: string) => readFile(new URL(relative, root), "utf8");
const [runner, evidence] = await Promise.all([
  read("scripts/c1-r6b-r4d-live.ts"),
  read("evidence/C1-R6B-R4D-LIVE-EFFECT-START-OWNERSHIP.json"),
]);

test("retained R4D harness is fixed to the registered 2.0.4 state-only boundary", () => {
  assert.match(runner, /CONTRACT_NUMERIC_ID = 878/);
  assert.match(runner, /CONTRACT_VERSION/);
  for (const functionName of ["create-incident", "claim-effect", "confirm-claim", "begin-effect", "confirm-effect-start"]) {
    assert.match(runner, new RegExp(functionName));
  }
  assert.match(runner, /RESERVATION_FUNCTION/);
  assert.doesNotMatch(runner, /register\(|register-contract|TenantContractsNamespace\.register|maps\.update/);
  assert.doesNotMatch(runner, /github-app|prepare-target|deleteKey|mintInstallationToken|setup-github/);
  assert.doesNotMatch(runner, /finalize-effect|reconcile-effect/);
});

test("retained R4D result is bounded effect-start evidence, not full C1 proof", () => {
  assert.match(evidence, /PASS_REGISTERED_2_0_4_EFFECT_START_OWNERSHIP_PROVEN/);
  assert.match(evidence, /\"numeric_id\": 878/);
  assert.match(evidence, /\"version\": \"2\.0\.4\"/);
  assert.match(evidence, /\"effect_attempts\": 1/);
  assert.match(evidence, /\"provider_operations\": 0/);
  assert.match(evidence, /\"github_api_calls\": 0/);
  assert.match(evidence, /\"credentials_in_evidence\": false/);
  assert.match(evidence, /No provider or GitHub operation was attempted/);
});

test("R4D ordering commits begin before effect-start confirmation and final readback", () => {
  const begin = runner.indexOf('"begin-effect"');
  const confirm = runner.indexOf('"confirm-effect-start"');
  const finalRead = runner.indexOf("finalRead");
  assert.ok(begin >= 0 && confirm > begin && finalRead > confirm);
});
