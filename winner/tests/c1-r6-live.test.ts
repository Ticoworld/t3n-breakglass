import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const live = await readFile(new URL("../scripts/c1-live.ts", import.meta.url), "utf8");
const broker = await readFile(new URL("../broker/run.ts", import.meta.url), "utf8");

test("R4E uses the fixed existing target and refuses PAT fallback", () => {
  assert.match(live, /C1_TARGET_MODE: "existing"/);
  assert.match(live, /C1_EXISTING_TARGET_ID: String\(TARGET_ID\)/);
  assert.match(live, /C1_EXISTING_TARGET_TITLE: TARGET_TITLE/);
  assert.match(live, /C1-R6B-R4E-R1-PROVIDER-PROOF\.json/);
  assert.match(live, /C1 live runner refuses a GitHub PAT/);
  assert.match(broker, /C1 broker refuses to run with GITHUB_PAT/);
});

test("provider work is blocked behind confirmed claim, effect-start, and operator gate", () => {
  const confirmClaim = broker.indexOf('"confirm-claim"', broker.indexOf("const confirmationRaw"));
  const mint = broker.indexOf("const minted = await mintEffectInstallationToken");
  const before = broker.indexOf("exactKey(effectToken");
  const begin = broker.indexOf('"begin-effect"');
  const confirmStart = broker.indexOf('"confirm-effect-start"');
  const deleteCall = broker.indexOf("deleteKey(effectToken");
  const gate = broker.indexOf("await waitForFile(releaseDelete)");
  assert.ok(confirmClaim >= 0 && mint > confirmClaim && before > mint && begin > before && confirmStart > begin && gate > confirmStart && deleteCall > gate);
  assert.match(broker, /C1_EFFECT_START_READY_FILE/);
  assert.match(broker, /effect_token_cleanup/);
  assert.match(broker, /mintReadOnlyInstallationToken/);
  assert.match(broker, /reconcile-effect/);
});

test("the live parent completes both proposals before allowing confirmation and DELETE", () => {
  const release = live.indexOf("claim-release.json");
  const proposals = live.indexOf("claim-proposals-complete.json");
  const effectReady = live.indexOf("const effectStartReady =");
  const deleteRelease = live.indexOf("const preDeleteRelease =");
  const childReads = live.indexOf("readJsonFile<JsonObject>(brokerAResultFile)");
  assert.ok(release >= 0 && childReads > release && proposals < childReads && effectReady > proposals && deleteRelease > effectReady);
  assert.match(live, /both_results_persisted: true/);
  assert.match(live, /operator_authority_verified: true/);
});
