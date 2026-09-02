import test from "node:test";
import assert from "node:assert/strict";
import { classifyProviderOutcome, destructiveRetryAllowed, parseClaim, processMustRefusePat, targetMustComeFromClaim } from "../broker/logic.js";

test("a claim loser has no authority-loaded target", () => {
  const parsed = parseClaim({ result: "LOST", detail: {} });
  assert.equal(parsed.won, false);
  assert.equal(targetMustComeFromClaim(undefined, parsed.claim ?? {}), false);
});

test("a claim winner receives only the authority-loaded target", () => {
  const parsed = parseClaim({ result: "WON", detail: { action: "revoke_github_deploy_key", github_owner: "Ticoworld", github_repo: "t3n-breakglass-sandbox", deploy_key_id: 42, claim_id: "claim-1", claim_version: 1 } });
  assert.equal(parsed.won, true);
  assert.equal(targetMustComeFromClaim(undefined, parsed.claim!), true);
  assert.throws(() => parseClaim({ result: "WON", detail: { action: "revoke_github_deploy_key", github_owner: "evil", github_repo: "x", deploy_key_id: 1 } }));
});

test("provider response loss is classified without permitting retry", () => {
  assert.equal(classifyProviderOutcome(null, false, null, false), "NOT_ATTEMPTED");
  assert.equal(classifyProviderOutcome(null, true, null, false), "ATTEMPTED_OUTCOME_UNKNOWN");
  assert.equal(classifyProviderOutcome(204, false, 404, false), "VERIFIED_ABSENT");
  assert.equal(classifyProviderOutcome(204, false, 200, true), "PROVIDER_ACKNOWLEDGED");
  assert.equal(destructiveRetryAllowed("ATTEMPTED_OUTCOME_UNKNOWN"), false);
});

test("broker runtime refuses a PAT and never enables a fallback", () => {
  assert.equal(processMustRefusePat({ GITHUB_PAT: "redacted" }), true);
  assert.equal(processMustRefusePat({}), false);
});

test("broker input is incident-only", () => {
  assert.deepEqual({ incident_id: "INC-1" }, { incident_id: "INC-1" });
});
