import assert from "node:assert/strict";
import { test } from "node:test";
import { normalizeVerifiedPushEvent } from "../c2/push-source.js";
import { buildC2PushPolicyV2, lookupPreExistingPushPolicy, validateC2PushPolicyV2, type C2PushPolicyV2 } from "../c2/push-policy.js";
import { PUSH_TEST_SECRET, fixturePolicy, signedPush } from "./c2-push-fixture.js";

test("push policy v2 freezes source repository/ref/path and requires caller-supplied target facts", () => {
  const policy = fixturePolicy();
  assert.equal(policy.repository_id, 1350596128);
  assert.equal(policy.repository_full_name, "Ticoworld/t3n-breakglass-sandbox");
  assert.equal(policy.ref, "refs/heads/c2-breakglass-demo");
  assert.equal(policy.secret_path, ".breakglass-c2/exposed-deploy-key");
  assert.equal(policy.expected_private_material_sha256.length, 64);
  assert.equal(validateC2PushPolicyV2(policy).valid, true);
  assert.equal(validateC2PushPolicyV2(policy).live, false);
});

test("local fixture policy cannot pass the live provenance boundary", () => {
  const event = normalizeVerifiedPushEvent(signedPush(), PUSH_TEST_SECRET);
  const policy = fixturePolicy({ actual_creation_timestamp: "2026-09-01T00:00:00.000Z" });
  const validation = validateC2PushPolicyV2(policy, { requireLiveProvenance: true });
  assert.equal(validation.live, false);
  assert.equal(validation.valid, false);
  assert.match(validation.reasons.join("; "), /local fixture/);
  assert.equal(lookupPreExistingPushPolicy(event, [policy]).kind, "NO_MATCH");
  assert.equal(lookupPreExistingPushPolicy(event, [policy], { allowLocalFixture: true }).kind, "MATCH");
});

test("policy builder overwrites any runtime attempt to substitute source binding", () => {
  const input = fixturePolicy();
  const policy = buildC2PushPolicyV2({
    ...input,
    secret_path: "../../other-repo/secret",
    repository_full_name: "Ticoworld/other-repo",
    ref: "refs/heads/main",
  } as never);
  assert.equal(policy.repository_full_name, "Ticoworld/t3n-breakglass-sandbox");
  assert.equal(policy.ref, "refs/heads/c2-breakglass-demo");
  assert.equal(policy.secret_path, ".breakglass-c2/exposed-deploy-key");
});

test("live provenance requires independent evidence rather than a timestamp string", () => {
  const policy = {
    ...fixturePolicy(),
    provenance: {
      classification: "LIVE_PROVENANCE",
      creation_evidence: "",
      enabled_before_event_proof: false,
    },
  } as C2PushPolicyV2;
  const validation = validateC2PushPolicyV2(policy);
  assert.equal(validation.live, false);
  assert.match(validation.reasons.join("; "), /creation evidence/);
  assert.match(validation.reasons.join("; "), /enabled-before-event/);
});
