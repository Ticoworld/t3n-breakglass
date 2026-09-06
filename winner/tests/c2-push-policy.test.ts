import assert from "node:assert/strict";
import { test } from "node:test";
import { normalizeVerifiedPushEvent } from "../c2/push-source.js";
import { buildC2PushPolicyV2, lookupPreExistingPushPolicy, retiredPolicyIdSet, validateC2PushPolicyV2, type C2PushPolicyV2 } from "../c2/push-policy.js";
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

function livePolicy(policy_id: string, overrides: Partial<C2PushPolicyV2> = {}): C2PushPolicyV2 {
  return fixturePolicy({
    policy_id,
    actual_creation_timestamp: "2026-09-06T00:00:00.000Z",
    creation_commit_or_registry_identity: `registry:${policy_id}`,
    provenance: { classification: "LIVE_PROVENANCE", creation_evidence: `remote:${policy_id}`, enabled_before_event_proof: true },
    ...overrides,
  });
}

test("one valid enabled live policy matches", () => {
  const event = normalizeVerifiedPushEvent(signedPush(), PUSH_TEST_SECRET);
  const result = lookupPreExistingPushPolicy(event, [livePolicy("live-one")]);
  assert.equal(result.kind, "MATCH");
});

test("disabled historical policy is ignored when one valid enabled policy exists", () => {
  const event = normalizeVerifiedPushEvent(signedPush(), PUSH_TEST_SECRET);
  const result = lookupPreExistingPushPolicy(event, [livePolicy("historical-disabled", { enabled: false }), livePolicy("live-current")]);
  assert.equal(result.kind, "MATCH");
  if (result.kind === "MATCH") assert.equal(result.policy.policy_id, "live-current");
});

test("two enabled valid matching policies fail closed as ambiguous", () => {
  const event = normalizeVerifiedPushEvent(signedPush(), PUSH_TEST_SECRET);
  const result = lookupPreExistingPushPolicy(event, [livePolicy("live-a"), livePolicy("live-b")]);
  assert.equal(result.kind, "AMBIGUOUS");
});

test("reversing policy input order cannot choose an authority", () => {
  const event = normalizeVerifiedPushEvent(signedPush(), PUSH_TEST_SECRET);
  const policies = [livePolicy("live-a"), livePolicy("live-b")];
  const first = lookupPreExistingPushPolicy(event, policies);
  const reversed = lookupPreExistingPushPolicy(event, [...policies].reverse());
  assert.deepEqual(first, reversed);
});

test("malformed historical policy cannot steal selection from a valid policy", () => {
  const event = normalizeVerifiedPushEvent(signedPush(), PUSH_TEST_SECRET);
  const malformed = { ...livePolicy("historical-malformed"), provenance: undefined } as unknown as C2PushPolicyV2;
  const result = lookupPreExistingPushPolicy(event, [malformed, livePolicy("live-current")]);
  assert.equal(result.kind, "MATCH");
  if (result.kind === "MATCH") assert.equal(result.policy.policy_id, "live-current");
});

test("duplicate policy identity fails closed", () => {
  const event = normalizeVerifiedPushEvent(signedPush(), PUSH_TEST_SECRET);
  const duplicate = livePolicy("same-policy");
  const result = lookupPreExistingPushPolicy(event, [duplicate, { ...duplicate }]);
  assert.equal(result.kind, "AMBIGUOUS");
});

test("duplicate identity is ambiguous even when one copy is malformed", () => {
  const event = normalizeVerifiedPushEvent(signedPush(), PUSH_TEST_SECRET);
  const malformed = { ...livePolicy("same-policy-malformed"), expected_private_material_sha256: "not-a-digest" };
  const result = lookupPreExistingPushPolicy(event, [livePolicy("same-policy-malformed"), malformed]);
  assert.equal(result.kind, "AMBIGUOUS");
});

test("duplicate identity is ambiguous even when one copy is disabled", () => {
  const event = normalizeVerifiedPushEvent(signedPush(), PUSH_TEST_SECRET);
  const result = lookupPreExistingPushPolicy(event, [livePolicy("same-policy-disabled"), livePolicy("same-policy-disabled", { enabled: false })]);
  assert.equal(result.kind, "AMBIGUOUS");
});

test("duplicate identity remains ambiguous with reversed input order", () => {
  const event = normalizeVerifiedPushEvent(signedPush(), PUSH_TEST_SECRET);
  const policies = [livePolicy("same-policy-order"), livePolicy("same-policy-order", { enabled: false })];
  const first = lookupPreExistingPushPolicy(event, policies);
  const reversed = lookupPreExistingPushPolicy(event, [...policies].reverse());
  assert.deepEqual(first, reversed);
});

test("stale deleted-target policy cannot win by appearing first, and retirement permits the new policy", () => {
  const event = normalizeVerifiedPushEvent(signedPush(), PUSH_TEST_SECRET);
  const stale = livePolicy("stale-deleted-target", { deploy_key_id: 162414923 });
  const current = livePolicy("live-current", { deploy_key_id: 162414924 });
  assert.equal(lookupPreExistingPushPolicy(event, [stale, current]).kind, "AMBIGUOUS");
  const retired = retiredPolicyIdSet([{ policy_id: stale.policy_id, retired: true, retirement_reason: "fixture cleanup", retirement_timestamp: "2026-09-06T00:00:00.000Z", retirement_evidence_identity: "retirement:test" }]);
  const selected = lookupPreExistingPushPolicy(event, [stale, current], { retiredPolicyIds: retired });
  assert.equal(selected.kind, "MATCH");
  if (selected.kind === "MATCH") assert.equal(selected.policy.policy_id, current.policy_id);
});
