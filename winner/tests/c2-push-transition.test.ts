import assert from "node:assert/strict";
import { test } from "node:test";
import { normalizeVerifiedPushEvent } from "../c2/push-source.js";
import { createImmutablePushReadPlan } from "../c2/push-read-plan.js";
import { derivePushC1CreateRequest } from "../c2/push-c1.js";
import { digestPrivateMaterial, verifyPushSecretTransition } from "../c2/push-transition.js";
import { immutableContentReadOperations, pushSourceReaderTokenRequest } from "../c2/push-source-reader.js";
import {
  PUSH_AFTER_SHA,
  PUSH_BEFORE_SHA,
  PUSH_PRIVATE_MATERIAL,
  PUSH_PRIVATE_MATERIAL_SHA256,
  PUSH_TEST_SECRET,
  fixturePolicy,
  observation,
  signedPush,
} from "./c2-push-fixture.js";

const policy = fixturePolicy();
const event = normalizeVerifiedPushEvent(signedPush(), PUSH_TEST_SECRET);

test("policy-bound push creates exactly two immutable read operations", () => {
  const plan = createImmutablePushReadPlan(event, policy, { allowLocalFixture: true });
  assert.deepEqual(plan, {
    repository: "Ticoworld/t3n-breakglass-sandbox",
    before_sha: PUSH_BEFORE_SHA,
    after_sha: PUSH_AFTER_SHA,
    path: ".breakglass-c2/exposed-deploy-key",
  });
  assert.deepEqual(immutableContentReadOperations(plan), [
    { method: "GET", repository: "Ticoworld/t3n-breakglass-sandbox", path: ".breakglass-c2/exposed-deploy-key", ref: PUSH_BEFORE_SHA },
    { method: "GET", repository: "Ticoworld/t3n-breakglass-sandbox", path: ".breakglass-c2/exposed-deploy-key", ref: PUSH_AFTER_SHA },
  ]);
  assert.deepEqual(pushSourceReaderTokenRequest(), {
    repositories: ["Ticoworld/t3n-breakglass-sandbox"],
    permissions: { contents: "read" },
  });
});

test("before absent and after exact digest is a causal secret introduction", () => {
  const result = verifyPushSecretTransition(
    observation(PUSH_BEFORE_SHA, 404),
    observation(PUSH_AFTER_SHA, 200, PUSH_PRIVATE_MATERIAL_SHA256),
    policy,
  );
  assert.deepEqual(result, {
    classification: "CAUSAL_SECRET_INTRODUCED",
    before_digest: null,
    after_digest: PUSH_PRIVATE_MATERIAL_SHA256,
  });
});

test("before different digest and after exact digest is causal", () => {
  const result = verifyPushSecretTransition(
    observation(PUSH_BEFORE_SHA, 200, "1".repeat(64)),
    observation(PUSH_AFTER_SHA, 200, PUSH_PRIVATE_MATERIAL_SHA256),
    policy,
  );
  assert.equal(result.classification, "CAUSAL_SECRET_INTRODUCED");
});

test("already present, missing, wrong, and malformed transitions fail closed", () => {
  assert.equal(verifyPushSecretTransition(observation(PUSH_BEFORE_SHA, 200, PUSH_PRIVATE_MATERIAL_SHA256), observation(PUSH_AFTER_SHA, 200, PUSH_PRIVATE_MATERIAL_SHA256), policy).classification, "SECRET_ALREADY_PRESENT_BEFORE");
  assert.equal(verifyPushSecretTransition(observation(PUSH_BEFORE_SHA, 404), observation(PUSH_AFTER_SHA, 404), policy).classification, "AFTER_MISSING");
  assert.equal(verifyPushSecretTransition(observation(PUSH_BEFORE_SHA, 404), observation(PUSH_AFTER_SHA, 200, "2".repeat(64)), policy).classification, "AFTER_DIGEST_MISMATCH");
  assert.equal(verifyPushSecretTransition(observation(PUSH_BEFORE_SHA, 200), observation(PUSH_AFTER_SHA, 200, PUSH_PRIVATE_MATERIAL_SHA256), policy).classification, "NO_SECRET_TRANSITION");
});

test("alternate repository/path cannot satisfy the policy-bound transition", () => {
  const alternate = { ...observation(PUSH_BEFORE_SHA, 404), path: ".other-secret" };
  assert.equal(verifyPushSecretTransition(alternate, observation(PUSH_AFTER_SHA, 200, PUSH_PRIVATE_MATERIAL_SHA256), policy).classification, "TARGET_POLICY_MISMATCH");
  assert.equal(verifyPushSecretTransition(observation("c".repeat(40), 404), observation(PUSH_AFTER_SHA, 200, PUSH_PRIVATE_MATERIAL_SHA256), policy, { before_sha: PUSH_BEFORE_SHA, after_sha: PUSH_AFTER_SHA }).classification, "TARGET_POLICY_MISMATCH");
  const alternatePolicy = { ...policy, secret_path: ".other-secret" } as unknown as typeof policy;
  assert.throws(() => createImmutablePushReadPlan(event, alternatePolicy, { allowLocalFixture: true }), /exact|path|usable/);
});

test("only a causal transition reaches the exact C1 request shape", () => {
  const transition = verifyPushSecretTransition(observation(PUSH_BEFORE_SHA, 404), observation(PUSH_AFTER_SHA, 200, PUSH_PRIVATE_MATERIAL_SHA256), policy);
  assert.throws(() => derivePushC1CreateRequest(event, policy, transition), /live provenance/);
  const result = derivePushC1CreateRequest(event, policy, transition, { allowLocalFixture: true });
  assert.deepEqual(Object.keys(result.create_request).sort(), [
    "deploy_key_id",
    "effect_broker_did",
    "incident_id",
    "remediation_agent_did",
    "ttl_secs",
  ]);
  assert.deepEqual(result.create_request, {
    incident_id: result.incident_id,
    remediation_agent_did: "did:t3n:c2-push-local-agent",
    effect_broker_did: "did:t3n:c2-push-local-broker",
    deploy_key_id: 987654321,
    ttl_secs: 900,
  });
  assert.equal(JSON.stringify(result).includes(PUSH_PRIVATE_MATERIAL), false);
});

test("private material is reduced to a digest and the dedicated buffer is overwritten", () => {
  const material = Buffer.from(PUSH_PRIVATE_MATERIAL, "utf8");
  assert.equal(digestPrivateMaterial(material), PUSH_PRIVATE_MATERIAL_SHA256);
  assert.equal(material.every((value) => value === 0), true);
});
