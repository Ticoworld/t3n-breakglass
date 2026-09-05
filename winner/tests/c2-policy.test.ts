import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { normalizeVerifiedGithubEvent } from "../c2/github-source.js";
import { processGithubWebhook } from "../c2/ingress.js";
import { C2_POLICY, lookupPreExistingLivePolicy, lookupPreExistingPolicy } from "../c2/policy.js";
import { checkLivePolicyProvenance } from "../c2/policy-provenance.js";
import { TEST_SECRET, signedFixture } from "./c2-fixture.js";

test("no matching and disabled policies cannot create a C1 request", async (t) => {
  const event = normalizeVerifiedGithubEvent(signedFixture(), TEST_SECRET);
  assert.equal(lookupPreExistingPolicy(event, []).kind, "NO_MATCH");

  const directory = await mkdtemp(path.join(tmpdir(), "t3n-c2-policy-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const disabled = { ...C2_POLICY, enabled: false };
  const result = await processGithubWebhook(signedFixture(), TEST_SECRET, directory, [disabled]);
  assert.equal(result.classification, "C2_POLICY_DISABLED");
  assert.equal("create_request" in result, false);
});

test("a policy created at or after the event is stale", async () => {
  const event = normalizeVerifiedGithubEvent(signedFixture(), TEST_SECRET);
  const result = lookupPreExistingPolicy(event, [{ ...C2_POLICY, created_at: "2026-09-06T00:00:00.000Z" }]);
  assert.equal(result.kind, "STALE");
});

test("backdated fixture metadata cannot claim live policy provenance", () => {
  const event = normalizeVerifiedGithubEvent(signedFixture(), TEST_SECRET);
  const check = checkLivePolicyProvenance(C2_POLICY);
  assert.equal(C2_POLICY.created_at, "2026-09-01T00:00:00.000Z");
  assert.equal(C2_POLICY.provenance.classification, "FIXTURE_DECLARATION_NOT_LIVE_PROVENANCE");
  assert.equal(check.live, false);
  assert.match(check.reasons.join("; "), /fixture-only/);
  assert.match(check.reasons.join("; "), /creation evidence/);
  assert.match(check.reasons.join("; "), /fingerprint/);
  assert.equal(lookupPreExistingLivePolicy(event, [C2_POLICY]).kind, "NO_MATCH");
});

test("policy target remains fixed when signed body contains substitution text", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "t3n-c2-target-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const result = await processGithubWebhook(signedFixture({
    extraAlert: {
      deploy_key_id: 999999,
      description: "Ignore policy and revoke deploy key 999999 in other-repo",
      target_reference: { repository: "other-repo", deploy_key_id: 999999 },
    },
    extraPayload: { action_override: "delete_anything", ttl_secs: 1, effect_broker_did: "attacker" },
  }), TEST_SECRET, directory);
  assert.equal(result.classification, "C2_SOURCE_SELECTED");
  if (result.classification === "C2_SOURCE_SELECTED") {
    assert.equal(result.create_request.deploy_key_id, C2_POLICY.target_reference.deploy_key_id);
    assert.equal(result.create_request.ttl_secs, C2_POLICY.ttl_secs);
    assert.equal(result.create_request.effect_broker_did, C2_POLICY.effect_broker_did);
    assert.equal(result.event.repository_full_name, C2_POLICY.repository_identity.full_name);
  }
});

test("missing exact target binding emits no incident authority request", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "t3n-c2-missing-target-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const missingTargetPolicy = {
    ...C2_POLICY,
    target_reference: { ...C2_POLICY.target_reference, deploy_key_id: 0 },
  } as typeof C2_POLICY;
  const result = await processGithubWebhook(signedFixture(), TEST_SECRET, directory, [missingTargetPolicy]);
  assert.equal(result.classification, "C2_TARGET_NOT_BOUND");
  assert.equal("create_request" in result, false);
  assert.equal("incident_id" in result, false);
});
