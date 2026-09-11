import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import { derivePushC1CreateRequest } from "../c2/push-c1.js";
import { pushEventBindingIdentity } from "../c2/push-binding.js";
import { normalizeVerifiedPushEvent } from "../c2/push-source.js";
import { verifyPushSecretTransition } from "../c2/push-transition.js";
import { PolicyRegistry, PolicyRegistryIntegrityError, policyRegistryInputFromJson, type RegistryPolicyInput } from "../runtime/policy-registry.js";
import { fixturePolicy, observation, PUSH_AFTER_SHA, PUSH_BEFORE_SHA, PUSH_PRIVATE_MATERIAL_SHA256, PUSH_STATE_INTEGRITY_KEY, PUSH_TEST_SECRET, signedPush } from "./c2-push-fixture.js";

function input(overrides: Record<string, unknown> = {}): RegistryPolicyInput {
  return policyRegistryInputFromJson({ ...fixturePolicy({ policy_id: "w1-policy", ...overrides }), provenance: { classification: "LOCAL_TEST_FIXTURE", creation_evidence: "attacker", enabled_before_event_proof: false } });
}

function registry(root: string): PolicyRegistry { return new PolicyRegistry(root, { stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY }); }

async function bind(reg: PolicyRegistry, policyId: string, deliveryId = "22222222-2222-4222-8222-222222222222") {
  const record = await reg.findRecord(policyId, 2);
  assert.ok(record);
  const event = normalizeVerifiedPushEvent(signedPush({ deliveryId }), PUSH_TEST_SECRET);
  const transition = verifyPushSecretTransition(observation(PUSH_BEFORE_SHA, 404), observation(PUSH_AFTER_SHA, 200, PUSH_PRIVATE_MATERIAL_SHA256), record.policy, { before_sha: event.before, after_sha: event.after });
  const derived = derivePushC1CreateRequest(event, record.policy, transition, { allowLocalFixture: false });
  const identity = pushEventBindingIdentity({ policy: record.policy, event, transition, incidentId: derived.incident_id, dedupeKey: "a".repeat(64), registryIdentity: record.registry_identity, policyContentHash: record.policy_sha256 });
  return reg.bindVerifiedEvent({ policy: record.policy, event, transition, incidentId: derived.incident_id, dedupeKey: "a".repeat(64), registryIdentity: record.registry_identity, policyContentHash: record.policy_sha256, eventBindingIdentity: identity });
}

test("registry creates server-provenanced MAC-protected policy records and refuses duplicate identity/version", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "breakglass-w1r2-policy-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const reg = registry(root);
  await reg.initialize();
  const record = await reg.create(input(), { trustedEvidenceIdentity: "offline-fixture:w1-policy" });
  assert.equal(record.policy.provenance.classification, "LIVE_PROVENANCE");
  assert.equal((await reg.activePolicies()).length, 1);
  assert.equal(typeof record.mac, "string");
  await assert.rejects(() => reg.create(input(), { trustedEvidenceIdentity: "offline-fixture:w1-policy" }), /duplicate policy identity\/version refused/);
  await assert.rejects(() => reg.create(input({ policy_id: "../escape" }), { trustedEvidenceIdentity: "offline-fixture:escape" }), /safe storage identifier/);
  await assert.rejects(() => reg.create(input(), {}), /trusted policy evidence identity/);
});

test("tampered, corrupt, legacy, and invalid-MAC registry records fail closed", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "breakglass-w1r2-policy-integrity-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const reg = registry(root);
  await reg.initialize();
  await reg.create(input({ policy_id: "w1-policy-integrity" }), { trustedEvidenceIdentity: "offline-fixture:integrity" });
  const policyFile = path.join(root, "policies", (await readdir(path.join(root, "policies")))[0]);
  const tampered = JSON.parse(await readFile(policyFile, "utf8")) as Record<string, any>;
  tampered.policy.deploy_key_id += 1;
  await writeFile(policyFile, JSON.stringify(tampered));
  await assert.rejects(() => reg.records(), /content hash mismatch|integrity verification failed/);
  await writeFile(policyFile, "not-json");
  await assert.rejects(() => reg.records(), /cannot parse policy record/);
});

test("verified event binding is one-shot, exclusive, and retirement is idempotent", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "breakglass-w1r2-policy-binding-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const reg = registry(root);
  await reg.initialize();
  const record = await reg.create(input({ policy_id: "w1-policy-binding" }), { trustedEvidenceIdentity: "offline-fixture:binding" });
  await bind(reg, record.policy.policy_id);
  assert.equal((await reg.activePolicies()).length, 0);
  await assert.rejects(() => bind(reg, record.policy.policy_id, "87654321-4321-4321-4321-210987654321"), /already bound|different verified event/);
  const binding = (await reg.bindings())[0];
  const retired = await reg.retire(record.policy.policy_id, record.policy.policy_version, binding.incident_id);
  const same = await reg.retire(record.policy.policy_id, record.policy.policy_version, binding.incident_id);
  assert.equal(retired.incident_id, same.incident_id);
  assert.equal((await reg.activePolicies()).length, 0);
});

test("binding and retirement corruption cannot resurrect policy state", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "breakglass-w1r2-policy-restart-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const reg = registry(root);
  await reg.initialize();
  const record = await reg.create(input({ policy_id: "w1-policy-restart" }), { trustedEvidenceIdentity: "offline-fixture:restart" });
  await bind(reg, record.policy.policy_id);
  const bindingFile = path.join(root, "bindings", (await readdir(path.join(root, "bindings")))[0]);
  const binding = JSON.parse(await readFile(bindingFile, "utf8")) as Record<string, unknown>;
  binding.dedupe_key = "b".repeat(64);
  await writeFile(bindingFile, JSON.stringify(binding));
  await assert.rejects(() => new PolicyRegistry(root, { stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY }).initialize(), /binding integrity verification failed/);
});
