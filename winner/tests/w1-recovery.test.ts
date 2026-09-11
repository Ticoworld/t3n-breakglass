import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import { processPushWebhookWithSourceReader } from "../c2/push-ingress.js";
import { reserveDedupe } from "../c2/dedupe.js";
import { normalizeVerifiedPushEvent } from "../c2/push-source.js";
import { BreakGlassCoordinator } from "../runtime/coordinator.js";
import { RuntimeJobStore } from "../runtime/job-store.js";
import { PolicyRegistry, policyRegistryInputFromJson } from "../runtime/policy-registry.js";
import { fixturePolicy, PUSH_AFTER_SHA, PUSH_BEFORE_SHA, PUSH_PRIVATE_MATERIAL_SHA256, PUSH_STATE_INTEGRITY_KEY, PUSH_TEST_SECRET, signedPush } from "./c2-push-fixture.js";

function config(root: string): any {
  return {
    role: "coordinator", paths: { root, receipts: path.join(root, "receipts"), policies: path.join(root, "policies"), retirements: path.join(root, "retirements"), jobs: path.join(root, "jobs"), results: path.join(root, "results") },
    listenHost: "127.0.0.1", listenPort: 0, webhookRoute: "/c2-b0/github-push", webhookSecret: PUSH_TEST_SECRET, maxBodyBytes: 1_000_000,
    operatorDid: "did:t3n:0000000000000000000000000000000000000000", remediationDid: "did:t3n:0000000000000000000000000000000000000001", brokerDid: "did:t3n:0000000000000000000000000000000000000002", contractId: "contract", contractVersion: "2.0.4", stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY, app: { appId: "1", installationId: "2", privateKeyPath: "C:\\outside\\app.pem", owner: "Ticoworld", repository: "t3n-breakglass-sandbox" }, pollMs: 10,
  };
}

function reader(options: { before?: 200 | 404; afterDigest?: string } = {}) {
  let calls = 0;
  return {
    readPlan: async () => { calls += 1; return { before: { repository: "Ticoworld/t3n-breakglass-sandbox", commit_sha: PUSH_BEFORE_SHA, path: ".breakglass-c2/exposed-deploy-key", status: options.before ?? 404, ...(options.before === 200 ? { content_sha256: PUSH_PRIVATE_MATERIAL_SHA256 } : {}) }, after: { repository: "Ticoworld/t3n-breakglass-sandbox", commit_sha: PUSH_AFTER_SHA, path: ".breakglass-c2/exposed-deploy-key", status: 200, content_sha256: options.afterDigest ?? PUSH_PRIVATE_MATERIAL_SHA256 }, token_minted: true, token_revoked: true, revoked_token_refused: true }; },
    calls: () => calls,
  };
}

function c1WithState(initial: string | null = null, loseCreateResponse = false) {
  let state = initial;
  let creates = 0;
  let reservations = 0;
  return {
    getIncident: async (incidentId: string) => state ? { result: "FOUND", state, detail: { incident_id: incidentId, remediation_agent_did: "did:t3n:c2-push-local-agent", effect_broker_did: "did:t3n:c2-push-local-broker", action: "revoke_github_deploy_key", github_owner: "Ticoworld", github_repo: "t3n-breakglass-sandbox", deploy_key_id: 987654321, ...(state === "EFFECT_STARTED" || state === "EFFECT_CLAIMED" ? { effect_claim_id: "claim-1", effect_claim_version: 1, ...(state === "EFFECT_STARTED" ? { effect_start_id: "start-1" } : {}) } : {}) }, ...(state === "CLOSED" ? { final_result_classification: "VERIFIED_ABSENT" } : {}) } : { result: "DENIED", state: "ABSENT" },
    createIncident: async () => { creates += 1; state = "ACTIVE"; if (loseCreateResponse) throw new Error("simulated create response loss"); return { result: "WON", state: "ACTIVE" }; },
    reserveIncident: async () => { reservations += 1; state = "RESERVED"; return { result: "WON", state: "RESERVED" }; },
    setState: (next: string) => { state = next; },
    creates: () => creates,
    reservations: () => reservations,
  };
}

async function make(t: { after(callback: () => void | Promise<void>): void }) {
  const root = await mkdtemp(path.join(tmpdir(), "breakglass-w1r2-recovery-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const registry = new PolicyRegistry(root, { stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY });
  await registry.initialize();
  const record = await registry.create(policyRegistryInputFromJson(fixturePolicy({ policy_id: "w1-recovery-policy" })), { trustedEvidenceIdentity: "offline-fixture:w1-recovery" });
  const jobs = new RuntimeJobStore(path.join(root, "jobs"), { stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY });
  const source = reader();
  return { root, registry, record, jobs, source, makeCoordinator: (c1: any) => new BreakGlassCoordinator({ config: config(root), registry, jobs, c1, sourceReader: source as any }) };
}

test("restart after ACCEPTED receipt recreates the job from the stored exact C1 request", async (t) => {
  const value = await make(t);
  const accepted = await processPushWebhookWithSourceReader(signedPush(), PUSH_TEST_SECRET, path.join(value.root, "receipts"), await value.registry.activePolicies(), value.source as any, { stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY });
  assert.equal(accepted.classification, "C2_PUSH_SELECTED");
  const c1 = c1WithState();
  await value.makeCoordinator(c1).initialize();
  assert.equal(c1.creates(), 1);
  assert.equal((await value.jobs.list())[0].state, "HANDOFF_READY");
  assert.equal(value.source.calls(), 1);
});

test("incident creation response loss is recovered by exact remote readback without a second create", async (t) => {
  const value = await make(t);
  const c1 = c1WithState(null, true);
  const result = await value.makeCoordinator(c1).acceptWebhook(signedPush());
  assert.equal(result.body.accepted, true);
  assert.equal(c1.creates(), 1);
  assert.equal(c1.reservations(), 1);
});

test("crash after binding before accepted receipt leaves policy bound and exact event resumable", async (t) => {
  const value = await make(t);
  const failingBind = async (input: any) => { await value.registry.bindVerifiedEvent(input); throw new Error("simulated crash after binding"); };
  const policies = await value.registry.activePolicies();
  await assert.rejects(() => processPushWebhookWithSourceReader(signedPush(), PUSH_TEST_SECRET, path.join(value.root, "receipts"), policies, value.source as any, { stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY, bindVerifiedPolicy: failingBind, requirePolicyBinding: true }), /simulated crash/);
  assert.equal((await value.registry.activePolicies()).length, 0);
  const c1 = c1WithState();
  const resumed = await value.makeCoordinator(c1).acceptWebhook(signedPush());
  assert.equal(resumed.body.accepted, true);
  assert.equal(value.source.calls(), 2);
  assert.equal(c1.creates(), 1);
});

test("restart with an interrupted RESERVED receipt does not read source or derive authority", async (t) => {
  const value = await make(t);
  const event = normalizeVerifiedPushEvent(signedPush(), PUSH_TEST_SECRET);
  await reserveDedupe(path.join(value.root, "receipts"), event, { stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY });
  const c1 = c1WithState();
  await value.makeCoordinator(c1).initialize();
  assert.equal((await value.jobs.list()).length, 0);
  const replay = await value.makeCoordinator(c1).acceptWebhook(signedPush());
  assert.equal(replay.body.accepted, false);
  assert.equal(value.source.calls(), 0);
});

test("restart after EFFECT_STARTED only records reconciliation-required state", async (t) => {
  const value = await make(t);
  await value.jobs.create({ incident_id: "effect-started-incident", receipt_key: "a".repeat(64), policy_id: value.record.policy.policy_id, policy_version: value.record.policy.policy_version, deploy_key_id: value.record.policy.deploy_key_id, expected_target_title: value.record.policy.expected_deploy_key_title, create_request: { incident_id: "effect-started-incident", remediation_agent_did: value.record.policy.remediation_agent_did, effect_broker_did: value.record.policy.effect_broker_did, deploy_key_id: value.record.policy.deploy_key_id, ttl_secs: value.record.policy.ttl_secs }, state: "PROCESSING" });
  await value.makeCoordinator(c1WithState("EFFECT_STARTED")).initialize();
  const recovered = await value.jobs.get("effect-started-incident");
  assert.equal(recovered?.state, "RECONCILE_REQUIRED");
  assert.equal(recovered?.effect_start_id, "start-1");
});

test("close-before-retire recovery requires the matching bound incident and retires only after remote confirmation", async (t) => {
  const value = await make(t);
  const c1 = c1WithState("RESERVED");
  const accepted = await value.makeCoordinator(c1).acceptWebhook(signedPush());
  assert.equal(accepted.body.accepted, true);
  assert.equal((await value.registry.activePolicies()).length, 0);
  const distinct = await value.makeCoordinator(c1).acceptWebhook(signedPush({ deliveryId: "87654321-4321-4321-4321-210987654321", after: PUSH_AFTER_SHA }));
  assert.equal(distinct.body.accepted, false);
  assert.equal(distinct.body.classification, "C2_PUSH_POLICY_ALREADY_BOUND");
  assert.equal((await value.registry.retirements()).length, 0);
  c1.setState("CLOSED");
  await value.makeCoordinator(c1).initialize();
  assert.equal((await value.registry.retirements()).length, 1);
  const replay = await value.makeCoordinator(c1).acceptWebhook(signedPush());
  assert.equal(replay.body.accepted, true);
  assert.equal(replay.body.replayed, true);
  assert.equal(value.source.calls(), 2);
});

test("a matching but nonqualifying source transition does not consume the policy", async (t) => {
  const value = await make(t);
  const nonqualifyingSource = {
    readPlan: async (plan: any) => ({
      before: { repository: plan.repository, commit_sha: plan.before_sha, path: plan.path, status: 200, content_sha256: PUSH_PRIVATE_MATERIAL_SHA256 },
      after: { repository: plan.repository, commit_sha: plan.after_sha, path: plan.path, status: 200, content_sha256: PUSH_PRIVATE_MATERIAL_SHA256 },
      token_minted: true, token_revoked: true, revoked_token_refused: true,
    }),
  };
  const c1 = c1WithState();
  const result = await new BreakGlassCoordinator({ config: config(value.root), registry: value.registry, jobs: value.jobs, c1: c1 as any, sourceReader: nonqualifyingSource as any }).acceptWebhook(signedPush());
  assert.equal(result.body.accepted, false);
  assert.equal(result.body.classification, "C2_PUSH_TRANSITION_REJECTED");
  assert.equal((await value.registry.activePolicies()).length, 1);
  assert.equal((await value.registry.bindings()).length, 0);
  assert.equal(c1.creates(), 0);
});

test("two distinct qualifying events race for one policy and exclusive binding selects exactly one", async (t) => {
  const value = await make(t);
  const source = {
    readPlan: async (plan: any) => {
      await new Promise((resolve) => setTimeout(resolve, 10));
      return {
        before: { repository: plan.repository, commit_sha: plan.before_sha, path: plan.path, status: 404 },
        after: { repository: plan.repository, commit_sha: plan.after_sha, path: plan.path, status: 200, content_sha256: PUSH_PRIVATE_MATERIAL_SHA256 },
        token_minted: true, token_revoked: true, revoked_token_refused: true,
      };
    },
  };
  const c1 = c1WithState();
  const coordinator = new BreakGlassCoordinator({ config: config(value.root), registry: value.registry, jobs: value.jobs, c1: c1 as any, sourceReader: source as any });
  const [first, second] = await Promise.all([
    coordinator.acceptWebhook(signedPush()),
    coordinator.acceptWebhook(signedPush({ deliveryId: "99999999-9999-4999-8999-999999999999", after: "c".repeat(40) })),
  ]);
  const results = [first, second];
  assert.equal(results.filter((result) => result.body.accepted === true).length, 1);
  assert.equal(results.filter((result) => result.body.accepted === false).length, 1);
  assert.equal((await value.registry.bindings()).length, 1);
  assert.equal(c1.creates(), 1);
  const loser = results.find((result) => result.body.accepted === false)!;
  assert.equal(loser.body.classification, "C2_PUSH_POLICY_ALREADY_BOUND");
});

test("local state cannot move backward and a locally CLOSED job conflicts with nonterminal remote truth", async (t) => {
  const value = await make(t);
  const job = await value.jobs.create({ incident_id: "state-conflict", receipt_key: "b".repeat(64), policy_id: value.record.policy.policy_id, policy_version: value.record.policy.policy_version, deploy_key_id: value.record.policy.deploy_key_id, expected_target_title: value.record.policy.expected_deploy_key_title, create_request: { incident_id: "state-conflict", remediation_agent_did: value.record.policy.remediation_agent_did, effect_broker_did: value.record.policy.effect_broker_did, deploy_key_id: value.record.policy.deploy_key_id, ttl_secs: value.record.policy.ttl_secs }, state: "CLOSED" });
  await assert.rejects(() => value.jobs.update(job.incident_id, { state: "HANDOFF_READY" }), /transition/);
  await value.makeCoordinator(c1WithState("RESERVED")).initialize();
  assert.equal((await value.jobs.get(job.incident_id))?.state, "STATE_CONFLICT");
});
