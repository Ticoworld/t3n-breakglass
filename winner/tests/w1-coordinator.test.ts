import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import { createHmac } from "node:crypto";
import { BreakGlassCoordinator } from "../runtime/coordinator.js";
import { RuntimeJobStore } from "../runtime/job-store.js";
import { PolicyRegistry, policyRegistryInputFromJson } from "../runtime/policy-registry.js";
import { fixturePolicy, signedPush, PUSH_AFTER_SHA, PUSH_BEFORE_SHA, PUSH_PRIVATE_MATERIAL_SHA256, PUSH_STATE_INTEGRITY_KEY, PUSH_TEST_SECRET } from "./c2-push-fixture.js";

function runtimeConfig(root: string): any {
  return {
    role: "coordinator",
    paths: { root, receipts: path.join(root, "receipts"), policies: path.join(root, "policies"), retirements: path.join(root, "retirements"), jobs: path.join(root, "jobs"), results: path.join(root, "results") },
    listenHost: "127.0.0.1",
    listenPort: 0,
    webhookRoute: "/c2-b0/github-push",
    webhookSecret: PUSH_TEST_SECRET,
    maxBodyBytes: 1024 * 1024,
    operatorDid: "did:t3n:0000000000000000000000000000000000000000",
    remediationDid: "did:t3n:0000000000000000000000000000000000000001",
    brokerDid: "did:t3n:0000000000000000000000000000000000000002",
    contractId: "z:0000000000000000000000000000000000000000:breakglass-winner-c1",
    contractVersion: "2.0.4",
    stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY,
    app: { appId: "1", installationId: "2", privateKeyPath: "C:\\outside\\app.pem", owner: "Ticoworld", repository: "t3n-breakglass-sandbox" },
    pollMs: 1000,
  };
}

function fakeC1() {
  let state: string | null = null;
  let creates = 0;
  let reservations = 0;
  return {
    getIncident: async (incidentId: string) => state ? { result: "FOUND", state, detail: { incident_id: incidentId, remediation_agent_did: "did:t3n:c2-push-local-agent", effect_broker_did: "did:t3n:c2-push-local-broker", action: "revoke_github_deploy_key", github_owner: "Ticoworld", github_repo: "t3n-breakglass-sandbox", deploy_key_id: 987654321 } } : { result: "DENIED", state: "ABSENT", detail: {} },
    createIncident: async () => { creates += 1; state = "ACTIVE"; return { result: "WON", state: "ACTIVE", detail: {} }; },
    reserveIncident: async () => { reservations += 1; state = "RESERVED"; return { result: "WON", state: "RESERVED", detail: {} }; },
    counts: () => ({ creates, reservations }),
  };
}

function sourceReader() {
  let reads = 0;
  return {
    readPlan: async () => { reads += 2; return { before: { repository: "Ticoworld/t3n-breakglass-sandbox", commit_sha: PUSH_BEFORE_SHA, path: ".breakglass-c2/exposed-deploy-key", status: 404 }, after: { repository: "Ticoworld/t3n-breakglass-sandbox", commit_sha: PUSH_AFTER_SHA, path: ".breakglass-c2/exposed-deploy-key", status: 200, content_sha256: PUSH_PRIVATE_MATERIAL_SHA256 }, token_minted: true, token_revoked: true, revoked_token_refused: true }; },
    count: () => reads,
  };
}

async function setup(t: { after(callback: () => void | Promise<void>): void }) {
  const root = await mkdtemp(path.join(tmpdir(), "breakglass-w1-coordinator-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const registry = new PolicyRegistry(root, { stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY });
  await registry.initialize();
  await registry.create(policyRegistryInputFromJson(fixturePolicy({ policy_id: "w1-coordinator-policy" })), { trustedEvidenceIdentity: "offline-fixture:w1-coordinator" });
  const c1 = fakeC1();
  const reader = sourceReader();
  const coordinator = new BreakGlassCoordinator({ config: runtimeConfig(root), registry, jobs: new RuntimeJobStore(path.join(root, "jobs"), { stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY }), c1: c1 as any, sourceReader: reader as any });
  return { root, registry, c1, reader, coordinator };
}

test("coordinator composes authenticated push, registry, immutable reader, receipt, C1 create, and remediation reserve", async (t) => {
  const { coordinator, c1, reader } = await setup(t);
  const result = await coordinator.acceptWebhook({ headers: signedPush().headers, body: signedPush().body });
  assert.equal(result.statusCode, 202);
  assert.equal(result.body.accepted, true);
  assert.equal(c1.counts().creates, 1);
  assert.equal(c1.counts().reservations, 1);
  assert.equal(reader.count(), 2);
});

test("accepted replay after retirement uses the receipt and performs zero new source reads", async (t) => {
  const { coordinator, registry, c1, reader } = await setup(t);
  const first = await coordinator.acceptWebhook({ headers: signedPush().headers, body: signedPush().body });
  assert.equal(first.body.accepted, true);
  await registry.retire("w1-coordinator-policy", 2, String(first.body.incident_id));
  const replay = await coordinator.acceptWebhook({ headers: signedPush().headers, body: signedPush().body });
  assert.equal(replay.body.accepted, true);
  assert.equal(replay.body.replayed, true);
  assert.equal(reader.count(), 2);
  assert.equal(c1.counts().creates, 1);
});

test("HTTP service enforces exact route, body bound, and raw-byte signature authentication", async (t) => {
  const { coordinator, reader } = await setup(t);
  await coordinator.start();
  t.after(() => coordinator.stop());
  const server = (coordinator as any).server;
  const port = server.address().port;
  const body = Buffer.from(JSON.stringify({ ref: "refs/heads/c2-breakglass-demo" }));
  const signed = signedPush();
  const signedBody = Buffer.from(signed.body);
  const signature = createHmac("sha256", PUSH_TEST_SECRET).update(signedBody).digest("hex");
  const base = `http://127.0.0.1:${port}`;
  assert.equal((await fetch(`${base}/wrong`, { method: "POST", body })).status, 404);
  assert.equal((await fetch(`${base}/c2-b0/github-push`, { method: "POST", body: Buffer.alloc(1025 * 1024) })).status, 413);
  assert.equal((await fetch(`${base}/c2-b0/github-push`, { method: "POST", body: signedBody, headers: { "x-github-event": "push", "x-github-delivery": "87654321-4321-4321-4321-210987654321" } })).status, 401);
  assert.equal((await fetch(`${base}/c2-b0/github-push`, { method: "POST", body: signedBody, headers: { "x-github-event": "push", "x-github-delivery": "87654321-4321-4321-4321-210987654321", "x-hub-signature-256": "sha256=bad" } })).status, 400);
  const accepted = await fetch(`${base}/c2-b0/github-push`, { method: "POST", body: signedBody, headers: { "x-github-event": "push", "x-github-delivery": "87654321-4321-4321-4321-210987654321", "x-hub-signature-256": `sha256=${signature}` } });
  assert.equal(accepted.status, 202);
  assert.equal((await accepted.json()).accepted, true);
  assert.equal(reader.count(), 2);
});
