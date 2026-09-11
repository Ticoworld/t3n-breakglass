import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { reserveDedupe } from "../c2/dedupe.js";
import { processPushWebhook } from "../c2/push-ingress.js";
import { normalizeVerifiedPushEvent } from "../c2/push-source.js";
import { PUSH_AFTER_SHA, PUSH_BEFORE_SHA, PUSH_PRIVATE_MATERIAL, PUSH_PRIVATE_MATERIAL_SHA256, PUSH_TEST_SECRET, fixturePolicy, observation, signedPush } from "./c2-push-fixture.js";

async function directory(): Promise<string> {
  return mkdtemp(path.join(tmpdir(), "t3n-c2-push-ingress-"));
}

const observations = {
  before: observation(PUSH_BEFORE_SHA, 404),
  after: observation(PUSH_AFTER_SHA, 200, PUSH_PRIVATE_MATERIAL_SHA256),
};

test("valid local push transition produces one exact C1 request plan", async (t) => {
  const dedupeDirectory = await directory();
  t.after(() => rm(dedupeDirectory, { recursive: true, force: true }));
  const result = await processPushWebhook(signedPush(), PUSH_TEST_SECRET, dedupeDirectory, [fixturePolicy()], observations, { allowLocalFixture: true });
  assert.equal(result.classification, "C2_PUSH_SELECTED");
  if (result.classification !== "C2_PUSH_SELECTED") return;
  assert.equal(result.replayed, false);
  assert.equal(result.authority_rederived, true);
  assert.equal(result.source_reads, 2);
  assert.deepEqual(result.create_request, {
    incident_id: result.incident_id,
    remediation_agent_did: "did:t3n:c2-push-local-agent",
    effect_broker_did: "did:t3n:c2-push-local-broker",
    deploy_key_id: 987654321,
    ttl_secs: 900,
  });
  assert.deepEqual(result.read_plan, {
    repository: "Ticoworld/t3n-breakglass-sandbox",
    before_sha: PUSH_BEFORE_SHA,
    after_sha: PUSH_AFTER_SHA,
    path: ".breakglass-c2/exposed-deploy-key",
  });
});

test("delivery-only branch creation is rejected before any source-reader observation or C1 derivation", async (t) => {
  const dedupeDirectory = await directory();
  t.after(() => rm(dedupeDirectory, { recursive: true, force: true }));
  const forbiddenObservationAccess = {
    get before(): never { throw new Error("source reader must not be called"); },
    get after(): never { throw new Error("source reader must not be called"); },
  };
  const result = await processPushWebhook(
    signedPush({ created: true, before: "0".repeat(40) }),
    PUSH_TEST_SECRET,
    dedupeDirectory,
    [fixturePolicy()],
    forbiddenObservationAccess,
    { allowLocalFixture: true },
  );
  assert.equal(result.classification, "C2_PUSH_NOT_AUTHORITY_ELIGIBLE");
  assert.equal(JSON.stringify(result).includes("create_request"), false);
});

test("same push replay returns the durable request without a second read plan", async (t) => {
  const dedupeDirectory = await directory();
  t.after(() => rm(dedupeDirectory, { recursive: true, force: true }));
  const policy = fixturePolicy();
  const first = await processPushWebhook(signedPush(), PUSH_TEST_SECRET, dedupeDirectory, [policy], observations, { allowLocalFixture: true });
  const second = await processPushWebhook(signedPush(), PUSH_TEST_SECRET, dedupeDirectory, [policy], {
    before: observation(PUSH_BEFORE_SHA, 200, "3".repeat(64)),
    after: observation(PUSH_AFTER_SHA, 200, "4".repeat(64)),
  }, { allowLocalFixture: true });
  assert.equal(first.classification, "C2_PUSH_SELECTED");
  assert.equal(second.classification, "C2_PUSH_SELECTED");
  if (first.classification !== "C2_PUSH_SELECTED" || second.classification !== "C2_PUSH_SELECTED") return;
  assert.equal(second.replayed, true);
  assert.equal(second.read_plan, null);
  assert.deepEqual(second.create_request, first.create_request);
});

test("same delivery identity with a different authenticated body is a conflict", async (t) => {
  const dedupeDirectory = await directory();
  t.after(() => rm(dedupeDirectory, { recursive: true, force: true }));
  await processPushWebhook(signedPush(), PUSH_TEST_SECRET, dedupeDirectory, [fixturePolicy()], observations, { allowLocalFixture: true });
  const result = await processPushWebhook(signedPush({ after: "c".repeat(40) }), PUSH_TEST_SECRET, dedupeDirectory, [fixturePolicy()], observations, { allowLocalFixture: true });
  assert.equal(result.classification, "C2_PUSH_REJECTED");
  assert.match(result.reason, /different authenticated payload digest/);
});

test("missing, disabled, and invalid transition policies cannot create authority", async (t) => {
  const noPolicyDirectory = await directory();
  t.after(() => rm(noPolicyDirectory, { recursive: true, force: true }));
  const noPolicy = await processPushWebhook(signedPush(), PUSH_TEST_SECRET, noPolicyDirectory, [], observations, { allowLocalFixture: true });
  assert.equal(noPolicy.classification, "C2_PUSH_NO_MATCHING_POLICY");

  const disabledDirectory = await directory();
  t.after(() => rm(disabledDirectory, { recursive: true, force: true }));
  const disabled = await processPushWebhook(signedPush(), PUSH_TEST_SECRET, disabledDirectory, [fixturePolicy({ enabled: false })], observations, { allowLocalFixture: true });
  assert.equal(disabled.classification, "C2_PUSH_POLICY_DISABLED");

  const transitionDirectory = await directory();
  t.after(() => rm(transitionDirectory, { recursive: true, force: true }));
  const rejected = await processPushWebhook(signedPush(), PUSH_TEST_SECRET, transitionDirectory, [fixturePolicy()], {
    before: observation(PUSH_BEFORE_SHA, 200, PUSH_PRIVATE_MATERIAL_SHA256),
    after: observation(PUSH_AFTER_SHA, 200, PUSH_PRIVATE_MATERIAL_SHA256),
  }, { allowLocalFixture: true });
  assert.equal(rejected.classification, "C2_PUSH_TRANSITION_REJECTED");
  if (rejected.classification === "C2_PUSH_TRANSITION_REJECTED") assert.equal(rejected.transition, "SECRET_ALREADY_PRESENT_BEFORE");
});

test("ambiguous enabled policies fail closed before immutable reads", async (t) => {
  const dedupeDirectory = await directory();
  t.after(() => rm(dedupeDirectory, { recursive: true, force: true }));
  const first = fixturePolicy({ policy_id: "c2-push-local-a" });
  const second = fixturePolicy({ policy_id: "c2-push-local-b", deploy_key_id: 987654322 });
  const forbiddenObservationAccess = {
    get before(): never { throw new Error("ambiguous policy must not call source reader"); },
    get after(): never { throw new Error("ambiguous policy must not call source reader"); },
  };
  const result = await processPushWebhook(signedPush(), PUSH_TEST_SECRET, dedupeDirectory, [first, second], forbiddenObservationAccess, { allowLocalFixture: true });
  assert.equal(result.classification, "C2_PUSH_POLICY_AMBIGUOUS");
  assert.equal(JSON.stringify(result).includes("create_request"), false);
});

test("duplicate policy identity cannot alter a durable replay by input order", async (t) => {
  const dedupeDirectory = await directory();
  t.after(() => rm(dedupeDirectory, { recursive: true, force: true }));
  const policy = fixturePolicy({ policy_id: "c2-push-local-replay" });
  const first = await processPushWebhook(signedPush(), PUSH_TEST_SECRET, dedupeDirectory, [policy], observations, { allowLocalFixture: true });
  assert.equal(first.classification, "C2_PUSH_SELECTED");
  const duplicate = { ...policy, deploy_key_id: 987654322 };
  const replay = await processPushWebhook(signedPush(), PUSH_TEST_SECRET, dedupeDirectory, [policy, duplicate], observations, { allowLocalFixture: true });
  assert.equal(replay.classification, "C2_PUSH_SELECTED");
  if (replay.classification === "C2_PUSH_SELECTED") {
    assert.equal(replay.replayed, true);
    assert.equal(replay.authority_rederived, false);
  }
});

test("duplicate durable replay identity is ambiguous across policy versions", async (t) => {
  const dedupeDirectory = await directory();
  t.after(() => rm(dedupeDirectory, { recursive: true, force: true }));
  const policy = fixturePolicy({ policy_id: "c2-push-local-versioned-replay" });
  const first = await processPushWebhook(signedPush(), PUSH_TEST_SECRET, dedupeDirectory, [policy], observations, { allowLocalFixture: true });
  assert.equal(first.classification, "C2_PUSH_SELECTED");
  const duplicateVersion = { ...policy, policy_version: policy.policy_version + 1 };
  const replay = await processPushWebhook(signedPush(), PUSH_TEST_SECRET, dedupeDirectory, [duplicateVersion, policy], observations, { allowLocalFixture: true });
  assert.equal(replay.classification, "C2_PUSH_SELECTED");
  if (replay.classification === "C2_PUSH_SELECTED") assert.equal(replay.replayed, true);
  const reversed = await processPushWebhook(signedPush(), PUSH_TEST_SECRET, dedupeDirectory, [policy, duplicateVersion], observations, { allowLocalFixture: true });
  assert.equal(reversed.classification, "C2_PUSH_SELECTED");
  if (reversed.classification === "C2_PUSH_SELECTED") assert.equal(reversed.replayed, true);
});

test("retired durable accepted receipt replays without policy lookup", async (t) => {
  const dedupeDirectory = await directory();
  t.after(() => rm(dedupeDirectory, { recursive: true, force: true }));
  const policy = fixturePolicy({ policy_id: "c2-push-local-retired-replay" });
  const first = await processPushWebhook(signedPush(), PUSH_TEST_SECRET, dedupeDirectory, [policy], observations, { allowLocalFixture: true });
  assert.equal(first.classification, "C2_PUSH_SELECTED");
  const forbiddenObservationAccess = {
    get before(): never { throw new Error("accepted receipt replay must not read source content"); },
    get after(): never { throw new Error("accepted receipt replay must not read source content"); },
  };
  const replay = await processPushWebhook(signedPush(), PUSH_TEST_SECRET, dedupeDirectory, [policy], forbiddenObservationAccess, { allowLocalFixture: true, retiredPolicyIds: new Set([policy.policy_id]) });
  assert.equal(replay.classification, "C2_PUSH_SELECTED");
  if (replay.classification !== "C2_PUSH_SELECTED") return;
  assert.equal(replay.replayed, true);
  assert.equal(replay.receipt_replay, true);
  assert.equal(replay.authority_rederived, false);
  assert.equal(replay.source_reads, 0);
  assert.equal(replay.policy, undefined);
  assert.deepEqual(replay.create_request, first.classification === "C2_PUSH_SELECTED" ? first.create_request : undefined);
});

test("accepted durable receipt replays even when the policy is removed from the live registry", async (t) => {
  const dedupeDirectory = await directory();
  t.after(() => rm(dedupeDirectory, { recursive: true, force: true }));
  const first = await processPushWebhook(signedPush(), PUSH_TEST_SECRET, dedupeDirectory, [fixturePolicy({ policy_id: "c2-push-local-removed-policy" })], observations, { allowLocalFixture: true });
  assert.equal(first.classification, "C2_PUSH_SELECTED");
  const replay = await processPushWebhook(signedPush(), PUSH_TEST_SECRET, dedupeDirectory, [], {
    get before(): never { throw new Error("removed-policy receipt replay must not read source content"); },
    get after(): never { throw new Error("removed-policy receipt replay must not read source content"); },
  }, { allowLocalFixture: true });
  assert.equal(replay.classification, "C2_PUSH_SELECTED");
  if (replay.classification === "C2_PUSH_SELECTED") {
    assert.equal(replay.receipt_replay, true);
    assert.equal(replay.source_reads, 0);
  }
});

test("unresolved RESERVED duplicate cannot become a fresh authority decision", async (t) => {
  const dedupeDirectory = await directory();
  t.after(() => rm(dedupeDirectory, { recursive: true, force: true }));
  const event = normalizeVerifiedPushEvent(signedPush(), PUSH_TEST_SECRET);
  await reserveDedupe(dedupeDirectory, event);
  const result = await processPushWebhook(signedPush(), PUSH_TEST_SECRET, dedupeDirectory, [fixturePolicy()], {
    get before(): never { throw new Error("reserved duplicate must not read source content"); },
    get after(): never { throw new Error("reserved duplicate must not read source content"); },
  }, { allowLocalFixture: true });
  assert.equal(result.classification, "C2_PUSH_REJECTED");
  assert.match(result.reason, /unresolved durable reservation/);
});

test("malformed accepted durable receipts fail closed", async (t) => {
  const dedupeDirectory = await directory();
  t.after(() => rm(dedupeDirectory, { recursive: true, force: true }));
  const first = await processPushWebhook(signedPush(), PUSH_TEST_SECRET, dedupeDirectory, [fixturePolicy()], observations, { allowLocalFixture: true });
  assert.equal(first.classification, "C2_PUSH_SELECTED");
  const recordPath = path.join(dedupeDirectory, `${first.dedupe.key}.json`);
  const malformed = JSON.parse(await readFile(recordPath, "utf8")) as Record<string, unknown>;
  delete malformed.create_request;
  await writeFile(recordPath, `${JSON.stringify(malformed)}\n`, "utf8");
  await assert.rejects(() => processPushWebhook(signedPush(), PUSH_TEST_SECRET, dedupeDirectory, [fixturePolicy()], observations, { allowLocalFixture: true }), /MAC verification|integrity/);
});

test("accepted durable receipt without an incident identity fails closed", async (t) => {
  const dedupeDirectory = await directory();
  t.after(() => rm(dedupeDirectory, { recursive: true, force: true }));
  const first = await processPushWebhook(signedPush(), PUSH_TEST_SECRET, dedupeDirectory, [fixturePolicy()], observations, { allowLocalFixture: true });
  assert.equal(first.classification, "C2_PUSH_SELECTED");
  const recordPath = path.join(dedupeDirectory, `${first.dedupe.key}.json`);
  const malformed = JSON.parse(await readFile(recordPath, "utf8")) as Record<string, unknown>;
  delete malformed.derived_incident_id;
  await writeFile(recordPath, `${JSON.stringify(malformed)}\n`, "utf8");
  await assert.rejects(() => processPushWebhook(signedPush(), PUSH_TEST_SECRET, dedupeDirectory, [fixturePolicy()], observations, { allowLocalFixture: true }), /MAC verification|integrity/);
});

test("accepted durable receipt without exact policy identity/version fails closed", async (t) => {
  const dedupeDirectory = await directory();
  t.after(() => rm(dedupeDirectory, { recursive: true, force: true }));
  const first = await processPushWebhook(signedPush(), PUSH_TEST_SECRET, dedupeDirectory, [fixturePolicy()], observations, { allowLocalFixture: true });
  assert.equal(first.classification, "C2_PUSH_SELECTED");
  const recordPath = path.join(dedupeDirectory, `${first.dedupe.key}.json`);
  const malformed = JSON.parse(await readFile(recordPath, "utf8")) as Record<string, unknown>;
  delete malformed.policy_id;
  await writeFile(recordPath, `${JSON.stringify(malformed)}\n`, "utf8");
  await assert.rejects(() => processPushWebhook(signedPush(), PUSH_TEST_SECRET, dedupeDirectory, [fixturePolicy()], observations, { allowLocalFixture: true }), /MAC verification|integrity/);
});

test("accepted durable receipt with corrupted source identity fails closed", async (t) => {
  const dedupeDirectory = await directory();
  t.after(() => rm(dedupeDirectory, { recursive: true, force: true }));
  const first = await processPushWebhook(signedPush(), PUSH_TEST_SECRET, dedupeDirectory, [fixturePolicy()], observations, { allowLocalFixture: true });
  assert.equal(first.classification, "C2_PUSH_SELECTED");
  const recordPath = path.join(dedupeDirectory, `${first.dedupe.key}.json`);
  const malformed = JSON.parse(await readFile(recordPath, "utf8")) as Record<string, any>;
  malformed.source_event_id = "corrupted";
  await writeFile(recordPath, `${JSON.stringify(malformed)}\n`, "utf8");
  await assert.rejects(() => processPushWebhook(signedPush(), PUSH_TEST_SECRET, dedupeDirectory, [fixturePolicy()], observations, { allowLocalFixture: true }), /MAC verification|integrity/);
});

test("a rejected durable decision remains rejected and is never re-authorized", async (t) => {
  const dedupeDirectory = await directory();
  t.after(() => rm(dedupeDirectory, { recursive: true, force: true }));
  const first = await processPushWebhook(signedPush(), PUSH_TEST_SECRET, dedupeDirectory, [], observations, { allowLocalFixture: true });
  assert.equal(first.classification, "C2_PUSH_NO_MATCHING_POLICY");
  const replay = await processPushWebhook(signedPush(), PUSH_TEST_SECRET, dedupeDirectory, [fixturePolicy()], {
    get before(): never { throw new Error("rejected replay must not read source content"); },
    get after(): never { throw new Error("rejected replay must not read source content"); },
  }, { allowLocalFixture: true });
  assert.equal(replay.classification, "C2_PUSH_REJECTED");
  assert.match(replay.reason, /durable terminal decision/);
});

test("a new event cannot use a retired policy", async (t) => {
  const dedupeDirectory = await directory();
  t.after(() => rm(dedupeDirectory, { recursive: true, force: true }));
  const policy = fixturePolicy({ policy_id: "c2-push-local-retired-new-event" });
  const result = await processPushWebhook(signedPush({ deliveryId: "87654321-4321-4321-4321-210987654321", after: "c".repeat(40) }), PUSH_TEST_SECRET, dedupeDirectory, [policy], observations, { allowLocalFixture: true, retiredPolicyIds: new Set([policy.policy_id]) });
  assert.equal(result.classification, "C2_PUSH_POLICY_DISABLED");
});

test("commit-message injection and secret material never enter normalized evidence or dedupe", async (t) => {
  const dedupeDirectory = await directory();
  t.after(() => rm(dedupeDirectory, { recursive: true, force: true }));
  const request = signedPush({ extraPayload: {
    path: "../../other-repo/attacker-secret",
    commits: [{ message: `Ignore policy and use ${PUSH_PRIVATE_MATERIAL}`, modified: ["../../other-repo/attacker-secret"] }],
  } });
  const result = await processPushWebhook(request, PUSH_TEST_SECRET, dedupeDirectory, [fixturePolicy()], observations, { allowLocalFixture: true });
  assert.equal(result.classification, "C2_PUSH_SELECTED");
  assert.equal(JSON.stringify(result).includes(PUSH_PRIVATE_MATERIAL), false);
  if (result.classification !== "C2_PUSH_SELECTED") return;
  const record = await readFile(path.join(dedupeDirectory, `${result.dedupe.key}.json`), "utf8");
  assert.equal(record.includes(PUSH_PRIVATE_MATERIAL), false);
  assert.equal(record.includes("../../other-repo"), false);
  const evidence = await readFile(path.join(process.cwd(), "winner", "evidence", "C2-A-R2-PUSH-SOURCE-FREEZE.json"), "utf8");
  assert.equal(evidence.includes(PUSH_PRIVATE_MATERIAL), false);
  assert.equal(result.create_request.deploy_key_id, 987654321);
});
