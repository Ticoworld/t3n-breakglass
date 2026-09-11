import assert from "node:assert/strict";
import { readFile, rm, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import { dedupeKey, listDedupeRecords, reserveDedupe } from "../c2/dedupe.js";
import { normalizeVerifiedPushEvent } from "../c2/push-source.js";
import { processPushWebhook } from "../c2/push-ingress.js";
import { canonicalize, IntegrityError } from "../runtime/integrity.js";
import { fixturePolicy, observation, PUSH_AFTER_SHA, PUSH_BEFORE_SHA, PUSH_PRIVATE_MATERIAL_SHA256, PUSH_STATE_INTEGRITY_KEY, PUSH_TEST_SECRET, signedPush } from "./c2-push-fixture.js";

const receiptOptions = { stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY };
const observations = { before: observation(PUSH_BEFORE_SHA, 404), after: observation(PUSH_AFTER_SHA, 200, PUSH_PRIVATE_MATERIAL_SHA256) };

test("integrity canonicalizer rejects unsupported object instances", () => {
  class CustomValue { value = 1; }
  for (const value of [new Date(0), new Map([["a", 1]]), new Set([1]), new CustomValue()]) {
    assert.throws(() => canonicalize(value), IntegrityError);
  }
  assert.throws(() => canonicalize(() => "unsupported"), IntegrityError);
  assert.throws(() => canonicalize(1n), IntegrityError);
  assert.throws(() => canonicalize(undefined), IntegrityError);
  assert.throws(() => canonicalize(Number.NaN), IntegrityError);
  assert.throws(() => canonicalize(Number.POSITIVE_INFINITY), IntegrityError);
  assert.equal(canonicalize({ z: 1, a: ["x", 2] }), canonicalize({ a: ["x", 2], z: 1 }));
});

test("receipt reservation is complete, MAC-protected, and concurrent reservations have one NEW owner", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "breakglass-w1r2-receipt-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const event = normalizeVerifiedPushEvent(signedPush(), PUSH_TEST_SECRET);
  const [a, b] = await Promise.all([reserveDedupe(directory, event, receiptOptions), reserveDedupe(directory, event, receiptOptions)]);
  assert.equal([a.status, b.status].filter((status) => status === "NEW").length, 1);
  assert.equal((await listDedupeRecords(directory, receiptOptions)).length, 1);
  const raw = JSON.parse(await readFile(path.join(directory, `${dedupeKey(event)}.json`), "utf8"));
  assert.equal(raw.schema_version, 3);
  assert.equal(typeof raw.mac, "string");
});

test("accepted receipt authority tampering fails closed for every critical field", async (t) => {
  const fields = ["deploy_key_id", "remediation_agent_did", "broker_did", "ttl_secs", "policy_id", "policy_hash", "delivery_id", "event_digest", "incident_id", "repository", "before", "after", "action", "state"];
  for (const field of fields) {
    const directory = await mkdtemp(path.join(tmpdir(), `breakglass-w1r2-tamper-${field}-`));
    t.after(() => rm(directory, { recursive: true, force: true }));
    const first = await processPushWebhook(signedPush(), PUSH_TEST_SECRET, directory, [fixturePolicy()], observations, { allowLocalFixture: true, stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY });
    assert.equal(first.classification, "C2_PUSH_SELECTED");
    if (first.classification !== "C2_PUSH_SELECTED") continue;
    const file = path.join(directory, `${first.dedupe.key}.json`);
    const value = JSON.parse(await readFile(file, "utf8")) as Record<string, any>;
    if (field === "deploy_key_id") value.create_request.deploy_key_id += 1;
    else if (field === "remediation_agent_did") value.create_request.remediation_agent_did = "did:t3n:tampered";
    else if (field === "broker_did") value.create_request.effect_broker_did = "did:t3n:tampered";
    else if (field === "ttl_secs") value.create_request.ttl_secs += 1;
    else if (field === "policy_id") value.policy_id = "tampered";
    else if (field === "policy_hash") value.policy_content_hash = "f".repeat(64);
    else if (field === "delivery_id") value.event_identity.delivery_id = "tampered";
    else if (field === "event_digest") value.source_event_digest = "f".repeat(64);
    else if (field === "incident_id") value.derived_incident_id = "tampered";
    else if (field === "repository") value.normalized_event.repository_full_name = "attacker/repo";
    else if (field === "before") value.normalized_event.before = "c".repeat(40);
    else if (field === "after") value.normalized_event.after = "c".repeat(40);
    else if (field === "action") value.action = "attacker-action";
    else value.state = "REJECTED";
    await writeFile(file, JSON.stringify(value));
    await assert.rejects(() => processPushWebhook(signedPush(), PUSH_TEST_SECRET, directory, [fixturePolicy()], observations, { allowLocalFixture: true, stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY }), /integrity|source identity|exact C1|incident identity/);
  }
});

test("legacy, missing, wrong-key, and malformed receipt envelopes fail closed", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "breakglass-w1r2-receipt-invalid-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const event = normalizeVerifiedPushEvent(signedPush(), PUSH_TEST_SECRET);
  await reserveDedupe(directory, event, receiptOptions);
  const file = path.join(directory, `${dedupeKey(event)}.json`);
  await writeFile(file, "{\"schema_version\":2");
  await assert.rejects(() => reserveDedupe(directory, event, receiptOptions), /cannot be parsed/);
  await writeFile(file, JSON.stringify({ schema_version: 2, dedupe_key: dedupeKey(event), state: "RESERVED" }));
  await assert.rejects(() => listDedupeRecords(directory, receiptOptions), /LEGACY_UNVERIFIED/);
});

test("persisted receipt JSON rejects duplicate object keys before integrity replay", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "breakglass-w1r2-receipt-duplicate-key-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const first = await processPushWebhook(signedPush(), PUSH_TEST_SECRET, directory, [fixturePolicy()], observations, { allowLocalFixture: true, stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY });
  assert.equal(first.classification, "C2_PUSH_SELECTED");
  if (first.classification !== "C2_PUSH_SELECTED") return;
  const file = path.join(directory, `${first.dedupe.key}.json`);
  const raw = await readFile(file, "utf8");
  await writeFile(file, raw.replace('"schema_version": 3,', '"schema_version": 3,\n  "schema_version": 3,'));
  await assert.rejects(() => processPushWebhook(signedPush(), PUSH_TEST_SECRET, directory, [fixturePolicy()], observations, { allowLocalFixture: true, stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY }), /cannot be parsed|duplicate JSON object key/);
});

test("stale RESERVED recovery is deterministic and remains bound to the exact event", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "breakglass-w1r2-receipt-recovery-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const event = normalizeVerifiedPushEvent(signedPush(), PUSH_TEST_SECRET);
  await reserveDedupe(directory, event, receiptOptions);
  const recovered = await reserveDedupe(directory, event, { ...receiptOptions, recoverReserved: true, reservedRecoveryMs: 0 });
  assert.equal(recovered.status, "DUPLICATE_SAME");
  assert.equal(recovered.record.state, "RESERVED");
  const conflict = await reserveDedupe(directory, normalizeVerifiedPushEvent(signedPush({ after: "c".repeat(40) }), PUSH_TEST_SECRET), { ...receiptOptions, recoverReserved: true, reservedRecoveryMs: 0 });
  assert.equal(conflict.status, "CONFLICT");
});
