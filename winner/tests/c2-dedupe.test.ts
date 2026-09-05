import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { processGithubWebhook } from "../c2/ingress.js";
import { C2_POLICY } from "../c2/policy.js";
import { TEST_SECRET, signedFixture } from "./c2-fixture.js";

test("exact duplicate returns the existing causal incident reference", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "t3n-c2-dedupe-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const first = await processGithubWebhook(signedFixture(), TEST_SECRET, directory);
  const second = await processGithubWebhook(signedFixture(), TEST_SECRET, directory);
  assert.equal(first.classification, "C2_SOURCE_SELECTED");
  assert.equal(second.classification, "C2_SOURCE_SELECTED");
  if (first.classification === "C2_SOURCE_SELECTED" && second.classification === "C2_SOURCE_SELECTED") {
    assert.equal(second.dedupe.status, "DUPLICATE_SAME");
    assert.equal(second.incident_id, first.incident_id);
    assert.deepEqual(second.create_request, first.create_request);
  }
});

test("same delivery identity with a different authenticated body is a conflict", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "t3n-c2-conflict-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await processGithubWebhook(signedFixture(), TEST_SECRET, directory);
  const conflict = await processGithubWebhook(signedFixture({ alertNumber: 18 }), TEST_SECRET, directory);
  assert.equal(conflict.classification, "C2_SOURCE_REJECTED");
  assert.match(conflict.reason, /different authenticated payload digest/);
  assert.equal(conflict.dedupe.status, "CONFLICT");
});

test("a terminal duplicate is not re-authorized by a later policy change", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "t3n-c2-policy-replay-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const first = await processGithubWebhook(signedFixture(), TEST_SECRET, directory, []);
  assert.equal(first.classification, "C2_NO_MATCHING_POLICY");
  const laterPolicy = { ...C2_POLICY, created_at: "2026-09-05T12:00:00.000Z" };
  const replay = await processGithubWebhook(signedFixture(), TEST_SECRET, directory, [laterPolicy]);
  assert.equal(replay.classification, "C2_SOURCE_REJECTED");
  assert.match(replay.reason, /durable terminal decision/);
});
