import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { processGithubWebhook } from "../c2/ingress.js";
import { C2_POLICY } from "../c2/policy.js";
import { TEST_SECRET, signedFixture } from "./c2-fixture.js";

test("same authenticated event and policy derive the same incident ID", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "t3n-c2-causality-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const first = await processGithubWebhook(signedFixture(), TEST_SECRET, directory);
  const second = await processGithubWebhook(signedFixture(), TEST_SECRET, directory);
  assert.equal(first.classification, "C2_SOURCE_SELECTED");
  assert.equal(second.classification, "C2_SOURCE_SELECTED");
  if (first.classification === "C2_SOURCE_SELECTED" && second.classification === "C2_SOURCE_SELECTED") {
    assert.match(first.incident_id, new RegExp(`^C2-${C2_POLICY.policy_id}-[0-9a-f]{24}$`));
    assert.equal(first.incident_id, second.incident_id);
    assert.equal(first.dedupe.record.source_event_digest, second.dedupe.record.source_event_digest);
  }
});
test("different authenticated events derive different incident IDs", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "t3n-c2-different-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const first = await processGithubWebhook(signedFixture(), TEST_SECRET, directory);
  const second = await processGithubWebhook(signedFixture({
    deliveryId: "22222222-2222-4222-8222-222222222222",
    alertNumber: 18,
  }), TEST_SECRET, directory);
  assert.equal(first.classification, "C2_SOURCE_SELECTED");
  assert.equal(second.classification, "C2_SOURCE_SELECTED");
  if (first.classification === "C2_SOURCE_SELECTED" && second.classification === "C2_SOURCE_SELECTED") {
    assert.notEqual(first.incident_id, second.incident_id);
  }
});
