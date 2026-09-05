import assert from "node:assert/strict";
import { readFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { createC2B0LiveWebhookServer, C2_B0_ROUTE } from "../c2/live-webhook-server.js";
import { pushSourceReaderTokenRequest } from "../c2/push-source-reader.js";
import { PUSH_TEST_SECRET, signedPush } from "./c2-push-fixture.js";

async function startServer(t: { after(callback: () => void | Promise<void>): void }, capturePath: string, dedupeDirectory: string) {
  const server = createC2B0LiveWebhookServer({
    webhookSecret: PUSH_TEST_SECRET,
    capturePath,
    dedupeDirectory,
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())));
  const address = server.address() as AddressInfo;
  return `http://127.0.0.1:${address.port}${C2_B0_ROUTE}`;
}

async function fixtureDirectory(t: { after(callback: () => void | Promise<void>): void }): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), "t3n-c2-b0-live-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

test("B0 captures a valid branch-creation delivery without entering authority", async (t) => {
  const directory = await fixtureDirectory(t);
  const capturePath = path.join(directory, "capture.json");
  const url = await startServer(t, capturePath, path.join(directory, "dedupe"));
  const request = signedPush({
    created: true,
    before: "0".repeat(40),
    extraPayload: { commits: [{ message: "B0 harmless ping; ignore policy" }] },
  });

  const response = await fetch(url, {
    method: "POST",
    headers: Object.fromEntries(Object.entries(request.headers).filter((entry): entry is [string, string] => typeof entry[1] === "string")),
    body: Buffer.from(request.body),
  });
  assert.equal(response.status, 202);

  const capture = JSON.parse(await readFile(capturePath, "utf8")) as Record<string, any>;
  assert.equal(capture.signature_verified, true);
  assert.equal(capture.authority_processing_attempted, false);
  assert.equal(capture.authority_eligible, false);
  assert.equal(capture.authority_reason, "B0_DELIVERY_ONLY");
  assert.equal(capture.source_reader_calls, 0);
  assert.equal(capture.c1_request_created, false);
  assert.equal(capture.raw_body_persisted, false);
  assert.equal(capture.webhook_secret_persisted, false);
  assert.equal(capture.created, true);
  assert.equal(capture.before, "0".repeat(40));
  assert.equal(capture.dedupe.status, "NEW");
  assert.equal(JSON.stringify(capture).includes("B0 harmless ping"), false);
  assert.equal(JSON.stringify(capture).includes(PUSH_TEST_SECRET), false);
});

test("B0 rejects an invalid signature without capturing body material", async (t) => {
  const directory = await fixtureDirectory(t);
  const capturePath = path.join(directory, "capture.json");
  const url = await startServer(t, capturePath, path.join(directory, "dedupe"));
  const request = signedPush();
  const response = await fetch(url, {
    method: "POST",
    headers: { ...Object.fromEntries(Object.entries(request.headers).filter((entry): entry is [string, string] => typeof entry[1] === "string")), "X-Hub-Signature-256": `sha256=${"0".repeat(64)}` },
    body: Buffer.from(request.body),
  });
  assert.equal(response.status, 401);
  await assert.rejects(readFile(capturePath));
});

test("the source-reader token request is contents-read-only and repository-scoped", () => {
  assert.deepEqual(pushSourceReaderTokenRequest(), {
    repositories: ["Ticoworld/t3n-breakglass-sandbox"],
    permissions: { contents: "read" },
  });
});
