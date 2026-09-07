import assert from "node:assert/strict";
import { readFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { createR2BReplayWebhookServer } from "../c2/replay-webhook-server.js";
import { signedPush, PUSH_AFTER_SHA, PUSH_BEFORE_SHA, PUSH_TEST_SECRET } from "./c2-push-fixture.js";

async function listen(server: ReturnType<typeof createR2BReplayWebhookServer>["server"]): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error) => { server.off("listening", onListening); reject(error); };
    const onListening = () => { server.off("error", onError); resolve(); };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(0, "127.0.0.1");
  });
  const address = server.address();
  assert.ok(address && typeof address === "object");
  return address.port;
}

test("R2B replay receiver authenticates the exact event and persists sanitized metadata only", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "t3n-c2-r2b-replay-test-"));
  const capturePath = path.join(directory, "capture.json");
  const server = createR2BReplayWebhookServer({
    webhookSecret: PUSH_TEST_SECRET,
    capturePath,
    expectedDeliveryId: "22222222-2222-4222-8222-222222222222",
    expectedBefore: PUSH_BEFORE_SHA,
    expectedAfter: PUSH_AFTER_SHA,
  });
  t.after(async () => { await server.close().catch(() => undefined); await rm(directory, { recursive: true, force: true }); });
  const port = await listen(server.server);
  const request = signedPush();
  const response = await fetch(`http://127.0.0.1:${port}/c2-b0/github-push`, { method: "POST", headers: request.headers as Record<string, string>, body: Buffer.from(request.body) });
  assert.equal(response.status, 202);
  const capture = server.getCapture();
  assert.ok(capture);
  assert.equal(capture.event.delivery_id, request.headers["X-GitHub-Delivery"]);
  assert.equal(capture.event.raw_body_sha256.length, 64);
  assert.equal(capture.evidence.signature_verified, true);
  assert.equal(capture.evidence.raw_body_persisted, false);
  assert.equal(capture.evidence.authority_processing_attempted, false);
  assert.equal(capture.evidence.source_reader_calls, 0);
  assert.equal(capture.evidence.c1_request_created, false);
  const serialized = await readFile(capturePath, "utf8");
  assert.equal(serialized.includes('"raw_body":'), false);
  assert.equal(serialized.includes("X-Hub-Signature-256"), false);
});

test("R2B replay receiver rejects a different delivery and never captures it", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "t3n-c2-r2b-replay-negative-"));
  const server = createR2BReplayWebhookServer({
    webhookSecret: PUSH_TEST_SECRET,
    capturePath: path.join(directory, "capture.json"),
    expectedDeliveryId: "22222222-2222-4222-8222-222222222222",
    expectedBefore: PUSH_BEFORE_SHA,
    expectedAfter: PUSH_AFTER_SHA,
  });
  t.after(async () => { await server.close().catch(() => undefined); await rm(directory, { recursive: true, force: true }); });
  const port = await listen(server.server);
  const request = signedPush({ deliveryId: "33333333-3333-4333-8333-333333333333" });
  const response = await fetch(`http://127.0.0.1:${port}/c2-b0/github-push`, { method: "POST", headers: request.headers as Record<string, string>, body: Buffer.from(request.body) });
  assert.equal(response.status, 400);
  assert.equal(server.getCapture(), null);
});
