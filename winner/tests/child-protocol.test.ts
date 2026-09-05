import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { parseChildJson } from "../scripts/child-protocol.js";

const liveSource = await readFile(new URL("../scripts/c1-live.ts", import.meta.url), "utf8");

test("child protocol parses compact JSON objects", () => {
  assert.deepEqual(parseChildJson('{"status":"READY","id":7}'), { status: "READY", id: 7 });
});

test("child protocol parses one complete formatted JSON document", () => {
  const formatted = JSON.stringify({ status: "READY", target: { id: 7, read_only: true } }, null, 2);
  assert.deepEqual(parseChildJson(formatted), { status: "READY", target: { id: 7, read_only: true } });
});

test("stderr diagnostics do not corrupt the stdout machine document", () => {
  const child = { stdout: JSON.stringify({ claim_outcome: "CLAIM_LOST" }, null, 2), stderr: "human-readable diagnostic\n" };
  assert.deepEqual(parseChildJson(child.stdout), { claim_outcome: "CLAIM_LOST" });
  assert.equal(child.stderr.includes("claim_outcome"), false);
});

test("malformed child output fails before the incident authority write", () => {
  assert.throws(() => parseChildJson('{"status":"READY"'), /one complete JSON document/);
  const parsedTarget = liveSource.indexOf("targetSetup");
  const authorityCreate = liveSource.indexOf('invokeC1OperatorSession(t3n, CONTRACT_ID, "create-incident"');
  assert.ok(parsedTarget >= 0 && authorityCreate > parsedTarget);
  assert.equal(liveSource.includes("tenant.maps.entrySet"), false);
  assert.equal(liveSource.includes("tenant.maps.entryGet"), false);
});

test("all machine-consumed C1 child outputs use the complete-document parser", () => {
  assert.equal((liveSource.match(/parseChildJson\(/g) ?? []).length, 2);
  assert.equal(liveSource.includes("lines.at(-1)"), false);
});

test("live broker children use durable per-run result files", () => {
  assert.match(liveSource, /broker-a\.result\.json/);
  assert.match(liveSource, /broker-b\.result\.json/);
  assert.match(liveSource, /replay\.result\.json/);
  assert.match(liveSource, /readJsonFile<JsonObject>\(brokerAResultFile\)/);
  assert.match(liveSource, /C1-R6B-R4E-R1-PROVIDER-FAILURE\.json/);
});
