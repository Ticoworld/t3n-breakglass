import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const surface = await readFile(new URL("../scripts/c1-r6b-surface.ts", import.meta.url), "utf8");

test("R6B surface probe keeps strict create input separate from safe nonexistent probes", () => {
  assert.match(surface, /const SURFACE_FUNCTIONS = \["get-incident", RESERVATION_FUNCTION, \.\.\.BROKER_FUNCTIONS\]/);
  assert.match(surface, /invalidCreateId/);
  assert.match(surface, /ttl_secs: 1/);
  assert.doesNotMatch(surface, /for \(const functionName of ALL_FUNCTIONS\)/);
});

test("R6B surface probe is operator-session-only and provider-free", () => {
  assert.match(surface, /invokeC1OperatorSession/);
  assert.doesNotMatch(surface, /github-app|prepare-target|broker\/run/);
  assert.match(surface, /provider_operations: 0/);
});
