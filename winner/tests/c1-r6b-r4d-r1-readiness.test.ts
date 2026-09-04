import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { classifyReadiness, sanitizeEvidence } from "../scripts/c1-r6b-r4d-r1-live.js";

test("readiness classifies a complete normal application denial as pass", () => {
  assert.equal(classifyReadiness({ outcome_kind: "RETURNED_RESPONSE", sanitized_response: { function: "get-incident", result: "DENIED", note: "incident authority does not exist" } }), "R4D_R1_READINESS_PASS");
});

test("readiness preserves thrown errors and classifies only explicit quota or credit signals", () => {
  assert.equal(classifyReadiness({ outcome_kind: "THROWN_ERROR", sanitized_error_message: "transport failed" }), "R4D_R1_OTHER_READINESS_FAILURE");
  assert.equal(classifyReadiness({ outcome_kind: "THROWN_ERROR", sanitized_error_message: "fuel_per_minute quota exceeded" }), "R4D_R1_QUOTA_CONFIRMED");
  assert.equal(classifyReadiness({ outcome_kind: "RETURNED_RESPONSE", sanitized_response: { result: "DENIED", note: "credit_exhausted=true" } }), "R4D_R1_CREDIT_LIMIT_CONFIRMED");
});

test("readiness sanitization retains structure but redacts credential-bearing fields", () => {
  const value = sanitizeEvidence({ unexpected: "retained", token: "not-a-real-token", Authorization: "Bearer not-a-real-token", nested: { api_key: "not-a-real-key" } }, ["not-a-real-token"]);
  assert.deepEqual(value, { unexpected: "retained", token: "[REDACTED]", Authorization: "[REDACTED]", nested: { api_key: "[REDACTED]" } });
});

test("readiness evidence is persisted before classification and historical failure is not overwritten", async () => {
  const runner = await readFile(new URL("../scripts/c1-r6b-r4d-r1-live.ts", import.meta.url), "utf8");
  assert.match(runner, /00-readiness-context\.json/);
  assert.match(runner, /01-readiness-result\.json/);
  assert.match(runner, /outcome_kind: "RETURNED_RESPONSE"/);
  assert.match(runner, /outcome_kind: "THROWN_ERROR"/);
  assert.ok(runner.indexOf("const persistedResult = await persist(resultFile, result)") < runner.indexOf("const classification = classifyReadiness(persistedResult)"));
  assert.doesNotMatch(runner, /C1-R6B-R4D-R1-STATE-FAILURE\.json/);
});
