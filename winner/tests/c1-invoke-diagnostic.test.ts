import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const source = await readFile(new URL("../scripts/c1-invoke-diagnostic.ts", import.meta.url), "utf8");

test("diagnostic is operator-only and refuses provider credentials", () => {
  assert.match(source, /GITHUB_PAT/);
  assert.match(source, /GITHUB_APP_PRIVATE_KEY_PATH/);
  assert.match(source, /EFFECT_BROKER_T3N_API_KEY/);
  assert.match(source, /REPLACEMENT_AGENT_T3N_API_KEY/);
  assert.match(source, /connectTenant\(\)/);
  assert.match(source, /did !== OPERATOR_DID/);
  assert.equal(source.includes("github-app.js"), false);
  assert.equal(source.includes("deploy_key_id.*DELETE"), false);
});

test("diagnostic uses the canonical stateless and authenticated request fields", () => {
  assert.match(source, /contract_id: CONTRACT_ID/);
  assert.match(source, /contract_version: CONTRACT_VERSION/);
  assert.match(source, /function_name: functionName/);
  assert.match(source, /t3n\.executeAndDecode/);
  assert.match(source, /\/api\/invoke/);
  assert.equal(source.includes("contract: CONTRACT_ID, version:"), false);
  assert.equal(source.includes("function: functionName, input:"), false);
});

test("diagnostic performs at most one deliberately bounded create probe and verifies absence", () => {
  assert.match(source, /ttl_secs: 1/);
  assert.match(source, /create-incident/);
  assert.match(source, /post-create-nonexistence-get/);
  assert.match(source, /successful_incident_creations: 0/);
  assert.match(source, /provider_mutations: 0/);
});

test("diagnostic records SDK error fields without recording credentials", () => {
  assert.match(source, /httpStatus/);
  assert.match(source, /requestId/);
  assert.match(source, /detail/);
  assert.match(source, /credentials_in_evidence: false/);
  assert.match(source, /native_tenant_control_plane_map_write_research/);
  assert.equal(source.includes("console.log(apiKey"), false);
  assert.equal(source.includes("console\.log\(.*Authorization"), false);
  assert.match(source, /const apiKey = process\.env\.T3N_API_KEY/);
});
