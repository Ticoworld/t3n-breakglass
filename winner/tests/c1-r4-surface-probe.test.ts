import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const source = await readFile(new URL("../scripts/c1-r4-surface-probe.ts", import.meta.url), "utf8");

test("R4 surface probe is operator-session-only and provider-free", () => {
  assert.match(source, /connectTenant\(\)/);
  assert.match(source, /executeAndDecode/);
  assert.match(source, /GITHUB_PAT/);
  assert.match(source, /GITHUB_APP_PRIVATE_KEY_PATH/);
  assert.match(source, /EFFECT_BROKER_T3N_API_KEY/);
  assert.equal(source.includes("github-app.js"), false);
  assert.equal(source.includes("fetch("), false);
  assert.equal(source.includes("entrySet"), false);
  assert.equal(source.includes("executeControl"), false);
});

test("R4 probe covers all six safe nonexistent-incident functions and one invalid create", () => {
  for (const name of ["get-incident", "reserve-incident", "claim-effect", "release-not-attempted", "finalize-effect", "reconcile-effect"]) assert.match(source, new RegExp(name));
  assert.match(source, /ttl_secs: 1/);
  assert.match(source, /deploy_key_id: 1/);
  assert.match(source, /successful_incident_creation: false/);
  assert.match(source, /map_entry_writes: 0/);
});

test("R4 evidence distinguishes local exports, routing, and guest execution", () => {
  assert.match(source, /pre_rebuild_exports/);
  assert.match(source, /post_rebuild_exports/);
  assert.match(source, /node_routing_verified_functions/);
  assert.match(source, /guest_execution_verified/);
  assert.match(source, /REGISTERED_SURFACE_MISMATCH/);
});
