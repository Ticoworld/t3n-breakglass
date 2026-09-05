import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const contractSource = await readFile(new URL("../contract/src/lib.rs", import.meta.url), "utf8");
const modelSource = await readFile(new URL("../contract/src/model.rs", import.meta.url), "utf8");
const witSource = await readFile(new URL("../contract/wit/world.wit", import.meta.url), "utf8");
const liveSource = await readFile(new URL("../scripts/c1-live.ts", import.meta.url), "utf8");
const seedSource = await readFile(new URL("../scripts/seed-incident.ts", import.meta.url), "utf8");
const configureSource = await readFile(new URL("../scripts/configure.ts", import.meta.url), "utf8");
const reserveSource = await readFile(new URL("../scripts/reserve-agent.ts", import.meta.url), "utf8");
const brokerSource = await readFile(new URL("../broker/run.ts", import.meta.url), "utf8");

test("C1 authority creation and read are contract exports", () => {
  assert.match(witSource, /create-incident: func/);
  assert.match(witSource, /get-incident: func/);
  assert.match(contractSource, /fn create_incident\(/);
  assert.match(contractSource, /fn get_incident\(/);
  assert.match(contractSource, /let map = incident_map\(\)/);
  assert.equal(liveSource.includes("tenant.maps.entrySet"), false);
  assert.equal(liveSource.includes("tenant.maps.entryGet"), false);
  assert.equal(seedSource.includes("tenant.maps.entrySet"), false);
  assert.equal(seedSource.includes("tenant.maps.entryGet"), false);
});

test("create boundary authenticates against runtime identity and cluster time", () => {
  assert.match(contractSource, /tenant_context::tenant_did\(\)/);
  assert.match(contractSource, /tenant_context::calling_user_did\(\)/);
  assert.match(contractSource, /operator_matches_tenant/);
  assert.match(contractSource, /tenant_context::cluster_timestamp_secs\(\)/);
  assert.match(modelSource, /pub fn operator_matches_tenant/);
  assert.match(modelSource, /now\.checked_add\(request\.ttl_secs\)/);
});

test("create input is strict and cannot supply authority target or state", () => {
  const createStruct = modelSource.slice(modelSource.indexOf("pub struct CreateIncidentRequest"), modelSource.indexOf("pub struct GetIncidentRequest"));
  assert.match(createStruct, /incident_id/);
  assert.match(createStruct, /remediation_agent_did/);
  assert.match(createStruct, /effect_broker_did/);
  assert.match(createStruct, /deploy_key_id/);
  assert.match(createStruct, /ttl_secs/);
  for (const forbidden of ["github_owner", "github_repo", "action", "created_at", "expires_at", "max_effects", "status", "reservation_id", "effect_claim_id", "final_result_classification"]) assert.equal(createStruct.includes(forbidden), false, `create request must not accept ${forbidden}`);
  assert.match(createStruct, /deny_unknown_fields/);
  const getStruct = modelSource.slice(modelSource.indexOf("pub struct GetIncidentRequest"), modelSource.indexOf("pub struct ClaimRequest"));
  assert.match(getStruct, /deny_unknown_fields/);
  assert.match(getStruct, /incident_id/);
});

test("authority fields are fixed by the contract and written only after an absent-key read", () => {
  assert.match(modelSource, /GITHUB_OWNER: &str = "Ticoworld"/);
  assert.match(modelSource, /GITHUB_REPOSITORY: &str = "t3n-breakglass-sandbox"/);
  assert.match(modelSource, /ACTION_REVOKE_GITHUB_DEPLOY_KEY/);
  assert.match(modelSource, /max_effects: 1/);
  assert.match(modelSource, /effect_attempts: 0/);
  assert.match(modelSource, /status: Status::Active/);
  const existing = contractSource.indexOf("let existing = kv_store::get");
  const write = contractSource.indexOf("kv_store::put", existing);
  assert.ok(existing >= 0 && write > existing);
  assert.match(contractSource, /if existing\.is_some\(\)/);
});

test("only the operator path receives create/get and agents retain lifecycle-only inputs", () => {
  assert.match(configureSource, /functions: \[RESERVATION_FUNCTION\]/);
  assert.match(configureSource, /functions: \[\.\.\.BROKER_FUNCTIONS\]/);
  const delegationTargets = configureSource.slice(configureSource.indexOf("const targets"), configureSource.indexOf("const { t3n"));
  assert.equal(delegationTargets.includes('"create-incident"'), false);
  assert.equal(delegationTargets.includes('"get-incident"'), false);
  assert.match(liveSource, /invokeC1OperatorSession\(t3n, CONTRACT_ID, "create-incident"/);
  assert.match(liveSource, /invokeC1OperatorSession\(t3n, CONTRACT_ID, "get-incident"/);
  assert.match(reserveSource, /input: \{ incident_id: incidentId \}/);
  assert.match(brokerSource, /expected_claim_version: expectedClaimVersion, contender_nonce: contenderNonce/);
});

test("TTL and overflow constraints are explicit and live readback is mediated", () => {
  assert.match(modelSource, /MIN_INCIDENT_TTL_SECS: u64 = 60/);
  assert.match(modelSource, /MAX_INCIDENT_TTL_SECS: u64 = 900/);
  assert.match(modelSource, /ttl_secs < MIN_INCIDENT_TTL_SECS/);
  assert.match(modelSource, /ttl_secs > MAX_INCIDENT_TTL_SECS/);
  assert.match(modelSource, /ttl_secs overflows cluster time/);
  assert.match(liveSource, /const active = requireResponse/);
  assert.match(liveSource, /ACTIVE readback mismatch/);
  assert.match(liveSource, /terminalBeforeReplay = requireResponse/);
});
