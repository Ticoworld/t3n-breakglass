import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const constants = await readFile(new URL("../scripts/constants.ts", import.meta.url), "utf8");
const configure = await readFile(new URL("../scripts/configure.ts", import.meta.url), "utf8");
const routing = await readFile(new URL("../scripts/c1-r5-routing.ts", import.meta.url), "utf8");
const live = await readFile(new URL("../scripts/c1-live.ts", import.meta.url), "utf8");
const broker = await readFile(new URL("../broker/run.ts", import.meta.url), "utf8");
const reserve = await readFile(new URL("../scripts/reserve-agent.ts", import.meta.url), "utf8");

test("R5 active C1 version and delegation surfaces are exact", () => {
  assert.match(constants, /CONTRACT_VERSION = "2\.0\.2"/);
  assert.match(configure, /node_routing_verified_functions/);
  assert.match(configure, /functions: \[RESERVATION_FUNCTION\]/);
  assert.match(configure, /functions: \[\.\.\.BROKER_FUNCTIONS\]/);
  assert.match(configure, /allowed_hosts: \[\]/);
  assert.match(routing, /CONTRACT_NUMERIC_ID = 876/);
  assert.match(routing, /C1_R5_LIVE_READINESS_PASS/);
  assert.match(routing, /external_provider_changes: 0/);
});

test("operator/session and opaque principal transports cannot silently cross", () => {
  assert.match(live, /invokeC1OperatorSession\(t3n, contractId, "create-incident"/);
  assert.match(live, /invokeC1OperatorSession\(t3n, contractId, "get-incident"/);
  assert.equal(live.includes("invokeC1("), false);
  assert.match(reserve, /connectC1Principal\("AGENT_T3N_API_KEY"/);
  assert.match(reserve, /invokeC1\(agent\.apiKey/);
  assert.match(broker, /connectC1Principal\("EFFECT_BROKER_T3N_API_KEY"/);
  assert.match(broker, /invokeC1\(broker\.apiKey/);
  assert.match(routing, /credential-bound DID metadata does not match/);
  assert.match(routing, /provider_counters/);
});

test("R5 routing probe is provider-free and uses only nonexistent incidents", () => {
  assert.equal(routing.includes("github-app.js"), false);
  assert.equal(routing.includes("fetch("), false);
  assert.match(routing, /fresh\("remediation-reserve"\)/);
  assert.match(routing, /fresh\(`broker-\$\{functionName/);
  assert.match(routing, /successful_incident_creations: 0/);
  assert.match(routing, /map_entry_writes: 0/);
  assert.match(routing, /github_api_calls: 0/);
});

test("R5 readiness review gates current configuration before target setup", () => {
  const configCheck = live.indexOf("live identity/configuration does not match");
  const targetSetup = live.indexOf("prepare-target.ts");
  assert.ok(configCheck >= 0 && targetSetup > configCheck);
  assert.match(routing, /active_version_and_registration_match/);
  assert.match(routing, /terminal_state_is_gated/);
  assert.match(routing, /ambiguous_provider_effect_is_not_retried/);
});
