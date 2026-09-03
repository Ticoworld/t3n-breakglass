import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const constants = await readFile(new URL("../scripts/constants.ts", import.meta.url), "utf8");
const rust = await readFile(new URL("../contract/src/lib.rs", import.meta.url), "utf8");
const live = await readFile(new URL("../scripts/c1-live.ts", import.meta.url), "utf8");
const seed = await readFile(new URL("../scripts/seed-incident.ts", import.meta.url), "utf8");
const reserve = await readFile(new URL("../scripts/reserve-agent.ts", import.meta.url), "utf8");
const broker = await readFile(new URL("../broker/run.ts", import.meta.url), "utf8");
const register = await readFile(new URL("../scripts/register.ts", import.meta.url), "utf8");

const functions = ["create-incident", "get-incident", "reserve-incident", "claim-effect", "release-not-attempted", "begin-effect", "finalize-effect", "reconcile-effect"];

test("C1 R4 version and local source surface agree", () => {
  assert.match(constants, /CONTRACT_VERSION = "2\.0\.3"/);
  assert.match(rust, /CONTRACT_VERSION: &str = "2\.0\.3"/);
  for (const name of functions) assert.match(rust, new RegExp(name.replaceAll("-", "_")));
});

test("operator create/get use session execution while agents retain opaque invoke", () => {
  assert.equal((live.match(/invokeC1OperatorSession\(t3n/g) ?? []).length, 6);
  assert.equal(live.includes("invokeC1(operatorKey"), false);
  assert.equal(seed.includes("invokeC1(operatorKey"), false);
  assert.match(seed, /invokeC1OperatorSession\(t3n/);
  assert.match(reserve, /connectC1Principal\("AGENT_T3N_API_KEY"/);
  assert.match(reserve, /invokeC1\(agent\.apiKey/);
  assert.match(broker, /connectC1Principal\("EFFECT_BROKER_T3N_API_KEY"/);
  assert.match(broker, /invokeC1\(broker\.apiKey/);
});

test("registration re-points only the existing private map and labels function evidence", () => {
  assert.match(register, /expected_functions_from_local_component/);
  assert.match(register, /locally_verified_component_exports/);
  assert.match(register, /node_routing_verified_functions/);
  assert.equal(register.includes("tenant.maps.create"), false);
  assert.match(register, /tenant\.maps\.update\(INCIDENT_MAP_TAIL/);
});

test("C1 transport boundary has no operator stateless fallback", () => {
  assert.match(live, /const \{ tenantDid, nodeUrl, t3n \} = await connectTenant\(\)/);
  assert.equal(live.includes("const operatorKey"), false);
  assert.equal(live.includes("invokeC1(operatorKey"), false);
  assert.match(live, /wrongRoleProbe\(brokerKey/);
  assert.match(live, /wrongRoleProbe\(remediationKey/);
});
