import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const live = await readFile(new URL("../scripts/c1-live.ts", import.meta.url), "utf8");

test("R6 checks wrong-role calls against the real ACTIVE authority before reservation", () => {
  const initialReadback = live.indexOf('const initialReadbackResponse = await invokeC1OperatorSession');
  const brokerWrongRole = live.indexOf('wrongRoleChecks.broker_attempts_reserve = await wrongRoleProbe');
  const remediationWrongRole = live.indexOf('wrongRoleChecks.remediation_attempts_claim = await wrongRoleProbe');
  const reserveChild = live.indexOf('"reserve-agent.ts"');
  assert.ok(initialReadback >= 0 && brokerWrongRole > initialReadback && remediationWrongRole > brokerWrongRole && reserveChild > remediationWrongRole);
  assert.match(live, /caller is not the remediation agent/);
  assert.match(live, /caller is not the effect broker/);
  assert.match(live, /after_broker_readback/);
  assert.match(live, /after_remediation_readback/);
});

test("R6 keeps operator session and opaque role credentials separated", () => {
  assert.match(live, /invokeC1OperatorSession\(t3n, contractId, "create-incident"/);
  assert.match(live, /wrongRoleProbe\(brokerKey, nodeUrl, contractId, RESERVATION_FUNCTION/);
  assert.match(live, /wrongRoleProbe\(remediationKey, nodeUrl, contractId, "claim-effect"/);
  assert.match(live, /EFFECT_BROKER_T3N_API_KEY/);
  assert.match(live, /AGENT_T3N_API_KEY/);
});
