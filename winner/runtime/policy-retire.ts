import { connectTenant } from "../../scripts/lib.js";

import { asC1Object } from "./c1-client.js";
import { loadDataDirectory, loadStateIntegrityKey } from "./config.js";
import { PolicyRegistry } from "./policy-registry.js";
import { invokeC1OperatorSession } from "../scripts/t3n.js";
import { contractName } from "../scripts/constants.js";

async function main(): Promise<void> {
  const policyId = process.argv[2];
  const policyVersion = Number(process.argv[3]);
  const incidentId = process.argv[4];
  if (!policyId || !Number.isSafeInteger(policyVersion) || policyVersion <= 0 || !incidentId) throw new Error("usage: breakglass:policy:retire <policy_id> <policy_version> <incident_id>");
  const operator = await connectTenant();
  const remote = asC1Object(await invokeC1OperatorSession(operator.t3n, contractName(operator.tenantDid), "get-incident", { incident_id: incidentId }));
  const detail = remote.detail && typeof remote.detail === "object" && !Array.isArray(remote.detail) ? remote.detail as Record<string, unknown> : {};
  const classification = typeof remote.final_result_classification === "string" ? remote.final_result_classification : detail.final_result_classification;
  if (remote.state !== "CLOSED" || classification !== "VERIFIED_ABSENT") throw new Error("policy retirement requires a CLOSED / VERIFIED_ABSENT incident readback");
  const registry = new PolicyRegistry(loadDataDirectory(), { stateIntegrityKey: loadStateIntegrityKey() });
  await registry.initialize();
  const retired = await registry.retire(policyId, policyVersion, incidentId);
  process.stdout.write(`${JSON.stringify({ policy_id: retired.policy_id, policy_version: retired.policy_version, retired: true, incident_id: retired.incident_id }, null, 2)}\n`);
}

main().catch((error) => { process.stderr.write(`breakglass policy retire failed: ${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; });
