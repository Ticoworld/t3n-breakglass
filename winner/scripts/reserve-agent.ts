import { invokeC1, connectC1Principal, redact, requireValue } from "./t3n.js";
import { contractName } from "./constants.js";

async function main() {
  if (process.env.GITHUB_PAT || process.env.T3N_API_KEY) throw new Error("C1 remediation process refuses operator/GitHub credentials");
  const agent = await connectC1Principal("AGENT_T3N_API_KEY", "AGENT_DID");
  const operatorDid = requireValue("C1_OPERATOR_DID");
  const incidentId = requireValue("C1_INCIDENT_ID");
  const result = await invokeC1(agent.apiKey, agent.nodeUrl, contractName(operatorDid), "reserve-incident", { incident_id: incidentId });
  console.log(JSON.stringify({ agent_did: agent.did, input: { incident_id: incidentId }, result, provider_mutations: 0, target_fields_supplied: false }, null, 2));
}
main().catch((error) => { console.error(`C1 remediation reserve failed: ${redact(error, [process.env.AGENT_T3N_API_KEY ?? ""])}`); process.exitCode = 1; });
