import { parseIncidentIdArgument } from "./product.js";
import { executeReplacementIncident, redactAgentError } from "./agent-execution.js";

async function main() {
  const incidentId = parseIncidentIdArgument(process.argv.slice(2));
  const result = await executeReplacementIncident({ incident_id: incidentId });
  console.log(JSON.stringify(result, null, 2));
}

main().catch((error) => {
  console.error(`agent execution failed: ${redactAgentError(error)}`);
  process.exitCode = 1;
});
