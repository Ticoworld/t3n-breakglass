import { discoverWhoami, getNodeUrl, invoke, setEnvironment } from "@terminal3/t3n-sdk";
import { CONTRACT_FUNCTION, CONTRACT_VERSION, redactError, required } from "./lib.js";
import { parseIncidentIdArgument, readPhase1Setup } from "./product.js";

async function main() {
  if (process.env.GITHUB_PAT || process.env.T3N_API_KEY) {
    throw new Error("phase2e agent refuses operator or GitHub credentials");
  }
  const incidentId = parseIncidentIdArgument(process.argv.slice(2));
  const configuredDid = required("REPLACEMENT_AGENT_DID");
  const apiKey = required("REPLACEMENT_AGENT_T3N_API_KEY");
  const { contractId } = await readPhase1Setup();
  setEnvironment("testnet");
  const nodeUrl = getNodeUrl();
  const whoami = await discoverWhoami({ baseUrl: nodeUrl, apiKey });
  if (whoami.did !== configuredDid) throw new Error("replacement agent key resolved to an unexpected DID");
  const request = { incident_id: incidentId };
  const result = await invoke({
    baseUrl: nodeUrl,
    apiKey,
    request: {
      contract_id: contractId,
      contract_version: CONTRACT_VERSION,
      function_name: CONTRACT_FUNCTION,
      input: request,
    },
  });
  console.log(JSON.stringify({
    t3n_node: nodeUrl,
    agent_did: whoami.did,
    contract: contractId,
    version: CONTRACT_VERSION,
    function: CONTRACT_FUNCTION,
    request,
    target_fields_in_request: false,
    result,
    github_credential_in_process: false,
    operator_credential_in_process: false,
  }));
}

main().catch((error) => {
  console.error(`phase2e agent failed: ${redactError(error, [process.env.REPLACEMENT_AGENT_T3N_API_KEY ?? "", process.env.GITHUB_PAT ?? "", process.env.T3N_API_KEY ?? ""])}`);
  process.exitCode = 1;
});
