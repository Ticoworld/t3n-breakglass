import { discoverWhoami, getNodeUrl, invoke, setEnvironment } from "@terminal3/t3n-sdk";
import { CONTRACT_FUNCTION, CONTRACT_VERSION, redactError, required } from "./lib.js";
import { parseAgentInput, readPhase1Setup, sanitizeExecutionResult } from "./product.js";

export async function executeReplacementIncident(input: unknown) {
  if (process.env.GITHUB_PAT || process.env.T3N_API_KEY) {
    throw new Error("agent execution refuses operator or GitHub credentials");
  }
  const request = parseAgentInput(input);
  const configuredDid = required("REPLACEMENT_AGENT_DID");
  const apiKey = required("REPLACEMENT_AGENT_T3N_API_KEY");
  const { contractId } = await readPhase1Setup();
  setEnvironment("testnet");
  const nodeUrl = getNodeUrl();
  const whoami = await discoverWhoami({ baseUrl: nodeUrl, apiKey });
  if (whoami.did !== configuredDid) throw new Error("replacement agent key resolved to an unexpected DID");
  const raw = await invoke({
    baseUrl: nodeUrl,
    apiKey,
    request: {
      contract_id: contractId,
      contract_version: CONTRACT_VERSION,
      function_name: CONTRACT_FUNCTION,
      input: request,
    },
  });
  return sanitizeExecutionResult(request.incident_id, raw);
}

export function redactAgentError(error: unknown): string {
  return redactError(error, [process.env.REPLACEMENT_AGENT_T3N_API_KEY ?? ""]);
}
