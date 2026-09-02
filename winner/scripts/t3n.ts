import { discoverWhoami, getNodeUrl, invoke, setEnvironment } from "@terminal3/t3n-sdk";
import { CONTRACT_VERSION, contractName } from "./constants.js";

export function requireValue(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

export function refuseProviderOrOperatorCredentials(environment: NodeJS.ProcessEnv = process.env): void {
  if (environment.GITHUB_PAT) throw new Error("C1 refuses to run with GITHUB_PAT present");
  if (environment.T3N_API_KEY) throw new Error("C1 principal process refuses the operator T3N credential");
}

export function redact(error: unknown, secrets: string[] = []): string {
  let message = error instanceof Error ? error.message : String(error);
  for (const secret of secrets) if (secret) message = message.split(secret).join("[REDACTED]");
  return message
    .replace(/(Authorization\s*:\s*Bearer\s+)[A-Za-z0-9._~+\/-]+/gi, "$1[REDACTED_AUTH]")
    .replace(/(Bearer\s+)[A-Za-z0-9._~+\/-]+/gi, "$1[REDACTED_AUTH]")
    .replace(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, "[REDACTED_JWT]")
    .replace(/(gh[pousr]_|github_pat_|t3n_key_)[A-Za-z0-9._~+\/-]+/gi, "$1[REDACTED_TOKEN]");
}

export async function connectC1Principal(apiKeyEnv: string, expectedDidEnv: string) {
  refuseProviderOrOperatorCredentials();
  const apiKey = requireValue(apiKeyEnv);
  const expectedDid = requireValue(expectedDidEnv);
  setEnvironment("testnet");
  const nodeUrl = getNodeUrl();
  const whoami = await discoverWhoami({ baseUrl: nodeUrl, apiKey });
  if (whoami.did !== expectedDid) throw new Error(`${apiKeyEnv} resolved to an unexpected DID`);
  return { apiKey, did: whoami.did, nodeUrl, whoami };
}

export async function invokeC1(apiKey: string, nodeUrl: string, contractId: string, functionName: string, input: unknown) {
  return invoke({
    baseUrl: nodeUrl,
    apiKey,
    request: { contract_id: contractId, contract_version: CONTRACT_VERSION, function_name: functionName, input },
  });
}

export function canonicalContractId(operatorDid: string): string {
  return contractName(operatorDid);
}
