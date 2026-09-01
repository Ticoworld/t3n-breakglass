import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { getNodeUrl, invoke, setEnvironment } from "@terminal3/t3n-sdk";
import {
  CONTRACT_FUNCTION,
  CONTRACT_VERSION,
  redactError,
  required,
} from "./lib.js";

const root = path.resolve(import.meta.dirname, "..");

async function contractFromEvidence() {
  const setup = JSON.parse(await readFile(path.join(root, "evidence", "phase1-setup.json"), "utf8")) as {
    contract?: { name?: string; version?: string; function?: string };
  };
  if (
    setup.contract?.name !== undefined &&
    setup.contract.version === CONTRACT_VERSION &&
    setup.contract.function === CONTRACT_FUNCTION
  ) return setup.contract.name;
  throw new Error("phase1 setup evidence does not identify the expected contract version/function");
}

async function main() {
  // The agent execution process must not have either bootstrap secret or the
  // operator key. Its only credential is AGENT_T3N_API_KEY.
  if (process.env.GITHUB_PAT || process.env.T3N_API_KEY) {
    throw new Error("agent invocation refuses operator/GitHub credentials in its environment");
  }
  const incidentId = required("INCIDENT_ID");
  const contractId = await contractFromEvidence();
  const agentApiKey = required("AGENT_T3N_API_KEY");
  const agentDid = required("AGENT_DID");
  setEnvironment("testnet");
  const nodeUrl = getNodeUrl();
  const result = await invoke({
    baseUrl: nodeUrl,
    apiKey: agentApiKey,
    request: {
      contract_id: contractId,
      contract_version: CONTRACT_VERSION,
      function_name: CONTRACT_FUNCTION,
      input: { incident_id: incidentId },
    },
  });

  const attempt = (process.env.BREAKGLASS_ATTEMPT ?? "valid").replace(/[^a-z0-9-]/gi, "-").toLowerCase();
  const evidence = {
    phase: "1",
    execution: "live",
    attempt,
    t3n_node: nodeUrl,
    agent_did: agentDid,
    contract: contractId,
    version: CONTRACT_VERSION,
    function: CONTRACT_FUNCTION,
    request: { incident_id: incidentId },
    target_fields_in_request: false,
    result,
    github_credential_in_process: false,
    operator_credential_in_process: false,
  };
  await mkdir(path.join(root, "evidence"), { recursive: true });
  await writeFile(path.join(root, "evidence", `phase1-invocation-${attempt}.json`), JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((error) => {
  console.error(`agent invoke failed: ${redactError(error, [process.env.AGENT_T3N_API_KEY ?? "", process.env.GITHUB_PAT ?? "", process.env.T3N_API_KEY ?? ""])}`);
  process.exitCode = 1;
});
