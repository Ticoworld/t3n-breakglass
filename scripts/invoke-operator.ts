import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { CONTRACT_FUNCTION, CONTRACT_VERSION, connectPrincipal, redactError, required } from "./lib.js";

const root = path.resolve(import.meta.dirname, "..");

async function contractFromEvidence() {
  const setup = JSON.parse(await readFile(path.join(root, "evidence", "phase1-setup.json"), "utf8")) as {
    contract?: { name?: string; version?: string; function?: string };
  };
  if (setup.contract?.name && setup.contract.version === CONTRACT_VERSION && setup.contract.function === CONTRACT_FUNCTION) {
    return setup.contract.name;
  }
  throw new Error("phase1 setup evidence does not identify the expected contract");
}

async function main() {
  if (process.env.GITHUB_PAT) throw new Error("wrong-agent test refuses GITHUB_PAT in its process");
  const incidentId = required("INCIDENT_ID");
  const contractId = await contractFromEvidence();
  const { t3n, did, nodeUrl } = await connectPrincipal("T3N_API_KEY");
  const result = await t3n.execute({
    contract_id: contractId,
    contract_version: CONTRACT_VERSION,
    function_name: CONTRACT_FUNCTION,
    input: { incident_id: incidentId },
  });
  const evidence = {
    phase: "1",
    execution: "live",
    attempt: "wrong-agent",
    t3n_node: nodeUrl,
    calling_did: did,
    request: { incident_id: incidentId },
    target_fields_in_request: false,
    result,
    github_destructive_call_count: 0,
    github_credential_in_process: false,
  };
  await mkdir(path.join(root, "evidence"), { recursive: true });
  await writeFile(path.join(root, "evidence", "phase1-wrong-agent.json"), JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((error) => {
  console.error(`wrong-agent invoke failed: ${redactError(error, [process.env.T3N_API_KEY ?? "", process.env.GITHUB_PAT ?? ""])}`);
  process.exitCode = 1;
});
