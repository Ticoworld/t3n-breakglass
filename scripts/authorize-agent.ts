import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  CONTRACT_FUNCTION,
  CONTRACT_TAIL,
  CONTRACT_VERSION,
  GITHUB_HOST,
  authorizeAgent,
  connectTenant,
  redactError,
  required,
  scriptName,
} from "./lib.js";

const root = path.resolve(import.meta.dirname, "..");

function validateAgentDid(value: string): string {
  if (!/^did:t3n:[0-9a-f]{40}$/i.test(value)) throw new Error("AGENT_DID must be a canonical did:t3n:<40-hex> value");
  return value.toLowerCase();
}

async function main() {
  const agentDid = validateAgentDid(required("AGENT_DID"));
  const { t3n, tenantDid, nodeUrl } = await connectTenant();
  await authorizeAgent(t3n, tenantDid, agentDid, CONTRACT_VERSION);

  const evidence = {
    phase: "1",
    status: "agent_authorized",
    environment: "testnet",
    t3n_node: nodeUrl,
    operator_did: tenantDid,
    agent_did: agentDid,
    contract: scriptName(tenantDid),
    contract_tail: CONTRACT_TAIL,
    contract_version: CONTRACT_VERSION,
    function: CONTRACT_FUNCTION,
    grant: {
      functions: [CONTRACT_FUNCTION],
      scopes: [],
      version_req: CONTRACT_VERSION,
      allowed_hosts: [GITHUB_HOST],
      validity_window: "not widened here; incident expires_at is the authority TTL",
    },
    agent_secret: { present_in_operator_output: false, present_in_agent_request: false, github_pat_available: false },
  };
  await mkdir(path.join(root, "evidence"), { recursive: true });
  await writeFile(path.join(root, "evidence", "phase1-agent-authorization.json"), JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((error) => {
  console.error(`agent authorization failed: ${redactError(error, [process.env.GITHUB_PAT ?? "", process.env.T3N_API_KEY ?? "", process.env.AGENT_T3N_API_KEY ?? ""])}`);
  process.exitCode = 1;
});
