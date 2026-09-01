import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { SessionOrgDataClient } from "@terminal3/t3n-sdk";
import { CONTRACT_FUNCTION, CONTRACT_VERSION, connectTenant, redactError } from "./lib.js";

const root = path.resolve(import.meta.dirname, "..");

async function main() {
  const setup = JSON.parse(await readFile(path.join(root, "evidence", "phase1-setup.json"), "utf8")) as {
    operator_did?: string;
    contract?: { name?: string; version?: string; function?: string };
  };
  const agentEvidence = JSON.parse(await readFile(path.join(root, "evidence", "phase1-agent-provisioning.json"), "utf8")) as {
    organisation_did?: string;
    agent_did?: string;
  };
  if (!/^did:t3n:[0-9a-f]{40}$/.test(setup.operator_did ?? "")) throw new Error("invalid recorded operator DID");
  if (!/^did:t3n:[0-9a-f]{40}$/.test(agentEvidence.organisation_did ?? "")) throw new Error("invalid recorded organisation DID");
  if (!/^did:t3n:[0-9a-f]{40}$/.test(agentEvidence.agent_did ?? "")) throw new Error("invalid recorded agent DID");
  if (setup.contract?.version !== CONTRACT_VERSION || setup.contract.function !== CONTRACT_FUNCTION || !setup.contract.name) {
    throw new Error("recorded contract does not match the expected Phase 1 function");
  }

  const { t3n, nodeUrl, tenantDid } = await connectTenant();
  if (tenantDid !== setup.operator_did) throw new Error("authenticated operator DID differs from the recorded DID");
  const orgData = new SessionOrgDataClient(t3n, nodeUrl);
  const ref = {
    orgDid: agentEvidence.organisation_did,
    agentDid: agentEvidence.agent_did,
    contractId: setup.contract.name,
  };
  const before = await orgData.getAgentEgress(ref);
  const mutation = await orgData.setAgentEgress({
    ...ref,
    allowedHosts: ["api.github.com"],
    functions: [CONTRACT_FUNCTION],
    versionReq: CONTRACT_VERSION,
  });
  const after = await orgData.getAgentEgress(ref);

  const evidence = {
    phase: "1",
    stage: "org_agent_egress_configuration",
    environment: "testnet",
    sdk: "@terminal3/t3n-sdk 5.2.0",
    node_url: nodeUrl,
    operator_did: tenantDid,
    organisation_did: agentEvidence.organisation_did,
    agent_did: agentEvidence.agent_did,
    contract: setup.contract.name,
    before,
    mutation: { succeeded: true, response_type: typeof mutation },
    after,
    configured_policy: {
      allowed_hosts: ["api.github.com"],
      functions: [CONTRACT_FUNCTION],
      version_req: CONTRACT_VERSION,
    },
    github_destructive_calls: 0,
    github_pat_logged: false,
  };
  await mkdir(path.join(root, "evidence"), { recursive: true });
  await writeFile(path.join(root, "evidence", "phase1-agent-egress.json"), JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((error) => {
  console.error(`agent egress configuration failed: ${redactError(error, [process.env.GITHUB_PAT ?? "", process.env.T3N_API_KEY ?? ""])}`);
  process.exitCode = 1;
});
