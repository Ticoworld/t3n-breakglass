import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { SessionOrgDataClient } from "@terminal3/t3n-sdk";
import { connectTenant, redactError } from "./lib.js";

const root = path.resolve(import.meta.dirname, "..");

async function main() {
  const setup = JSON.parse(await readFile(path.join(root, "evidence", "phase1-setup.json"), "utf8")) as {
    operator_did?: string;
    contract?: { name?: string };
  };
  const agentEvidence = JSON.parse(await readFile(path.join(root, "evidence", "phase1-agent-provisioning.json"), "utf8")) as {
    organisation_did?: string;
    agent_did?: string;
  };
  const { t3n, nodeUrl, tenantDid } = await connectTenant();
  if (tenantDid !== setup.operator_did) throw new Error("authenticated operator DID differs from evidence");
  const orgData = new SessionOrgDataClient(t3n, nodeUrl);
  const orgDid = agentEvidence.organisation_did;
  const agentDid = agentEvidence.agent_did;
  const contractId = setup.contract?.name;
  if (!orgDid || !agentDid || !contractId) throw new Error("missing recorded organization, agent, or contract");

  const roster = await orgData.listAgents({ orgDid, limit: 100 });
  let card: unknown;
  let cardError: string | null = null;
  try {
    card = await orgData.agentCardGet({ ownerDid: orgDid, agentDid });
  } catch (error) {
    cardError = redactError(error, [process.env.GITHUB_PAT ?? "", process.env.T3N_API_KEY ?? ""]);
  }
  let egress: unknown;
  let egressError: string | null = null;
  try {
    egress = await orgData.getAgentEgress({ orgDid, agentDid, contractId });
  } catch (error) {
    egressError = redactError(error, [process.env.GITHUB_PAT ?? "", process.env.T3N_API_KEY ?? ""]);
  }

  const evidence = {
    phase: "1",
    stage: "read_only_agent_ownership_diagnostics",
    environment: "testnet",
    sdk: "@terminal3/t3n-sdk 5.2.0",
    node_url: nodeUrl,
    operator_did: tenantDid,
    organisation_did: orgDid,
    agent_did: agentDid,
    contract: contractId,
    org_roster: roster,
    agent_listed_in_org_roster: roster.agents.some((entry) => entry.did === agentDid),
    private_card: card ?? null,
    private_card_error: cardError,
    egress: egress ?? null,
    egress_error: egressError,
    mutation_calls: 0,
    github_destructive_calls: 0,
  };
  await mkdir(path.join(root, "evidence"), { recursive: true });
  await writeFile(path.join(root, "evidence", "phase1-agent-membership.json"), JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((error) => {
  console.error(`agent membership diagnostics failed: ${redactError(error, [process.env.GITHUB_PAT ?? "", process.env.T3N_API_KEY ?? ""])}`);
  process.exitCode = 1;
});
