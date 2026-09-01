import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { SessionOrgDataClient } from "@terminal3/t3n-sdk";
import { CONTRACT_FUNCTION, CONTRACT_VERSION, connectTenant, redactError } from "./lib.js";

const root = path.resolve(import.meta.dirname, "..");
const expectedOrgDid = "did:t3n:3c63f09271c0d9184abbcccbfae28698a8f4a912";
const expectedOperatorDid = "did:t3n:adb9365ee986cc6d0cb4006580782fe6fc7a431f";
const oldAgentDid = "did:t3n:06cb1776cc1bc4596b4195112813453e95709500";

async function main() {
  const setup = JSON.parse(await readFile(path.join(root, "evidence", "phase1-setup.json"), "utf8")) as {
    contract?: { name?: string; version?: string; function?: string };
  };
  const provisioning = JSON.parse(await readFile(path.join(root, "evidence", "phase1-replacement-agent-provisioning.json"), "utf8")) as {
    organisation_did?: string;
    replacement_agent_did?: string;
  };
  const orgDid = provisioning.organisation_did;
  const agentDid = provisioning.replacement_agent_did;
  const contractId = setup.contract?.name;
  if (orgDid !== expectedOrgDid || !agentDid || agentDid === oldAgentDid) throw new Error("replacement provisioning evidence is invalid");
  if (setup.contract?.version !== CONTRACT_VERSION || setup.contract.function !== CONTRACT_FUNCTION || !contractId) {
    throw new Error("recorded contract does not match the existing Phase 1 contract");
  }

  const { t3n, nodeUrl, tenantDid } = await connectTenant();
  if (tenantDid !== expectedOperatorDid) throw new Error("authenticated operator DID differs from recorded operator DID");
  const orgData = new SessionOrgDataClient(t3n, nodeUrl);
  const admin = await orgData.amIAdmin({ orgDid });
  const roster = await orgData.listAgents({ orgDid, limit: 100 });
  const listed = roster.agents.some((entry) => entry.did === agentDid);
  if (!listed) throw new Error("replacement agent is not present in the organization roster");

  const card = await orgData.agentCardGet({ ownerDid: orgDid, agentDid });
  if (card.agent_did !== agentDid || typeof card.card !== "string" || card.card.length === 0) {
    throw new Error("replacement private agent card was not readable by the organization admin");
  }

  const egressBefore = await orgData.getAgentEgress({ orgDid, agentDid, contractId });
  const mutation = await orgData.setAgentEgress({
    orgDid,
    agentDid,
    contractId,
    allowedHosts: ["api.github.com"],
    functions: [CONTRACT_FUNCTION],
    versionReq: CONTRACT_VERSION,
  });
  const egressAfter = await orgData.getAgentEgress({ orgDid, agentDid, contractId });
  const configured = egressAfter.egress?.contract_id === contractId
    && egressAfter.egress.allowed_hosts.length === 1
    && egressAfter.egress.allowed_hosts[0] === "api.github.com"
    && egressAfter.egress.functions.length === 1
    && egressAfter.egress.functions[0] === CONTRACT_FUNCTION
    && egressAfter.egress.version_req === CONTRACT_VERSION;
  if (!configured) throw new Error("replacement agent egress did not match the exact required policy");

  const evidence = {
    phase: "1-repair",
    stage: "replacement_agent_ownership_preflight",
    status: "ORG_OWNERSHIP_CONFIRMED",
    environment: "testnet",
    sdk: "@terminal3/t3n-sdk 5.2.0",
    t3n_node: nodeUrl,
    operator_did: tenantDid,
    organisation_did: orgDid,
    replacement_agent_did: agentDid,
    organization_admin_check: admin,
    organization_roster: roster,
    roster_contains_replacement: listed,
    private_agent_card: {
      read_succeeded: true,
      agent_did: card.agent_did,
      card_bytes: card.card.length,
      body_recorded: false,
      public_publish_called: false,
    },
    egress: {
      before: egressBefore,
      mutation_succeeded: true,
      mutation_response_type: typeof mutation,
      after: egressAfter,
      exact_required_policy: configured,
      allowed_hosts: ["api.github.com"],
      functions: [CONTRACT_FUNCTION],
      version_req: CONTRACT_VERSION,
    },
    github_mutation_calls: 0,
    breakglass_invocations: 0,
  };
  await mkdir(path.join(root, "evidence"), { recursive: true });
  await writeFile(path.join(root, "evidence", "phase1-replacement-agent-ownership.json"), JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((error) => {
  console.error(`replacement ownership preflight failed: ${redactError(error, [process.env.GITHUB_PAT ?? "", process.env.T3N_API_KEY ?? ""])}`);
  process.exitCode = 1;
});
