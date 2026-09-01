import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { connectTenant, redactError } from "./lib.js";

const root = path.resolve(import.meta.dirname, "..");
const agentEnvPath = path.join(root, ".env.agent");
const intermediatePath = path.join(root, "evidence", "phase1-agent-provisioning-intermediate.json");

async function existingFile(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

function envValue(contents: string, name: string): string | undefined {
  const line = contents.split(/\r?\n/).find((candidate) => candidate.startsWith(`${name}=`));
  return line?.slice(name.length + 1).trim();
}

async function main() {
  if (await existingFile(agentEnvPath)) {
    const existing = await readFile(agentEnvPath, "utf8");
    if (envValue(existing, "AGENT_T3N_API_KEY") && envValue(existing, "AGENT_DID")) {
      console.log(JSON.stringify({ status: "already_provisioned", agent_did: envValue(existing, "AGENT_DID"), credential: "not printed" }, null, 2));
      return;
    }
    throw new Error(".env.agent exists but is incomplete; refusing to overwrite it");
  }

  const { t3n, tenantDid, nodeUrl } = await connectTenant();
  let organisationDid: string | undefined;
  if (await existingFile(intermediatePath)) {
    const intermediate = JSON.parse(await readFile(intermediatePath, "utf8")) as { organisation_did?: string };
    organisationDid = intermediate.organisation_did;
  }
  if (!organisationDid) {
    const created = await t3n.createOrganisation("BreakGlass Phase 1");
    organisationDid = created.value;
    await mkdir(path.join(root, "evidence"), { recursive: true });
    await writeFile(intermediatePath, JSON.stringify({
      phase: "1",
      status: "organisation_created_agent_pending",
      environment: "testnet",
      t3n_node: nodeUrl,
      operator_did: tenantDid,
      organisation_did: organisationDid,
      secret: "not present",
    }, null, 2) + "\n");
  }

  const createdAgent = await t3n.createAgent(organisationDid, "BreakGlass Phase 1 Executor", { defaultCard: false });
  const agentDid = createdAgent.agentDid.value;
  if (!createdAgent.apiKey || !/^t3n_key_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(createdAgent.apiKey)) {
    throw new Error("T3N did not return an opaque agent API key in the documented format");
  }
  await writeFile(agentEnvPath, [
    `AGENT_T3N_API_KEY=${createdAgent.apiKey}`,
    `AGENT_DID=${agentDid}`,
    `AGENT_ORGANISATION_DID=${organisationDid}`,
    "",
  ].join("\n"), { flag: "wx" });

  const evidence = {
    phase: "1",
    status: "agent_provisioned",
    environment: "testnet",
    t3n_node: nodeUrl,
    operator_did: tenantDid,
    organisation_did: organisationDid,
    agent_did: agentDid,
    credential: { format: "opaque_t3n_key", stored_in: ".env.agent (ignored)", printed: false, logged: false },
    separate_principal: agentDid !== tenantDid,
    card: { hosted: false, public: false },
  };
  await mkdir(path.join(root, "evidence"), { recursive: true });
  await writeFile(path.join(root, "evidence", "phase1-agent-provisioning.json"), JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((error) => {
  console.error(`agent provisioning failed: ${redactError(error, [process.env.GITHUB_PAT ?? "", process.env.T3N_API_KEY ?? "", process.env.AGENT_T3N_API_KEY ?? ""])}`);
  process.exitCode = 1;
});
