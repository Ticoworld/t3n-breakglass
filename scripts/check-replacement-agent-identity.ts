import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { discoverWhoami, getNodeUrl, setEnvironment } from "@terminal3/t3n-sdk";
import { redactError, required } from "./lib.js";

const root = path.resolve(import.meta.dirname, "..");
const expectedOrgDid = "did:t3n:3c63f09271c0d9184abbcccbfae28698a8f4a912";

async function main() {
  if (process.env.GITHUB_PAT || process.env.T3N_API_KEY) {
    throw new Error("replacement agent identity check refuses operator/GitHub credentials in its environment");
  }
  const expectedAgentDid = required("REPLACEMENT_AGENT_DID");
  const agentApiKey = required("REPLACEMENT_AGENT_T3N_API_KEY");
  const provisioning = JSON.parse(await readFile(path.join(root, "evidence", "phase1-replacement-agent-provisioning.json"), "utf8")) as {
    replacement_agent_did?: string;
    organisation_did?: string;
  };
  if (provisioning.replacement_agent_did !== expectedAgentDid || provisioning.organisation_did !== expectedOrgDid) {
    throw new Error("replacement agent environment does not match provisioning evidence");
  }

  setEnvironment("testnet");
  const nodeUrl = getNodeUrl();
  const whoami = await discoverWhoami({ baseUrl: nodeUrl, apiKey: agentApiKey });
  if (whoami.did !== expectedAgentDid) throw new Error("replacement opaque key resolved to an unexpected DID");
  if (whoami.owner !== expectedOrgDid) throw new Error("replacement agent owner is not the existing organization");
  if (!whoami.organisations.includes(expectedOrgDid)) throw new Error("replacement agent does not report membership in the existing organization");

  const evidence = {
    phase: "1-repair",
    stage: "replacement_agent_whoami",
    status: "IDENTITY_AND_OWNER_CONFIRMED",
    environment: "testnet",
    sdk: "@terminal3/t3n-sdk 5.2.0",
    t3n_node: nodeUrl,
    agent_did: whoami.did,
    expected_agent_did: expectedAgentDid,
    organisations: whoami.organisations,
    owner: whoami.owner,
    operator_credential_in_process: false,
    github_pat_in_process: false,
    agent_key_logged: false,
    breakglass_invocations: 0,
    github_mutation_calls: 0,
  };
  await mkdir(path.join(root, "evidence"), { recursive: true });
  await writeFile(path.join(root, "evidence", "phase1-replacement-agent-whoami.json"), JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((error) => {
  console.error(`replacement agent identity check failed: ${redactError(error, [process.env.REPLACEMENT_AGENT_T3N_API_KEY ?? ""])}`);
  process.exitCode = 1;
});
