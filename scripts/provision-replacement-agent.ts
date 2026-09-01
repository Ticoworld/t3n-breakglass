import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { SessionOrgDataClient } from "@terminal3/t3n-sdk";
import { connectTenant, redactError } from "./lib.js";

const root = path.resolve(import.meta.dirname, "..");
const orgDid = "did:t3n:3c63f09271c0d9184abbcccbfae28698a8f4a912";
const operatorDid = "did:t3n:adb9365ee986cc6d0cb4006580782fe6fc7a431f";
const oldAgentDid = "did:t3n:06cb1776cc1bc4596b4195112813453e95709500";
const agentName = "BreakGlass Agent";
const replacementEnvPath = path.join(root, ".env.replacement-agent");
const evidencePath = path.join(root, "evidence", "phase1-replacement-agent-provisioning.json");

async function exists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function main() {
  if (await exists(replacementEnvPath)) {
    throw new Error(".env.replacement-agent already exists; refusing to create a second replacement agent");
  }
  if (await exists(evidencePath)) {
    throw new Error("replacement provisioning evidence already exists; refusing to create another agent");
  }

  const { t3n, nodeUrl, tenantDid } = await connectTenant();
  if (tenantDid !== operatorDid) throw new Error("authenticated operator DID differs from the recorded operator DID");

  const orgData = new SessionOrgDataClient(t3n, nodeUrl);
  const writersBefore = await orgData.writersGet({ orgDid, scope: "agent-cards" });
  let writersMutation: { changed: boolean; response_type?: string } = { changed: false };
  if (!writersBefore.writers.includes(operatorDid)) {
    const mutation = await orgData.setWriters({ orgDid, scope: "agent-cards", writers: [operatorDid] });
    writersMutation = { changed: true, response_type: typeof mutation };
  }
  const writersAfter = await orgData.writersGet({ orgDid, scope: "agent-cards" });
  if (!writersAfter.writers.includes(operatorDid)) throw new Error("operator was not granted agent-cards write access");

  // No options is deliberate: this is the official default-card path. Do not
  // add defaultCard:false, --no-card, an empty URI, or a custom card.
  const created = await t3n.createAgent(orgDid, agentName);
  const replacementAgentDid = created.agentDid.value;
  if (!/^did:t3n:[0-9a-f]{40}$/.test(replacementAgentDid)) throw new Error("T3N returned an invalid replacement agent DID");
  if (replacementAgentDid === oldAgentDid || replacementAgentDid === operatorDid) {
    throw new Error("T3N returned an unexpected existing principal as replacement agent");
  }
  if (!/^t3n_key_[0-9a-f]{16}\.[0-9a-f]+$/.test(created.apiKey)) {
    throw new Error("T3N did not return the documented opaque agent API key format");
  }
  if (!/^[0-9a-f]{16}$/.test(created.keyId)) throw new Error("T3N did not return the documented safe key ID format");

  await writeFile(replacementEnvPath, [
    `REPLACEMENT_AGENT_T3N_API_KEY=${created.apiKey}`,
    `REPLACEMENT_AGENT_DID=${replacementAgentDid}`,
    `REPLACEMENT_AGENT_ORGANISATION_DID=${orgDid}`,
    `REPLACEMENT_AGENT_KEY_ID=${created.keyId}`,
    "",
  ].join("\n"), { flag: "wx" });

  const evidence = {
    phase: "1-repair",
    stage: "replacement_agent_provisioning",
    status: "provisioned_default_card_path",
    environment: "testnet",
    sdk: "@terminal3/t3n-sdk 5.2.0",
    t3n_node: nodeUrl,
    operator_did: tenantDid,
    organisation_did: orgDid,
    replacement_agent_did: replacementAgentDid,
    old_agent_preserved: true,
    provisioning: {
      method: "T3nClient.createAgent",
      name: agentName,
      custom_card: false,
      default_card: true,
      agent_uri: false,
      no_card: false,
      returned_agent_uri: Boolean(created.agentUri),
      returned_card_entry_id: Boolean(created.cardEntryId),
    },
    agent_key: {
      format: "opaque_t3n_key",
      key_id: created.keyId,
      stored_in: ".env.replacement-agent (ignored)",
      secret_printed: false,
      secret_logged: false,
    },
    agent_cards_writer: {
      before: writersBefore,
      mutation: writersMutation,
      after: writersAfter,
    },
    github_mutation_calls: 0,
    breakglass_invocations: 0,
  };
  await mkdir(path.join(root, "evidence"), { recursive: true });
  await writeFile(evidencePath, JSON.stringify(evidence, null, 2) + "\n", { flag: "wx" });
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((error) => {
  console.error(`replacement agent provisioning failed: ${redactError(error, [process.env.GITHUB_PAT ?? "", process.env.T3N_API_KEY ?? "", process.env.REPLACEMENT_AGENT_T3N_API_KEY ?? ""])}`);
  process.exitCode = 1;
});
