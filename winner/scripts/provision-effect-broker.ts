import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { SessionOrgDataClient } from "@terminal3/t3n-sdk";
import { connectTenant, redactError } from "../../scripts/lib.js";
import { ORGANISATION_DID } from "./constants.js";

const root = path.resolve(import.meta.dirname, "../..");
const envPath = path.join(root, ".env.effect-broker");
const evidencePath = path.join(root, "winner", "evidence", "broker-provisioning.json");
const agentName = "BreakGlass Effect Broker";

async function exists(filePath: string): Promise<boolean> {
  try { await access(filePath); return true; } catch { return false; }
}

async function main() {
  if (process.env.GITHUB_PAT) throw new Error("broker provisioning refuses a GitHub PAT");
  if (await exists(envPath)) {
    const contents = await readFile(envPath, "utf8");
    const did = contents.match(/^EFFECT_BROKER_DID=([^\r\n]+)$/m)?.[1];
    if (did) { console.log(JSON.stringify({ status: "already_provisioned", effect_broker_did: did, credential: "not printed" }, null, 2)); return; }
    throw new Error(".env.effect-broker exists but is incomplete; refusing to overwrite it");
  }

  const { t3n, tenantDid, nodeUrl } = await connectTenant();
  const orgData = new SessionOrgDataClient(t3n, nodeUrl);
  if (!(await orgData.amIAdmin({ orgDid: ORGANISATION_DID }))) throw new Error("operator is not an administrator of the BreakGlass organization");
  const roster = await orgData.listAgents({ orgDid: ORGANISATION_DID, limit: 100 });
  const existing = roster.agents.filter((agent) => agent.name === agentName);
  if (existing.length > 0) throw new Error(`effect broker agent already exists without a local credential: ${existing.map((agent) => agent.did).join(",")}`);

  const created = await t3n.createAgent(ORGANISATION_DID, agentName);
  const did = created.agentDid.value;
  if (!/^did:t3n:[0-9a-f]{40}$/.test(did)) throw new Error("T3N returned an invalid effect broker DID");
  if (!/^t3n_key_[0-9a-f]{16}\.[0-9a-f]+$/.test(created.apiKey)) throw new Error("T3N did not return the documented opaque API key format");
  await writeFile(envPath, [
    `EFFECT_BROKER_T3N_API_KEY=${created.apiKey}`,
    `EFFECT_BROKER_DID=${did}`,
    `EFFECT_BROKER_ORGANISATION_DID=${ORGANISATION_DID}`,
    `EFFECT_BROKER_KEY_ID=${created.keyId}`,
    "",
  ].join("\n"), { flag: "wx" });
  const evidence = {
    experiment: "C1 dedicated broker principal provisioning",
    status: "PROVISIONED",
    environment: "testnet",
    sdk: "@terminal3/t3n-sdk 5.2.0",
    t3n_node: nodeUrl,
    operator_did: tenantDid,
    organisation_did: ORGANISATION_DID,
    effect_broker_did: did,
    name: agentName,
    agent_key: { format: "opaque_t3n_key", key_id: created.keyId, stored_in: ".env.effect-broker (ignored)", secret_printed: false, secret_logged: false },
    default_card: true,
    provider_mutations: 0,
  };
  await mkdir(path.dirname(evidencePath), { recursive: true });
  await writeFile(evidencePath, JSON.stringify(evidence, null, 2) + "\n", { flag: "wx" });
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((error) => {
  console.error(`effect broker provisioning failed: ${redactError(error, [process.env.T3N_API_KEY ?? "", process.env.EFFECT_BROKER_T3N_API_KEY ?? "", process.env.GITHUB_PAT ?? ""])}`);
  process.exitCode = 1;
});
