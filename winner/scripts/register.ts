import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { connectTenant, redactError } from "../../scripts/lib.js";
import { CONTRACT_TAIL, CONTRACT_VERSION, INCIDENT_MAP_TAIL, contractName } from "./constants.js";

const root = path.resolve(import.meta.dirname, "../..");
const wasmPath = path.join(root, "winner", "contract", "target", "wasm32-wasip2", "release", "breakglass_winner_contract.wasm");
const evidencePath = path.join(root, "winner", "evidence", "contract-registration.json");

async function ensureMap(tenant: Awaited<ReturnType<typeof connectTenant>>["tenant"], contractId: number) {
  const acl = { only: [contractId] };
  try {
    await tenant.maps.create({ tail: INCIDENT_MAP_TAIL, visibility: "private", writers: acl, readers: acl });
  } catch (error) {
    if (!/already exists/i.test(error instanceof Error ? error.message : String(error))) throw error;
  }
  await tenant.maps.update(INCIDENT_MAP_TAIL, { visibility: "private", writers: acl, readers: acl });
}

async function main() {
  if (process.env.GITHUB_PAT) throw new Error("C1 registration refuses a GitHub PAT");
  const wasm = new Uint8Array(await readFile(wasmPath));
  if (wasm.length === 0) throw new Error("winner contract WASM is empty");
  const { tenant, tenantDid, nodeUrl } = await connectTenant();
  const registered = await tenant.contracts.register({ tail: CONTRACT_TAIL, version: CONTRACT_VERSION, wasm });
  await ensureMap(tenant, registered.contract_id);
  const evidence = {
    experiment: "C1 state-only contract registration",
    status: "REGISTERED",
    environment: "testnet",
    sdk: "@terminal3/t3n-sdk 5.2.0",
    t3n_node: nodeUrl,
    operator_did: tenantDid,
    contract: { name: registered.name, tail: CONTRACT_TAIL, version: CONTRACT_VERSION, contract_id: registered.contract_id, functions: ["create-incident", "get-incident", "reserve-incident", "claim-effect", "release-not-attempted", "finalize-effect", "reconcile-effect"] },
    map: { name: tenant.canonicalName(INCIDENT_MAP_TAIL), tail: INCIDENT_MAP_TAIL, private: true, acl_contract_id: registered.contract_id },
    provider_mutations: 0,
  };
  await mkdir(path.dirname(evidencePath), { recursive: true });
  await writeFile(evidencePath, JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((error) => { console.error(`C1 registration failed: ${redactError(error, [process.env.T3N_API_KEY ?? "", process.env.GITHUB_PAT ?? ""])}`); process.exitCode = 1; });
