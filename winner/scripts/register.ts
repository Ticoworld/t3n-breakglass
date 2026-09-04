import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { connectTenant, redactError } from "../../scripts/lib.js";
import { CONTRACT_TAIL, CONTRACT_VERSION, INCIDENT_MAP_TAIL, contractName } from "./constants.js";

const root = path.resolve(import.meta.dirname, "../..");
const wasmPath = path.join(root, "winner", "contract", "target", "wasm32-wasip2", "release", "breakglass_winner_contract.wasm");
const evidencePath = path.join(root, "winner", "evidence", "contract-registration.json");
const EXPECTED_C1_FUNCTIONS = ["create-incident", "get-incident", "reserve-incident", "claim-effect", "confirm-claim", "release-not-attempted", "begin-effect", "confirm-effect-start", "finalize-effect", "reconcile-effect"] as const;

async function ensureMap(tenant: Awaited<ReturnType<typeof connectTenant>>["tenant"], contractId: number) {
  const acl = { only: [contractId] };
  // R4 only re-points the existing private map ACL.  It never seeds an entry
  // and never attempts to create a replacement map.
  await tenant.maps.update(INCIDENT_MAP_TAIL, { visibility: "private", writers: acl, readers: acl });
}

async function main() {
  if (process.env.GITHUB_PAT) throw new Error("C1 registration refuses a GitHub PAT");
  const wasm = new Uint8Array(await readFile(wasmPath));
  if (wasm.length === 0) throw new Error("winner contract WASM is empty");
  const wasmText = execFileSync("wasm-tools", ["component", "wit", wasmPath], { encoding: "utf8" });
  const locallyVerifiedComponentExports = EXPECTED_C1_FUNCTIONS.filter((name) => new RegExp(`^\\s+${name}: func`, "m").test(wasmText));
  const missing = EXPECTED_C1_FUNCTIONS.filter((name) => !locallyVerifiedComponentExports.includes(name));
  if (missing.length > 0) throw new Error(`local component surface is missing: ${missing.join(",")}`);
  const wasmSha256 = createHash("sha256").update(wasm).digest("hex");
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
    contract: { name: registered.name, tail: CONTRACT_TAIL, version: CONTRACT_VERSION, contract_id: registered.contract_id, wasm_bytes: wasm.length, wasm_sha256: wasmSha256, expected_functions_from_local_component: [...EXPECTED_C1_FUNCTIONS], locally_verified_component_exports: [...locallyVerifiedComponentExports], node_routing_verified_functions: [] },
    map: { name: tenant.canonicalName(INCIDENT_MAP_TAIL), tail: INCIDENT_MAP_TAIL, private: true, acl_contract_id: registered.contract_id },
    provider_mutations: 0,
  };
  await mkdir(path.dirname(evidencePath), { recursive: true });
  await writeFile(evidencePath, JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((error) => { console.error(`C1 registration failed: ${redactError(error, [process.env.T3N_API_KEY ?? "", process.env.GITHUB_PAT ?? ""])}`); process.exitCode = 1; });
