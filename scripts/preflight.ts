import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { connectTenant, redactError } from "./lib.js";

const root = path.resolve(import.meta.dirname, "..");
const evidenceDir = path.join(root, "evidence");

async function main() {
  if (process.env.GITHUB_PAT) throw new Error("safe preflight refuses a GitHub PAT in its environment");
  const { tenant, tenantDid, nodeUrl } = await connectTenant();
  const tenantRead = await tenant.tenant.me();
  const evidence = {
    phase: "0",
    stage: "safe_t3n_preflight",
    environment: "testnet",
    sdk: "@terminal3/t3n-sdk 5.2.0",
    node_url: nodeUrl,
    tenant_did: tenantDid,
    trust_manifest_verified: true,
    handshake_succeeded: true,
    authentication_succeeded: true,
    harmless_tenant_read_succeeded: true,
    harmless_tenant_read_type: typeof tenantRead,
    github_pat_in_process: false,
    destructive_calls: 0,
  };
  await mkdir(evidenceDir, { recursive: true });
  await writeFile(path.join(evidenceDir, "t3n-preflight-5.2.0.json"), JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((error) => {
  console.error(`T3N preflight failed: ${redactError(error, [process.env.T3N_API_KEY ?? ""])}`);
  process.exitCode = 1;
});
