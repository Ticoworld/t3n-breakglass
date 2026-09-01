import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  CONTRACT_FUNCTION,
  CONTRACT_TAIL,
  CONTRACT_VERSION,
  connectTenant,
  redactError,
} from "./lib.js";

const root = path.resolve(import.meta.dirname, "..");

async function main() {
  // Deliberately do not read GITHUB_PAT. The invoking process only has the
  // T3N API key needed to authenticate the execution request.
  if (process.env.GITHUB_PAT) {
    throw new Error("invoke refuses to run when GITHUB_PAT is present in its environment");
  }

  const { tenant, tenantDid } = await connectTenant();
  const result = await tenant.contracts.execute(CONTRACT_TAIL, {
    version: CONTRACT_VERSION,
    functionName: CONTRACT_FUNCTION,
    input: {},
  });
  const evidence = {
    phase: "0",
    execution: "live",
    tenant_did: tenantDid,
    contract: `z:${tenantDid.slice("did:t3n:".length)}:${CONTRACT_TAIL}`,
    version: CONTRACT_VERSION,
    function: CONTRACT_FUNCTION,
    result,
    github_credential_in_process: false,
  };
  const label = process.env.BREAKGLASS_ATTEMPT === "replay" ? "replay-refusal" : "first-execution";
  const evidenceDir = path.join(root, "evidence");
  await mkdir(evidenceDir, { recursive: true });
  await writeFile(path.join(evidenceDir, `${label}.json`), JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((error) => {
  console.error(`invoke failed: ${redactError(error, [process.env.T3N_API_KEY ?? ""])}`);
  process.exitCode = 1;
});
