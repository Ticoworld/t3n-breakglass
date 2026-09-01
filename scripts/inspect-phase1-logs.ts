import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { connectTenant, redactError } from "./lib.js";

const root = path.resolve(import.meta.dirname, "..");

async function main() {
  if (process.env.GITHUB_PAT) throw new Error("Phase 1 log inspection refuses a GitHub PAT in its environment");
  const { tenant, tenantDid, nodeUrl } = await connectTenant();
  const logs = await tenant.contracts.logs("breakglass", { limit: 100, minLevel: "info" });
  const entries = logs.entries.map((entry) => ({
    level: entry.level,
    message: entry.message,
    span_id_present: entry.span_id !== null,
  }));
  const secretLeak = entries.some((entry) => /gh[pousr]_|github_pat_|Bearer\s+\S+|BEGIN .*PRIVATE KEY|t3n_key_[A-Za-z0-9_-]+/i.test(entry.message));
  if (secretLeak) throw new Error("Phase 1 T3N log inspection found a likely secret pattern");
  const evidence = {
    phase: "1",
    stage: "t3n_log_inspection",
    environment: "testnet",
    sdk: "@terminal3/t3n-sdk 5.2.0",
    node_url: nodeUrl,
    operator_did: tenantDid,
    contract_tail: "breakglass",
    entries,
    next_seq: logs.next_seq,
    truncated: logs.truncated,
    likely_secret_pattern_found: false,
    github_pat_in_process: false,
  };
  await mkdir(path.join(root, "evidence"), { recursive: true });
  await writeFile(path.join(root, "evidence", "phase1-logs.json"), JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((error) => {
  console.error(`Phase 1 log inspection failed: ${redactError(error, [process.env.T3N_API_KEY ?? "", process.env.GITHUB_PAT ?? ""])}`);
  process.exitCode = 1;
});
