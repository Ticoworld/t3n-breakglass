import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { connectTenant } from "../scripts/lib.js";

const root = path.resolve(import.meta.dirname, "..");
const occ = JSON.parse(await readFile(path.join(root, "research", "C-0R-occ-result.json"), "utf8"));
const tail = String(occ.contract_tail);
const version = String(occ.contract_version);
const targetId = `audit-probe-${Date.now()}`;

function safeError(error: unknown): Record<string, unknown> {
  const key = process.env.T3N_API_KEY ?? "";
  const message = error instanceof Error ? error.message : String(error);
  const result: Record<string, unknown> = { message: key ? message.split(key).join("[REDACTED_T3N_API_KEY]") : message };
  if (error && typeof error === "object") {
    for (const field of ["name", "code", "httpStatus", "requestId", "detail"]) {
      if (field in error) result[field] = (error as Record<string, unknown>)[field];
    }
  }
  return result;
}

if (process.env.GITHUB_PAT) throw new Error("audit probe refuses GITHUB_PAT");
const evidence: Record<string, unknown> = {
  experiment: "R4 live T3N activity/audit receipt binding",
  date_utc: new Date().toISOString(),
  sdk_version: "@terminal3/t3n-sdk 5.2.0",
  node_environment: "testnet",
  contract_tail: tail,
  contract_version: version,
  safe_input: { target_id: targetId, contender_id: "audit-probe" },
  credentials_in_evidence: false,
};

try {
  const { tenant, tenantDid, t3n } = await connectTenant();
  evidence.caller_did = tenantDid;
  try {
    evidence.invocation = await tenant.contracts.execute(tail, {
      version,
      functionName: "reserve",
      input: { target_id: targetId, contender_id: "audit-probe" },
    });
  } catch (error) {
    evidence.invocation_error = safeError(error);
  }
  try { evidence.activity = await t3n.getActivityLog({ contract: tail, function: "reserve", limit: 10 }); }
  catch (error) { evidence.activity_error = safeError(error); }
  try { evidence.audit_events = await t3n.getAuditEvents({ limit: 10 }); }
  catch (error) { evidence.audit_events_error = safeError(error); }
  try { evidence.contract_logs = await tenant.contracts.logs(tail, { limit: 20 }); }
  catch (error) { evidence.contract_logs_error = safeError(error); }
} catch (error) {
  evidence.connection_error = safeError(error);
}

await writeFile(path.join(root, "research", "C-0R-audit-result.json"), JSON.stringify(evidence, null, 2) + "\n");
console.log(JSON.stringify(evidence, null, 2));
