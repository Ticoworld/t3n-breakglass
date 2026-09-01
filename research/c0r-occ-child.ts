import { existsSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { connectTenant } from "../scripts/lib.js";

const barrier = process.env.C0R_BARRIER_FILE!;
const ready = process.env.C0R_READY_FILE!;
const tail = process.env.C0R_OCC_TAIL!;
const version = process.env.C0R_OCC_VERSION!;
const targetId = process.env.C0R_TARGET_ID!;
const contenderId = process.env.C0R_CONTENDER_ID!;

function safeError(error: unknown): Record<string, unknown> {
  const apiKey = process.env.T3N_API_KEY ?? "";
  const message = error instanceof Error ? error.message : String(error);
  const result: Record<string, unknown> = { message: apiKey ? message.split(apiKey).join("[REDACTED_T3N_API_KEY]") : message };
  if (error && typeof error === "object") {
    for (const key of ["name", "code", "httpStatus", "requestId", "detail"]) {
      if (key in error) result[key] = (error as Record<string, unknown>)[key];
    }
  }
  return result;
}

if (process.env.GITHUB_PAT) throw new Error("occ child refuses GITHUB_PAT");
const evidence: Record<string, unknown> = {
  contender_id: contenderId,
  input: { target_id: targetId, contender_id: contenderId },
  process_id: process.pid,
};

try {
  const { tenant, tenantDid } = await connectTenant();
  evidence.caller_tenant_did = tenantDid;
  await writeFile(ready, JSON.stringify({ contender_id: contenderId, ready_at_unix_ms: Date.now(), process_id: process.pid }));
  while (!existsSync(barrier)) await new Promise((resolve) => setTimeout(resolve, 10));
  evidence.started_at_unix_ms = Date.now();
  evidence.started_at_monotonic_ms = performance.now();
  try {
    evidence.response = await tenant.contracts.execute(tail, {
      version,
      functionName: "reserve",
      input: { target_id: targetId, contender_id: contenderId },
    });
  } catch (error) {
    evidence.error = safeError(error);
  }
  evidence.finished_at_unix_ms = Date.now();
} catch (error) {
  evidence.error = safeError(error);
}

process.stdout.write(JSON.stringify(evidence));
