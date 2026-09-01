import { readFile } from "node:fs/promises";
import path from "node:path";
import { connectTenant } from "../scripts/lib.js";

const root = path.resolve(import.meta.dirname, "..");
const wasmPath = path.join(root, "research", "C-0R-outbox-probe", "target", "wasm32-wasip2", "release", "c0r_outbox_probe.wasm");
const tail = "c0r-outbox-probe";
const version = "0.1.1";

function safeError(error: unknown): string {
  const key = process.env.T3N_API_KEY ?? "";
  const message = error instanceof Error ? error.message : String(error);
  return key ? message.split(key).join("[REDACTED_T3N_API_KEY]") : message;
}

function safeErrorObject(error: unknown): Record<string, unknown> {
  const value: Record<string, unknown> = { message: safeError(error) };
  if (error && typeof error === "object") {
    for (const key of ["name", "code", "httpStatus", "requestId", "detail", "data"]) {
      if (key in error) value[key] = key === "detail" || key === "data" ? safeError((error as Record<string, unknown>)[key]) : (error as Record<string, unknown>)[key];
    }
  }
  return value;
}

if (process.env.GITHUB_PAT) {
  throw new Error("probe refuses to run when GITHUB_PAT is present in its environment");
}

const evidence: Record<string, unknown> = {
  experiment: "R1 durable outbox testnet registration and safe invocation",
  date_utc: new Date().toISOString(),
  sdk_version: "@terminal3/t3n-sdk 5.2.0",
  node_environment: "testnet",
  contract_tail: tail,
  contract_version: version,
  wasm_sha256: "omitted-from-console-and-evidence-by-design",
  request: { method: "GET", url: "https://example.com/", body: "empty" },
  credentials_in_probe: false,
};

try {
  const { tenant, tenantDid } = await connectTenant();
  evidence.tenant_did = tenantDid;
  evidence.registration_attempted = true;
  try {
    const registered = await tenant.contracts.register({
      tail,
      version,
      wasm: new Uint8Array(await readFile(wasmPath)),
    });
    evidence.registration = { outcome: "success", result: registered };
    try {
      const result = await tenant.contracts.execute(tail, {
        version,
        functionName: "enqueue-probe",
        input: { input: new TextEncoder().encode("c0r-safe-probe"), userProfile: undefined, context: undefined },
      });
      evidence.invocation = { outcome: "success", result };
    } catch (error) {
      evidence.invocation = { outcome: "error", error: safeErrorObject(error) };
    }
    try {
      evidence.contract_logs = await tenant.contracts.logs(tail, { limit: 100 });
    } catch (error) {
      evidence.contract_logs = { outcome: "error", error: safeErrorObject(error) };
    }
  } catch (error) {
    evidence.registration = { outcome: "error", error: safeErrorObject(error) };
  }
} catch (error) {
  evidence.connection = { outcome: "error", error: safeErrorObject(error) };
}

console.log(JSON.stringify(evidence, null, 2));
