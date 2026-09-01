import { readFile } from "node:fs/promises";
import path from "node:path";
import { connectTenant } from "../scripts/lib.js";

const root = path.resolve(import.meta.dirname, "..");
const wasmPath = path.join(root, "research", "C-0R-outbox-probe", "target", "wasm32-wasip2", "release", "c0r_outbox_probe.wasm");
const tail = "c0r-outbox-link-probe";
const version = "0.1.2";

function safeError(error: unknown): Record<string, unknown> {
  const message = error instanceof Error ? error.message : String(error);
  const key = process.env.T3N_API_KEY ?? "";
  const safe = key ? message.split(key).join("[REDACTED_T3N_API_KEY]") : message;
  const value: Record<string, unknown> = { message: safe };
  if (error && typeof error === "object") {
    for (const field of ["name", "code", "httpStatus", "requestId", "detail", "data"]) {
      if (field in error) {
        const raw = String((error as Record<string, unknown>)[field]);
        value[field] = field === "detail" || field === "data"
          ? (key ? raw.split(key).join("[REDACTED_T3N_API_KEY]") : raw)
          : (error as Record<string, unknown>)[field];
      }
    }
  }
  return value;
}

if (process.env.GITHUB_PAT) throw new Error("probe refuses to run when GITHUB_PAT is present");

const evidence: Record<string, unknown> = {
  experiment: "R1 outbox-link probe: import present, no outbox call",
  date_utc: new Date().toISOString(),
  sdk_version: "@terminal3/t3n-sdk 5.2.0",
  node_environment: "testnet",
  contract_tail: tail,
  contract_version: version,
  credentials_in_probe: false,
};

try {
  const { tenant, tenantDid } = await connectTenant();
  evidence.tenant_did = tenantDid;
  try {
    const registered = await tenant.contracts.register({
      tail,
      version,
      wasm: new Uint8Array(await readFile(wasmPath)),
    });
    evidence.registration = { outcome: "success", result: registered };
    try {
      evidence.invocation = {
        outcome: "success",
        result: await tenant.contracts.execute(tail, {
          version,
          functionName: "link-probe",
          input: { input: undefined, userProfile: undefined, context: undefined },
        }),
      };
    } catch (error) {
      evidence.invocation = { outcome: "error", error: safeError(error) };
    }
  } catch (error) {
    evidence.registration = { outcome: "error", error: safeError(error) };
  }
} catch (error) {
  evidence.connection = { outcome: "error", error: safeError(error) };
}

console.log(JSON.stringify(evidence, null, 2));
