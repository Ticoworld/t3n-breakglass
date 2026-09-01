import { createServer, type IncomingMessage } from "node:http";
import { writeFile } from "node:fs/promises";
import path from "node:path";

type Mode = "ack" | "drop_after_effect" | "drop_before_effect" | "verify_unavailable";
const calls: Array<{ method: string; path: string; operation_id: string; at_ms: number }> = [];
let targetPresent = true;
let mode: Mode = "ack";
let verifyAvailable = true;

function body(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => { let out = ""; req.on("data", (chunk) => { out += String(chunk); }); req.on("end", () => resolve(out)); });
}

const server = createServer(async (req, res) => {
  const operationId = String(req.headers["x-operation-id"] ?? "missing");
  calls.push({ method: req.method ?? "", path: req.url ?? "", operation_id: operationId, at_ms: Date.now() });
  if (req.url === "/target" && req.method === "GET") {
    if (!verifyAvailable || mode === "verify_unavailable") { req.socket.destroy(); return; }
    res.statusCode = targetPresent ? 200 : 404;
    res.end();
    return;
  }
  if (req.url === "/target" && req.method === "DELETE") {
    await body(req);
    if (mode === "drop_after_effect") targetPresent = false;
    if (mode === "drop_after_effect" || mode === "drop_before_effect") { req.socket.destroy(); return; }
    targetPresent = false;
    res.statusCode = 204;
    res.end();
    return;
  }
  res.statusCode = 404;
  res.end();
});

await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
const address = server.address();
if (!address || typeof address === "string") throw new Error("local connector did not expose a port");
const base = `http://127.0.0.1:${address.port}`;

async function request(method: "GET" | "DELETE", operationId: string): Promise<{ ok: boolean; status?: number; error?: string }> {
  try {
    const response = await fetch(`${base}/target`, { method, headers: { "X-Operation-Id": operationId } });
    return { ok: true, status: response.status };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.name : String(error) };
  }
}

const cases: Array<Record<string, unknown>> = [];
const operation = "c0r-ambiguous-operation-01";

// No outbound request was made.
targetPresent = true; mode = "ack"; verifyAvailable = true;
const beforeNotAttempted = calls.length;
cases.push({ name: "NOT_ATTEMPTED", provider_requests_before: beforeNotAttempted, provider_requests_after: calls.length, classification: "NOT_ATTEMPTED" });

// The connector applies the side effect and drops the response; verification is unavailable.
targetPresent = true; mode = "drop_after_effect"; verifyAvailable = false;
const unknownRequest = await request("DELETE", operation);
const unknownCalls = calls.filter((call) => call.operation_id === operation).length;
cases.push({ name: "ATTEMPTED_OUTCOME_UNKNOWN", client_response: unknownRequest, provider_request_count: unknownCalls, provider_side_effect_observed_by_fixture: !targetPresent, verification: "unavailable", retry_count: 0, classification: "ATTEMPTED_OUTCOME_UNKNOWN" });

// A provider acknowledgement is a transport-level fact, not yet independent verification.
targetPresent = true; mode = "ack"; verifyAvailable = true;
const acknowledged = await request("DELETE", "c0r-acknowledged-01");
cases.push({ name: "PROVIDER_ACKNOWLEDGED", client_response: acknowledged, provider_request_count: calls.filter((call) => call.operation_id === "c0r-acknowledged-01").length, classification: "PROVIDER_ACKNOWLEDGED" });

// A dropped response can still be resolved by a successful read showing absence.
targetPresent = true; mode = "drop_after_effect"; verifyAvailable = true;
const droppedThenVerifiedAbsent = await request("DELETE", "c0r-verified-absent-01");
const verifiedAbsent = await request("GET", "c0r-verified-absent-01");
cases.push({ name: "VERIFIED_ABSENT", delete_response: droppedThenVerifiedAbsent, verification_response: verifiedAbsent, classification: verifiedAbsent.status === 404 ? "VERIFIED_ABSENT" : "not-proven" });

// A dropped response before the side effect is applied can be resolved by a read showing presence.
targetPresent = true; mode = "drop_before_effect"; verifyAvailable = true;
const droppedThenVerifiedPresent = await request("DELETE", "c0r-verified-present-01");
const verifiedPresent = await request("GET", "c0r-verified-present-01");
cases.push({ name: "VERIFIED_PRESENT", delete_response: droppedThenVerifiedPresent, verification_response: verifiedPresent, classification: verifiedPresent.status === 200 ? "VERIFIED_PRESENT" : "not-proven" });

const evidence = {
  experiment: "R7 post-effect ambiguity with disposable local connector",
  date_utc: new Date().toISOString(),
  connector: "127.0.0.1 disposable HTTP fixture; no GitHub/Circle/provider resource",
  operation_identity: operation,
  cases,
  total_provider_requests: calls.length,
  unknown_operation_request_count: calls.filter((call) => call.operation_id === operation).length,
  no_blind_retry_proven: calls.filter((call) => call.operation_id === operation).length === 1,
  conclusion: "A dropped response is not an acknowledgement. A safe system needs an explicit unknown state plus provider verification or an idempotent connector operation identity; retrying the destructive call blindly is unsound.",
};

server.close();
const root = path.resolve(import.meta.dirname, "..");
await writeFile(path.join(root, "research", "C-0R-ambiguity-result.json"), JSON.stringify(evidence, null, 2) + "\n");
console.log(JSON.stringify(evidence, null, 2));
