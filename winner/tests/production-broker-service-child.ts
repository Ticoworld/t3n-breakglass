import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import { runBrokerService } from "../runtime/broker.js";

const statsFile = process.env.BROKER_TEST_STATS_FILE;
if (!statsFile) throw new Error("BROKER_TEST_STATS_FILE is required");

let verifierTokenMints = 0;
let childRuns = 0;
const c1Calls: string[] = [];
const transportModule = path.resolve(import.meta.dirname, "production-broker-transport.ts");

const brokerDid = "did:t3n:0000000000000000000000000000000000000002";

const workerAdapters = {
  // This is the only test seam needed by the maintained service itself. The
  // normal child launcher remains the production implementation; the child
  // loads only transport fakes through its explicit offline test module.
  transportModule,
  connectBrokerPrincipal: async () => ({ apiKey: "broker-only-test-key", nodeUrl: "local", did: brokerDid }),
  verifyProvider: async () => {
    verifierTokenMints += 1;
    return { classification: "VERIFIED_ABSENT" as const, target_id: 42, token_minted: true, token_revoked: true, revoked_token_refused: true, repository_scope_http_status: 200, exact_get_http_status: 404, list_get_http_status: 200, list_body_valid: true, list_contains_target: false };
  },
  reconcile: async (_config: any, job: any, classification: string) => { c1Calls.push("reconcile-effect"); return { result: "WON", function: "reconcile-effect", state: "CLOSED", final_result_classification: classification, incident_id: job.incident_id }; },
};

try {
  await runBrokerService({ adapters: workerAdapters, once: true });
} finally {
  let childStats: Record<string, unknown> = {};
  try { childStats = JSON.parse(await readFile(statsFile, "utf8")) as Record<string, unknown>; } catch { /* recovery-only mode has no broker child */ }
  await writeFile(statsFile, JSON.stringify({
    ...childStats,
    brokerGetIncidentCalls: childStats.brokerGetIncidentCalls ?? 0,
    c1Calls: childStats.c1Calls ?? c1Calls,
    deleteAttempts: childStats.deleteAttempts ?? 0,
    effectTokenMints: childStats.effectTokenMints ?? 0,
    verifierTokenMints: Number(childStats.verifierTokenMints ?? 0) + verifierTokenMints,
    childRuns,
  }) + "\n", "utf8");
}
