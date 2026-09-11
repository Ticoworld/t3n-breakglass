import { writeFileSync } from "node:fs";

import type { BrokerRuntimeAdapters } from "../broker/run.js";

const app = { appId: "1", installationId: "2", privateKeyPath: "C:\\outside\\app.pem", owner: "Ticoworld", repository: "t3n-breakglass-sandbox" };
const statsFile = process.env.BROKER_TEST_STATS_FILE;
if (!statsFile) throw new Error("BROKER_TEST_STATS_FILE is required");

let deleted = false;
let deleteAttempts = 0;
let effectTokenMints = 0;
let verifierTokenMints = 0;
let brokerGetIncidentCalls = 0;
const c1Calls: string[] = [];

function persist(): void {
  writeFileSync(statsFile!, JSON.stringify({ brokerGetIncidentCalls, c1Calls, deleteAttempts, effectTokenMints, verifierTokenMints }) + "\n", "utf8");
}

export const brokerRuntimeAdapters: Partial<BrokerRuntimeAdapters> = {
  connectC1Principal: async () => ({ apiKey: "broker-only-test-key", nodeUrl: "local", did: "did:t3n:0000000000000000000000000000000000000002" }),
  invokeC1: async (_apiKey: string, _nodeUrl: string, _contract: string, functionName: string) => {
    c1Calls.push(functionName);
    if (functionName === "get-incident") {
      brokerGetIncidentCalls += 1;
      persist();
      return { result: "DENIED", state: null, note: "broker is not the tenant operator" };
    }
    if (functionName === "claim-effect") { persist(); return { result: "PROPOSED", state: "EFFECT_CLAIMED", detail: { claim_id: "claim-service", claim_version: 1 } }; }
    if (functionName === "confirm-claim") { persist(); return { result: "CONFIRMED", state: "EFFECT_CLAIMED", detail: { action: "revoke_github_deploy_key", github_owner: "Ticoworld", github_repo: "t3n-breakglass-sandbox", deploy_key_id: 42, claim_id: "claim-service", claim_version: 1 } }; }
    if (functionName === "begin-effect") { persist(); return { result: "WON", function: "begin-effect", state: "EFFECT_STARTED", effect_attempts: 1, detail: { effect_start_id: "start-service" } }; }
    if (functionName === "confirm-effect-start") { persist(); return { result: "CONFIRMED", function: "confirm-effect-start", state: "EFFECT_STARTED" }; }
    if (functionName === "finalize-effect") { persist(); return { result: "WON", function: "finalize-effect", state: "CLOSED", final_result_classification: "VERIFIED_ABSENT" }; }
    if (functionName === "reconcile-effect") { persist(); return { result: "WON", function: "reconcile-effect", state: "CLOSED", final_result_classification: "VERIFIED_ABSENT" }; }
    throw new Error(`unexpected C1 function ${functionName}`);
  },
  appConfigFromEnvironment: () => app,
  appJwt: async () => "service-test-jwt",
  validateInstallation: async () => ({ status: 200, body: {}, responseHeaders: {} }),
  mintEffectInstallationToken: async () => { effectTokenMints += 1; persist(); return { response: { status: 201, body: {}, responseHeaders: {} }, token: "effect-service-token", metadata: { permissions: { administration: "write" }, repository_selection: "selected" } }; },
  mintReadOnlyInstallationToken: async () => { verifierTokenMints += 1; persist(); return { response: { status: 201, body: {}, responseHeaders: {} }, token: "verifier-service-token", metadata: { permissions: { administration: "read" }, repository_selection: "selected" } }; },
  listInstallationRepositories: async () => ({ status: 200, body: { repositories: [{ full_name: "Ticoworld/t3n-breakglass-sandbox", private: true }] }, responseHeaders: {} }),
  exactKey: async (token: string) => token === "effect-service-token" && !deleted ? { status: 200, body: { id: 42, title: "target", read_only: true }, responseHeaders: {} } : { status: 404, body: null, responseHeaders: {} },
  listKeys: async (token: string) => token === "effect-service-token" && !deleted ? { status: 200, body: [{ id: 42 }], responseHeaders: {} } : { status: 200, body: [], responseHeaders: {} },
  deleteKey: async () => { deleteAttempts += 1; deleted = true; persist(); return { status: 204, body: null, responseHeaders: { "x-github-request-id": "offline-service" } }; },
  revokeInstallationToken: async () => ({ status: 204, body: null, responseHeaders: {} }),
  repositoryRead: async () => ({ status: 401, body: null, responseHeaders: {} }),
};

persist();
