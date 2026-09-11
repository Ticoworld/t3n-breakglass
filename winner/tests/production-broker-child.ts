import { runBroker } from "../broker/run.js";

const app = { appId: "1", installationId: "2", privateKeyPath: "C:\\outside\\app.pem", owner: "Ticoworld", repository: "t3n-breakglass-sandbox" };
let deleted = false;

const adapters = {
  connectC1Principal: async () => ({ apiKey: "broker-only-test-key", nodeUrl: "local", did: "did:t3n:0000000000000000000000000000000000000002" }),
  invokeC1: async (_apiKey: string, _nodeUrl: string, _contract: string, functionName: string) => {
    if (functionName === "claim-effect") return { result: "PROPOSED", state: "EFFECT_CLAIMED", detail: { claim_id: "claim-child", claim_version: 1 } };
    if (functionName === "confirm-claim") return { result: "CONFIRMED", state: "EFFECT_CLAIMED", detail: { action: "revoke_github_deploy_key", github_owner: "Ticoworld", github_repo: "t3n-breakglass-sandbox", deploy_key_id: 42, claim_id: "claim-child", claim_version: 1 } };
    if (functionName === "begin-effect") return { result: "WON", function: "begin-effect", state: "EFFECT_STARTED", effect_attempts: 1, detail: { effect_start_id: "start-child" } };
    if (functionName === "confirm-effect-start") return { result: "CONFIRMED", function: "confirm-effect-start", state: "EFFECT_STARTED" };
    if (functionName === "finalize-effect") return { result: "WON", function: "finalize-effect", state: "CLOSED", final_result_classification: "VERIFIED_ABSENT" };
    throw new Error(`unexpected C1 function ${functionName}`);
  },
  appConfigFromEnvironment: () => app,
  appJwt: async () => "child-test-jwt",
  validateInstallation: async () => ({ status: 200, body: {}, responseHeaders: {} }),
  mintEffectInstallationToken: async () => ({ response: { status: 201, body: {}, responseHeaders: {} }, token: "child-effect-token", metadata: { permissions: { administration: "write" }, repository_selection: "selected" } }),
  mintReadOnlyInstallationToken: async () => ({ response: { status: 201, body: {}, responseHeaders: {} }, token: "child-verifier-token", metadata: { permissions: { administration: "read" }, repository_selection: "selected" } }),
  listInstallationRepositories: async () => ({ status: 200, body: { repositories: [{ full_name: "Ticoworld/t3n-breakglass-sandbox", private: true }] }, responseHeaders: {} }),
  exactKey: async (token: string) => token === "child-effect-token" && !deleted ? { status: 200, body: { id: 42, title: "target", read_only: true }, responseHeaders: {} } : { status: 404, body: null, responseHeaders: {} },
  listKeys: async (token: string) => ({ status: 200, body: token === "child-effect-token" && !deleted ? [{ id: 42 }] : [], responseHeaders: {} }),
  deleteKey: async () => { deleted = true; return { status: 204, body: null, responseHeaders: {} }; },
  revokeInstallationToken: async () => ({ status: 204, body: null, responseHeaders: {} }),
  repositoryRead: async () => ({ status: 401, body: null, responseHeaders: {} }),
};

await runBroker(process.env, process.argv, adapters);
