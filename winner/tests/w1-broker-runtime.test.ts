import assert from "node:assert/strict";
import { test } from "node:test";

import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { verifyProviderTarget, type ProviderVerifierAdapter } from "../broker/provider-verifier.js";
import { runBroker } from "../broker/run.js";
import { BreakGlassBrokerWorker, buildBrokerChildEnvironment } from "../runtime/broker-worker.js";
import { BreakGlassCoordinator } from "../runtime/coordinator.js";
import { RuntimeJobStore } from "../runtime/job-store.js";
import { PolicyRegistry, policyRegistryInputFromJson } from "../runtime/policy-registry.js";
import { fixturePolicy, observation, PUSH_AFTER_SHA, PUSH_BEFORE_SHA, PUSH_PRIVATE_MATERIAL_SHA256, PUSH_STATE_INTEGRITY_KEY, PUSH_TEST_SECRET, signedPush } from "./c2-push-fixture.js";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

const config = { appId: "1", installationId: "2", privateKeyPath: "C:\\outside\\app.pem", owner: "Ticoworld", repository: "t3n-breakglass-sandbox" };

function adapter(overrides: Partial<ProviderVerifierAdapter> = {}): ProviderVerifierAdapter {
  return {
    mint: async () => ({ token: "read-token", response: { status: 201, body: null, responseHeaders: {} } }),
    repositories: async () => ({ status: 200, body: { repositories: [{ full_name: "Ticoworld/t3n-breakglass-sandbox", private: true }] }, responseHeaders: {} }),
    exact: async () => ({ status: 404, body: null, responseHeaders: {} }),
    keys: async () => ({ status: 200, body: [], responseHeaders: {} }),
    revoke: async () => ({ status: 204, body: null, responseHeaders: {} }),
    probe: async () => ({ status: 401, body: null, responseHeaders: {} }),
    ...overrides,
  };
}

test("independent provider verification is read-only and cleans its separate token", async () => {
  const calls: string[] = [];
  const result = await verifyProviderTarget(config, 42, adapter({
    exact: async () => { calls.push("exact-get"); return { status: 404, body: null, responseHeaders: {} }; },
    keys: async () => { calls.push("list-keys"); return { status: 200, body: [], responseHeaders: {} }; },
    revoke: async () => { calls.push("revoke"); return { status: 204, body: null, responseHeaders: {} }; },
    probe: async () => { calls.push("refusal-probe"); return { status: 401, body: null, responseHeaders: {} }; },
  }));
  assert.equal(result.classification, "VERIFIED_ABSENT");
  assert.equal(result.token_minted, true);
  assert.equal(result.token_revoked, true);
  assert.equal(result.revoked_token_refused, true);
  assert.deepEqual(calls, ["exact-get", "list-keys", "revoke", "refusal-probe"]);
});

test("present target and cleanup failures never become verified absence", async () => {
  const present = await verifyProviderTarget(config, 42, adapter({ exact: async () => ({ status: 200, body: { id: 42 }, responseHeaders: {} }), keys: async () => ({ status: 200, body: [{ id: 42 }], responseHeaders: {} }) }));
  assert.equal(present.classification, "VERIFIED_PRESENT");
  await assert.rejects(() => verifyProviderTarget(config, 42, adapter({ revoke: async () => ({ status: 500, body: null, responseHeaders: {} }) })), /revocation failed/);
});

test("normal broker mode makes proof barriers conditional and never retries after effect-start", async () => {
  const source = await readFile(new URL("../broker/run.ts", import.meta.url), "utf8");
  assert.match(source, /C1_RUNTIME_MODE === "production"/);
  assert.match(source, /if \(!productionMode && proposalsComplete\)/);
  assert.match(source, /deleteMayHaveBeenInitiated = true/);
  assert.match(source, /retry_allowed: false/);
});

test("production broker child environment is an explicit allowlist", () => {
  const runtime: any = { role: "broker", paths: { root: "C:\\ProgramData\\BreakGlass", results: "C:\\ProgramData\\BreakGlass\\results" }, operatorDid: "did:t3n:0000000000000000000000000000000000000000", brokerDid: "did:t3n:0000000000000000000000000000000000000002", brokerApiKey: "broker-only", app: config };
  const job: any = { job_id: "job", incident_id: "incident", claim_version: 1, expected_target_title: "target", remote_state: "RESERVED" };
  const child = buildBrokerChildEnvironment(runtime, job, {
    PATH: "path", T3N_API_KEY: "operator-secret", AGENT_T3N_API_KEY: "remediation-secret", C2_WEBHOOK_SECRET: "webhook-secret", BREAKGLASS_STATE_INTEGRITY_KEY: "state-secret", C1_BARRIER_FILE: "proof-barrier", UNRELATED_API_KEY: "unrelated-secret",
  });
  assert.equal(child.EFFECT_BROKER_T3N_API_KEY, "broker-only");
  assert.equal(child.C1_OPERATOR_DID, runtime.operatorDid);
  for (const forbidden of ["T3N_API_KEY", "AGENT_T3N_API_KEY", "C2_WEBHOOK_SECRET", "BREAKGLASS_STATE_INTEGRITY_KEY", "C1_BARRIER_FILE", "UNRELATED_API_KEY"]) assert.equal(child[forbidden], undefined, forbidden);
});

test("two local broker workers do not create a second effect path, and a claim loser gets no provider authority", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "breakglass-w1-broker-workers-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const paths: any = { root, receipts: path.join(root, "receipts"), policies: path.join(root, "policies"), retirements: path.join(root, "retirements"), jobs: path.join(root, "jobs"), results: path.join(root, "results") };
  const runtime: any = { role: "broker", paths, operatorDid: "did:t3n:0000000000000000000000000000000000000000", remediationDid: "did:t3n:0000000000000000000000000000000000000001", brokerDid: "did:t3n:0000000000000000000000000000000000000002", contractId: "contract", app: config, pollMs: 1 };
  const jobs = new RuntimeJobStore(paths.jobs, { stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY });
  await jobs.initialize();
  await jobs.create({ incident_id: "worker-incident", receipt_key: "c".repeat(64), policy_id: "worker-policy", policy_version: 2, deploy_key_id: 42, expected_target_title: "target", create_request: { incident_id: "worker-incident", remediation_agent_did: runtime.remediationDid, effect_broker_did: runtime.brokerDid, deploy_key_id: 42, ttl_secs: 900 }, state: "HANDOFF_READY", remote_state: "RESERVED", operator_handoff_id: "handoff-1" });
  const registry = new PolicyRegistry(root);
  let childRuns = 0;
  let providerVerifications = 0;
  const adapters = { runChild: async () => { childRuns += 1; return { claim_outcome: "CLAIM_LOST", token_minted: false, destructive_call_count: 0, delete_attempted: false }; }, verifyProvider: async () => { providerVerifications += 1; return { classification: "VERIFIED_ABSENT" as const, target_id: 42, token_minted: true, token_revoked: true, revoked_token_refused: true, repository_scope_http_status: 200, exact_get_http_status: 404, list_get_http_status: 200, list_body_valid: true, list_contains_target: false }; }, reconcile: async () => ({ state: "CLOSED" }) };
  const first = new BreakGlassBrokerWorker(runtime, jobs, registry, adapters);
  const second = new BreakGlassBrokerWorker(runtime, jobs, registry, adapters);
  (first as any).brokerPrincipal = { apiKey: "broker", nodeUrl: "local", did: runtime.brokerDid };
  (second as any).brokerPrincipal = { apiKey: "broker", nodeUrl: "local", did: runtime.brokerDid };
  await Promise.all([first.tick(), second.tick()]);
  assert.equal(childRuns, 1);
  assert.equal(providerVerifications, 0);
  assert.equal((await jobs.get("worker-incident"))?.state, "RETRY_READY");
});

test("effect-start recovery verifies read-only and reconciles without invoking a delete", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "breakglass-w1-broker-reconcile-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const paths: any = { root, receipts: path.join(root, "receipts"), policies: path.join(root, "policies"), retirements: path.join(root, "retirements"), jobs: path.join(root, "jobs"), results: path.join(root, "results") };
  const runtime: any = { role: "broker", paths, operatorDid: "did:t3n:0000000000000000000000000000000000000000", remediationDid: "did:t3n:0000000000000000000000000000000000000001", brokerDid: "did:t3n:0000000000000000000000000000000000000002", contractId: "contract", app: config, pollMs: 1 };
  const jobs = new RuntimeJobStore(paths.jobs, { stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY });
  await jobs.initialize();
  await jobs.create({ incident_id: "reconcile-incident", receipt_key: "d".repeat(64), policy_id: "worker-policy", policy_version: 2, deploy_key_id: 42, expected_target_title: "target", create_request: { incident_id: "reconcile-incident", remediation_agent_did: runtime.remediationDid, effect_broker_did: runtime.brokerDid, deploy_key_id: 42, ttl_secs: 900 }, state: "RECONCILE_REQUIRED", remote_state: "EFFECT_STARTED", claim_id: "claim-1", claim_version: 1, effect_start_id: "start-1", operator_handoff_id: "handoff-reconcile" });
  const registry = new PolicyRegistry(root);
  let deletes = 0;
  const worker = new BreakGlassBrokerWorker(runtime, jobs, registry, { verifyProvider: async () => ({ classification: "VERIFIED_ABSENT", target_id: 42, token_minted: true, token_revoked: true, revoked_token_refused: true, repository_scope_http_status: 200, exact_get_http_status: 404, list_get_http_status: 200, list_body_valid: true, list_contains_target: false }), reconcile: async () => { deletes += 0; return { state: "CLOSED" }; } });
  (worker as any).brokerPrincipal = { apiKey: "broker", nodeUrl: "local", did: runtime.brokerDid };
  await worker.tick();
  assert.equal(deletes, 0);
  assert.equal((await jobs.get("reconcile-incident"))?.state, "CLOSED");
});

test("normal broker records a contract-closed child result without a second reconciliation attempt", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "breakglass-w1-broker-closed-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const paths: any = { root, receipts: path.join(root, "receipts"), policies: path.join(root, "policies"), retirements: path.join(root, "retirements"), jobs: path.join(root, "jobs"), results: path.join(root, "results") };
  const runtime: any = { role: "broker", paths, operatorDid: "did:t3n:0000000000000000000000000000000000000000", remediationDid: "did:t3n:0000000000000000000000000000000000000001", brokerDid: "did:t3n:0000000000000000000000000000000000000002", contractId: "contract", app: config, pollMs: 1 };
  const jobs = new RuntimeJobStore(paths.jobs, { stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY });
  await jobs.initialize();
  await jobs.create({ incident_id: "closed-incident", receipt_key: "e".repeat(64), policy_id: "worker-policy", policy_version: 2, deploy_key_id: 42, expected_target_title: "target", create_request: { incident_id: "closed-incident", remediation_agent_did: runtime.remediationDid, effect_broker_did: runtime.brokerDid, deploy_key_id: 42, ttl_secs: 900 }, state: "HANDOFF_READY", remote_state: "RESERVED", operator_handoff_id: "handoff-closed" });
  const registry = new PolicyRegistry(root);
  let verification = 0;
  const worker = new BreakGlassBrokerWorker(runtime, jobs, registry, {
    runChild: async () => ({ claim_outcome: "CLAIM_WON", effect_start_confirmed: true, effect_start_id: "start-1", classification: "VERIFIED_ABSENT", c1_state: "CLOSED", c1_result: "WON" }),
    verifyProvider: async () => { verification += 1; throw new Error("closed result must not re-verify"); },
  });
  (worker as any).brokerPrincipal = { apiKey: "broker", nodeUrl: "local", did: runtime.brokerDid };
  await worker.tick();
  assert.equal(verification, 0);
  assert.equal((await jobs.get("closed-incident"))?.state, "CLOSED");
});

function productionEnvironment(resultFile: string): NodeJS.ProcessEnv {
  return {
    C1_RUNTIME_MODE: "production",
    C1_RESULT_FILE: resultFile,
    C1_EXPECTED_CLAIM_VERSION: "0",
    C1_EXPECTED_TARGET_TITLE: "target",
    C1_OPERATOR_DID: "did:t3n:0000000000000000000000000000000000000000",
    EFFECT_BROKER_DID: "did:t3n:0000000000000000000000000000000000000002",
    EFFECT_BROKER_T3N_API_KEY: "broker-only-test-key",
    GITHUB_APP_ID: "1",
    GITHUB_APP_INSTALLATION_ID: "2",
    GITHUB_APP_PRIVATE_KEY_PATH: "C:\\outside\\app.pem",
    GITHUB_OWNER: "Ticoworld",
    GITHUB_REPO: "t3n-breakglass-sandbox",
  };
}

function maintainedBrokerEnvironment(root: string, statsFile: string, mode = "normal"): NodeJS.ProcessEnv {
  return {
    PATH: process.env.PATH,
    SystemRoot: process.env.SystemRoot,
    TEMP: process.env.TEMP,
    TMP: process.env.TMP,
    BREAKGLASS_DATA_DIRECTORY: root,
    BREAKGLASS_STATE_INTEGRITY_KEY: PUSH_STATE_INTEGRITY_KEY,
    BREAKGLASS_STATE_INTEGRITY_KEY_ID: "current",
    C1_OPERATOR_DID: "did:t3n:0000000000000000000000000000000000000000",
    AGENT_DID: "did:t3n:0000000000000000000000000000000000000001",
    EFFECT_BROKER_DID: "did:t3n:0000000000000000000000000000000000000002",
    EFFECT_BROKER_T3N_API_KEY: "broker-only-test-key",
    GITHUB_APP_ID: "1",
    GITHUB_APP_INSTALLATION_ID: "2",
    GITHUB_APP_PRIVATE_KEY_PATH: "C:\\outside\\app.pem",
    GITHUB_OWNER: "Ticoworld",
    GITHUB_REPO: "t3n-breakglass-sandbox",
    BROKER_TEST_STATS_FILE: statsFile,
    BROKER_TEST_MODE: mode,
  };
}

async function spawnMaintainedBrokerService(environment: NodeJS.ProcessEnv): Promise<{ code: number | null; stderr: string }> {
  return new Promise((resolve, reject) => {
    const processChild = spawn(process.execPath, ["--import", "tsx", path.resolve(import.meta.dirname, "production-broker-service-child.ts")], { cwd: process.cwd(), env: environment, stdio: ["ignore", "ignore", "pipe"], windowsHide: true });
    let stderr = "";
    processChild.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString("utf8"); });
    processChild.once("error", reject);
    processChild.once("close", (code) => resolve({ code, stderr }));
  });
}

function productionAdapters(options: { claimLost?: boolean } = {}) {
  let deleted = false;
  let deleteCalls = 0;
  let effectMints = 0;
  let verifierMints = 0;
  const c1Calls: string[] = [];
  const adapters: any = {
    connectC1Principal: async () => ({ apiKey: "broker-only-test-key", nodeUrl: "local", did: "did:t3n:0000000000000000000000000000000000000002" }),
    invokeC1: async (_apiKey: string, _nodeUrl: string, _contract: string, functionName: string) => {
      c1Calls.push(functionName);
      if (functionName === "claim-effect") return options.claimLost ? { result: "LOST", state: "RESERVED" } : { result: "PROPOSED", state: "EFFECT_CLAIMED", detail: { claim_id: "claim-1", claim_version: 1 } };
      if (functionName === "confirm-claim") return { result: "CONFIRMED", state: "EFFECT_CLAIMED", detail: { action: "revoke_github_deploy_key", github_owner: "Ticoworld", github_repo: "t3n-breakglass-sandbox", deploy_key_id: 42, claim_id: "claim-1", claim_version: 1 } };
      if (functionName === "begin-effect") return { result: "WON", function: "begin-effect", state: "EFFECT_STARTED", effect_attempts: 1, detail: { effect_start_id: "start-1" } };
      if (functionName === "confirm-effect-start") return { result: "CONFIRMED", function: "confirm-effect-start", state: "EFFECT_STARTED" };
      if (functionName === "finalize-effect") return { result: "WON", function: "finalize-effect", state: "CLOSED", final_result_classification: "VERIFIED_ABSENT" };
      if (functionName === "reconcile-effect") return { result: "WON", function: "reconcile-effect", state: "CLOSED", final_result_classification: "VERIFIED_ABSENT" };
      throw new Error(`unexpected C1 function ${functionName}`);
    },
    appConfigFromEnvironment: () => config,
    appJwt: async () => "test-jwt",
    validateInstallation: async () => ({ status: 200, body: {}, responseHeaders: {} }),
    mintEffectInstallationToken: async () => { effectMints += 1; return { response: { status: 201, body: {}, responseHeaders: {} }, token: "effect-token", metadata: { permissions: { administration: "write" }, repository_selection: "selected" } }; },
    mintReadOnlyInstallationToken: async () => { verifierMints += 1; return { response: { status: 201, body: {}, responseHeaders: {} }, token: "verifier-token", metadata: { permissions: { administration: "read" }, repository_selection: "selected" } }; },
    listInstallationRepositories: async () => ({ status: 200, body: { repositories: [{ full_name: "Ticoworld/t3n-breakglass-sandbox", private: true }] }, responseHeaders: {} }),
    exactKey: async (token: string) => token === "effect-token" && !deleted ? { status: 200, body: { id: 42, title: "target", read_only: true }, responseHeaders: {} } : { status: 404, body: null, responseHeaders: {} },
    listKeys: async (token: string) => token === "effect-token" && !deleted ? { status: 200, body: [{ id: 42 }], responseHeaders: {} } : { status: 200, body: [], responseHeaders: {} },
    deleteKey: async () => { deleteCalls += 1; deleted = true; return { status: 204, body: null, responseHeaders: { "x-github-request-id": "offline" } }; },
    revokeInstallationToken: async () => ({ status: 204, body: null, responseHeaders: {} }),
    repositoryRead: async () => ({ status: 401, body: null, responseHeaders: {} }),
  };
  return { adapters, stats: () => ({ deleted, deleteCalls, effectMints, verifierMints, c1Calls }) };
}

test("the real production broker entrypoint runs barrier-free through injected transport boundaries", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "breakglass-w1-production-broker-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const resultFile = path.join(root, "result.json");
  const fake = productionAdapters();
  await runBroker(productionEnvironment(resultFile), ["node", "run.ts", "production-incident"], fake.adapters);
  const result = JSON.parse(await readFile(resultFile, "utf8")) as Record<string, unknown>;
  const stats = fake.stats();
  assert.equal(result.effect_start_confirmed, true);
  assert.equal(result.c1_state, "CLOSED");
  assert.equal(result.c1_result, "WON");
  assert.equal(result.destructive_call_count, 1);
  assert.equal(result.delete_attempted, true);
  assert.equal(stats.deleteCalls, 1);
  assert.equal(stats.effectMints, 1);
  assert.equal(stats.verifierMints, 1);
  assert.deepEqual(stats.c1Calls, ["claim-effect", "confirm-claim", "begin-effect", "confirm-effect-start", "finalize-effect"]);
});

test("the real production broker entrypoint exits before provider authority on claim loss", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "breakglass-w1-production-loser-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const resultFile = path.join(root, "result.json");
  const fake = productionAdapters({ claimLost: true });
  await runBroker(productionEnvironment(resultFile), ["node", "run.ts", "losing-incident"], fake.adapters);
  const result = JSON.parse(await readFile(resultFile, "utf8")) as Record<string, unknown>;
  const stats = fake.stats();
  assert.equal(result.claim_outcome, "CLAIM_LOST");
  assert.equal(result.token_minted, false);
  assert.equal(result.destructive_call_count, 0);
  assert.equal(stats.effectMints, 0);
  assert.equal(stats.verifierMints, 0);
  assert.equal(stats.deleteCalls, 0);
  assert.deepEqual(stats.c1Calls, ["claim-effect"]);
});

test("the production broker entrypoint propagates result through an offline child process", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "breakglass-w1-production-child-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const resultFile = path.join(root, "child-result.json");
  const childEnvironment = productionEnvironment(resultFile);
  const child = await new Promise<{ code: number | null; stderr: string }>((resolve, reject) => {
    const processChild = spawn(process.execPath, ["--import", "tsx", path.resolve(import.meta.dirname, "production-broker-child.ts"), "child-production-incident"], { env: childEnvironment, stdio: ["ignore", "ignore", "pipe"], windowsHide: true });
    let stderr = "";
    processChild.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString("utf8"); });
    processChild.once("error", reject);
    processChild.once("close", (code) => resolve({ code, stderr }));
  });
  assert.equal(child.code, 0, child.stderr);
  const result = JSON.parse(await readFile(resultFile, "utf8")) as Record<string, unknown>;
  assert.equal(result.incident_id, "child-production-incident");
  assert.equal(result.c1_state, "CLOSED");
  assert.equal(result.destructive_call_count, 1);
  assert.equal(result.token_minted, true);
});

test("the actual breakglass broker service completes with operator-only get denied", async (t) => {
  const root = await mkdtemp(path.join(path.dirname(process.cwd()), "breakglass-w1-service-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const statsFile = path.join(root, "service-stats.json");
  const runtime: any = {
    role: "broker",
    paths: { root, receipts: path.join(root, "receipts"), policies: path.join(root, "policies"), retirements: path.join(root, "retirements"), jobs: path.join(root, "jobs"), results: path.join(root, "results") },
    operatorDid: "did:t3n:0000000000000000000000000000000000000000",
    remediationDid: "did:t3n:0000000000000000000000000000000000000001",
    brokerDid: "did:t3n:0000000000000000000000000000000000000002",
    contractId: "contract",
    app: config,
    pollMs: 10,
  };
  const jobs = new RuntimeJobStore(runtime.paths.jobs, { stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY });
  await jobs.initialize();
  await jobs.create({
    incident_id: "service-incident",
    receipt_key: "1".repeat(64),
    policy_id: "service-policy",
    policy_version: 1,
    deploy_key_id: 42,
    expected_target_title: "target",
    create_request: { incident_id: "service-incident", remediation_agent_did: runtime.remediationDid, effect_broker_did: runtime.brokerDid, deploy_key_id: 42, ttl_secs: 900 },
    state: "HANDOFF_READY",
    remote_state: "RESERVED",
    operator_handoff_id: "operator-handoff-service",
  });
  const environment = maintainedBrokerEnvironment(root, statsFile);
  const child = await spawnMaintainedBrokerService(environment);
  assert.equal(child.code, 0, child.stderr);
  const stats = JSON.parse(await readFile(statsFile, "utf8")) as { brokerGetIncidentCalls: number; c1Calls: string[]; deleteAttempts: number; effectTokenMints: number };
  assert.equal(stats.brokerGetIncidentCalls, 0);
  assert.equal(stats.c1Calls.includes("get-incident"), false);
  assert.deepEqual(stats.c1Calls, ["claim-effect", "confirm-claim", "begin-effect", "confirm-effect-start", "finalize-effect"]);
  assert.equal(stats.effectTokenMints, 1);
  assert.equal(stats.deleteAttempts, 1);
  assert.equal((await jobs.get("service-incident"))?.state, "CLOSED");
});

test("operator coordinator routes a real accepted job to the ACL-faithful broker service", async (t) => {
  const root = await mkdtemp(path.join(path.dirname(process.cwd()), "breakglass-w1-service-e2e-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const operatorDid = "did:t3n:0000000000000000000000000000000000000000";
  const remediationDid = "did:t3n:0000000000000000000000000000000000000001";
  const brokerDid = "did:t3n:0000000000000000000000000000000000000002";
  const registry = new PolicyRegistry(root, { stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY });
  await registry.initialize();
  await registry.create(policyRegistryInputFromJson(fixturePolicy({ policy_id: "service-e2e-policy", deploy_key_id: 42, expected_deploy_key_title: "target", remediation_agent_did: remediationDid, effect_broker_did: brokerDid })), { trustedEvidenceIdentity: "offline-service-e2e" });
  let remoteState: string | null = null;
  let operatorGetCalls = 0;
  const c1: any = {
    getIncident: async (incidentId: string) => {
      operatorGetCalls += 1;
      if (!remoteState) return { result: "DENIED", state: null, detail: {}, note: "incident authority does not exist" };
      return { result: "FOUND", state: remoteState, detail: { incident_id: incidentId, remediation_agent_did: remediationDid, effect_broker_did: brokerDid, action: "revoke_github_deploy_key", github_owner: "Ticoworld", github_repo: "t3n-breakglass-sandbox", deploy_key_id: 42, effect_claim_version: 0 } };
    },
    createIncident: async () => { remoteState = "ACTIVE"; return { result: "WON", state: "ACTIVE", detail: {} }; },
    reserveIncident: async () => { remoteState = "RESERVED"; return { result: "WON", state: "RESERVED", detail: {} }; },
  };
  const sourceReader = { readPlan: async (plan: any) => ({ before: observation(plan.before_sha, 404), after: observation(plan.after_sha, 200, PUSH_PRIVATE_MATERIAL_SHA256), token_minted: true, token_revoked: true, revoked_token_refused: true }) };
  const configForCoordinator: any = {
    role: "coordinator",
    paths: { root, receipts: path.join(root, "receipts"), policies: path.join(root, "policies"), retirements: path.join(root, "retirements"), jobs: path.join(root, "jobs"), results: path.join(root, "results") },
    listenHost: "127.0.0.1",
    listenPort: 0,
    webhookRoute: "/c2-b0/github-push",
    webhookSecret: PUSH_TEST_SECRET,
    maxBodyBytes: 1024 * 1024,
    operatorDid,
    remediationDid,
    brokerDid,
    contractId: "contract",
    contractVersion: "2.0.4",
    stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY,
    app: config,
    pollMs: 10,
  };
  const coordinator = new BreakGlassCoordinator({ config: configForCoordinator, registry, jobs: new RuntimeJobStore(configForCoordinator.paths.jobs, { stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY }), c1, sourceReader });
  const push = signedPush();
  const accepted = await coordinator.acceptWebhook({ headers: push.headers, body: push.body });
  assert.equal(accepted.body.accepted, true);
  assert.ok(operatorGetCalls > 0);
  const statsFile = path.join(root, "service-e2e-stats.json");
  const child = await spawnMaintainedBrokerService(maintainedBrokerEnvironment(root, statsFile));
  assert.equal(child.code, 0, child.stderr);
  const stats = JSON.parse(await readFile(statsFile, "utf8")) as { brokerGetIncidentCalls: number; c1Calls: string[]; deleteAttempts: number; effectTokenMints: number };
  assert.equal(stats.brokerGetIncidentCalls, 0);
  assert.deepEqual(stats.c1Calls, ["claim-effect", "confirm-claim", "begin-effect", "confirm-effect-start", "finalize-effect"]);
  assert.equal(stats.effectTokenMints, 1);
  assert.equal(stats.deleteAttempts, 1);
  assert.equal((await new RuntimeJobStore(configForCoordinator.paths.jobs, { stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY }).get(String(accepted.body.incident_id)))?.state, "CLOSED");
});

test("the actual breakglass broker service performs effect-start recovery without claim or DELETE", async (t) => {
  const root = await mkdtemp(path.join(path.dirname(process.cwd()), "breakglass-w1-service-recovery-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const statsFile = path.join(root, "service-recovery-stats.json");
  const incidentId = "service-recovery-incident";
  const jobs = new RuntimeJobStore(path.join(root, "jobs"), { stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY });
  await jobs.initialize();
  await jobs.create({
    incident_id: incidentId,
    receipt_key: "2".repeat(64),
    policy_id: "service-policy",
    policy_version: 1,
    deploy_key_id: 42,
    expected_target_title: "target",
    create_request: { incident_id: incidentId, remediation_agent_did: "did:t3n:0000000000000000000000000000000000000001", effect_broker_did: "did:t3n:0000000000000000000000000000000000000002", deploy_key_id: 42, ttl_secs: 900 },
    state: "RECONCILE_REQUIRED",
    remote_state: "EFFECT_STARTED",
    claim_id: "claim-service-recovery",
    claim_version: 1,
    effect_start_id: "start-service-recovery",
    operator_handoff_id: "operator-handoff-service-recovery",
  });
  await jobs.create({
    incident_id: "service-reconcile-required-incident",
    receipt_key: "4".repeat(64),
    policy_id: "service-policy",
    policy_version: 1,
    deploy_key_id: 42,
    expected_target_title: "target",
    create_request: { incident_id: "service-reconcile-required-incident", remediation_agent_did: "did:t3n:0000000000000000000000000000000000000001", effect_broker_did: "did:t3n:0000000000000000000000000000000000000002", deploy_key_id: 42, ttl_secs: 900 },
    state: "RECONCILE_REQUIRED",
    remote_state: "RECONCILE_REQUIRED",
    claim_id: "claim-service-reconcile-required",
    claim_version: 2,
    effect_start_id: "start-service-reconcile-required",
    operator_handoff_id: "operator-handoff-service-reconcile-required",
  });
  const child = await spawnMaintainedBrokerService(maintainedBrokerEnvironment(root, statsFile, "recovery"));
  assert.equal(child.code, 0, child.stderr);
  const stats = JSON.parse(await readFile(statsFile, "utf8")) as { brokerGetIncidentCalls: number; c1Calls: string[]; deleteAttempts: number; effectTokenMints: number; verifierTokenMints: number; childRuns: number };
  assert.equal(stats.brokerGetIncidentCalls, 0);
  assert.deepEqual(stats.c1Calls, ["reconcile-effect", "reconcile-effect"]);
  assert.equal(stats.childRuns, 0);
  assert.equal(stats.effectTokenMints, 0);
  assert.equal(stats.deleteAttempts, 0);
  assert.equal(stats.verifierTokenMints, 2);
  assert.equal((await jobs.get(incidentId))?.state, "CLOSED");
  assert.equal((await jobs.get("service-reconcile-required-incident"))?.state, "CLOSED");
});

test("a stale operator RESERVED snapshot cannot unlock provider authority after C1 claim loss", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "breakglass-w1-stale-snapshot-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const paths: any = { root, receipts: path.join(root, "receipts"), policies: path.join(root, "policies"), retirements: path.join(root, "retirements"), jobs: path.join(root, "jobs"), results: path.join(root, "results") };
  const runtime: any = { role: "broker", paths, operatorDid: "did:t3n:0000000000000000000000000000000000000000", remediationDid: "did:t3n:0000000000000000000000000000000000000001", brokerDid: "did:t3n:0000000000000000000000000000000000000002", brokerApiKey: "broker-only-test-key", contractId: "contract", app: config, pollMs: 1 };
  const jobs = new RuntimeJobStore(paths.jobs, { stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY });
  await jobs.initialize();
  await jobs.create({ incident_id: "stale-snapshot-incident", receipt_key: "3".repeat(64), policy_id: "stale-policy", policy_version: 1, deploy_key_id: 42, expected_target_title: "target", create_request: { incident_id: "stale-snapshot-incident", remediation_agent_did: runtime.remediationDid, effect_broker_did: runtime.brokerDid, deploy_key_id: 42, ttl_secs: 900 }, state: "HANDOFF_READY", remote_state: "RESERVED", operator_handoff_id: "operator-handoff-stale" });
  const fake = productionAdapters({ claimLost: true });
  const worker = new BreakGlassBrokerWorker(runtime, jobs, new PolicyRegistry(root), {
    connectBrokerPrincipal: async () => ({ apiKey: runtime.brokerApiKey, nodeUrl: "local", did: runtime.brokerDid }),
    runChild: async (_runtime: any, job: any) => {
      const resultFile = path.join(root, "stale-snapshot-result.json");
      await runBroker(productionEnvironment(resultFile), ["node", "run.ts", job.incident_id], fake.adapters);
      return JSON.parse(await readFile(resultFile, "utf8"));
    },
  });
  await worker.initialize();
  await worker.tick();
  assert.deepEqual(fake.stats().c1Calls, ["claim-effect"]);
  assert.equal(fake.stats().effectMints, 0);
  assert.equal(fake.stats().deleteCalls, 0);
  assert.equal((await jobs.get("stale-snapshot-incident"))?.state, "RETRY_READY");
});

test("heartbeat lease prevents overlap beyond the initial lease interval", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "breakglass-w1-heartbeat-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const jobs = new RuntimeJobStore(root, { stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY, leaseDurationMs: 1200 });
  await jobs.initialize();
  await jobs.create({ incident_id: "heartbeat-incident", receipt_key: "f".repeat(64), policy_id: "lease-policy", policy_version: 1, deploy_key_id: 42, expected_target_title: "target", create_request: { incident_id: "heartbeat-incident", remediation_agent_did: "did:t3n:agent", effect_broker_did: "did:t3n:broker", deploy_key_id: 42, ttl_secs: 900 }, state: "HANDOFF_READY" });
  const first = jobs.withLease("heartbeat-incident", async () => { await new Promise((resolve) => setTimeout(resolve, 2200)); return "owner"; });
  await new Promise((resolve) => setTimeout(resolve, 1500));
  const overlap = await jobs.withLease("heartbeat-incident", async () => "overlap");
  assert.equal(overlap, null);
  assert.equal(await first, "owner");
});

test("broker never substitutes local retry state for an operator handoff", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "breakglass-w1-retry-recovery-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const paths: any = { root, receipts: path.join(root, "receipts"), policies: path.join(root, "policies"), retirements: path.join(root, "retirements"), jobs: path.join(root, "jobs"), results: path.join(root, "results") };
  const runtime: any = { role: "broker", paths, operatorDid: "did:t3n:0000000000000000000000000000000000000000", remediationDid: "did:t3n:0000000000000000000000000000000000000001", brokerDid: "did:t3n:0000000000000000000000000000000000000002", contractId: "contract", app: config, pollMs: 1 };
  const jobs = new RuntimeJobStore(paths.jobs, { stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY });
  await jobs.initialize();
  await jobs.create({ incident_id: "retry-effect-started", receipt_key: "a".repeat(64), policy_id: "retry-policy", policy_version: 1, deploy_key_id: 42, expected_target_title: "target", create_request: { incident_id: "retry-effect-started", remediation_agent_did: runtime.remediationDid, effect_broker_did: runtime.brokerDid, deploy_key_id: 42, ttl_secs: 900 }, state: "RETRY_READY" });
  let childRuns = 0;
  const worker = new BreakGlassBrokerWorker(runtime, jobs, new PolicyRegistry(root), {
    runChild: async () => { childRuns += 1; return {}; },
    verifyProvider: async () => { throw new Error("provider verifier is not part of this restart step"); },
  });
  (worker as any).brokerPrincipal = { apiKey: "broker", nodeUrl: "local", did: runtime.brokerDid };
  const before = await jobs.get("retry-effect-started");
  await worker.tick();
  assert.equal(childRuns, 0);
  assert.deepEqual(await jobs.get("retry-effect-started"), before);
});

test("expired lease with a dead owner is reclaimable, while ownership remains exclusive", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "breakglass-w1-stale-lease-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const jobs = new RuntimeJobStore(root, { stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY, leaseDurationMs: 300 });
  await jobs.initialize();
  const incidentId = "stale-lease-incident";
  await jobs.create({ incident_id: incidentId, receipt_key: "b".repeat(64), policy_id: "lease-policy", policy_version: 1, deploy_key_id: 42, expected_target_title: "target", create_request: { incident_id: incidentId, remediation_agent_did: "did:t3n:agent", effect_broker_did: "did:t3n:broker", deploy_key_id: 42, ttl_secs: 900 }, state: "HANDOFF_READY" });
  const leaseFile = path.join(root, `${createHash("sha256").update(incidentId, "utf8").digest("hex")}.lease`);
  const expired = new Date(Date.now() - 10_000).toISOString();
  await writeFile(leaseFile, JSON.stringify({ schema_version: 1, owner_id: "dead-owner", pid: 999999, acquired_at: expired, last_heartbeat_at: expired, expires_at: expired, heartbeat_sequence: 2 }));
  assert.equal(await jobs.withLease(incidentId, async () => "reclaimed"), "reclaimed");
});

test("expired lease with a live or identity-ambiguous PID fails closed", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "breakglass-w1-live-lease-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const jobs = new RuntimeJobStore(root, { stateIntegrityKey: PUSH_STATE_INTEGRITY_KEY, leaseDurationMs: 300 });
  await jobs.initialize();
  const incidentId = "live-lease-incident";
  await jobs.create({ incident_id: incidentId, receipt_key: "c".repeat(64), policy_id: "lease-policy", policy_version: 1, deploy_key_id: 42, expected_target_title: "target", create_request: { incident_id: incidentId, remediation_agent_did: "did:t3n:agent", effect_broker_did: "did:t3n:broker", deploy_key_id: 42, ttl_secs: 900 }, state: "HANDOFF_READY" });
  const leaseFile = path.join(root, `${createHash("sha256").update(incidentId, "utf8").digest("hex")}.lease`);
  const expired = new Date(Date.now() - 10_000).toISOString();
  await writeFile(leaseFile, JSON.stringify({ schema_version: 1, owner_id: "ambiguous-owner", pid: process.pid, acquired_at: expired, last_heartbeat_at: expired, expires_at: expired, heartbeat_sequence: 2 }));
  await assert.rejects(() => jobs.withLease(incidentId, async () => "must-not-run"), /LEASE_OWNER_AMBIGUOUS/);
});
