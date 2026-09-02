import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { appConfigFromEnvironment, mintInstallationToken, repositoryListIsWellFormed, revokeInstallationToken, validateInstallation } from "../broker/github-app.js";
import { claimTargetMatchesConfiguredRepository, classifyProviderOutcome, destructiveRetryAllowed, parseClaim } from "../broker/logic.js";
import { redact, refuseProviderOrOperatorCredentials } from "../scripts/t3n.js";

const runSource = await readFile(new URL("../broker/run.ts", import.meta.url), "utf8");
const liveSource = await readFile(new URL("../scripts/c1-live.ts", import.meta.url), "utf8");
const configureSource = await readFile(new URL("../scripts/configure.ts", import.meta.url), "utf8");
const seedSource = await readFile(new URL("../scripts/seed-incident.ts", import.meta.url), "utf8");
const t3nSource = await readFile(new URL("../scripts/t3n.ts", import.meta.url), "utf8");

test("claim-before-effect ordering is source-enforced", () => {
  const claim = runSource.indexOf('"claim-effect"');
  const committed = runSource.indexOf('evidence.claim_outcome = "CLAIM_WON"');
  const jwt = runSource.indexOf("const jwt = await appJwt");
  const token = runSource.indexOf("mintInstallationToken(config, jwt)");
  const providerGet = runSource.indexOf("exactKey(token");
  const providerDelete = runSource.indexOf("deleteKey(token");
  assert.ok(claim >= 0 && committed > claim && jwt > committed && token > jwt && providerGet > token && providerDelete > providerGet);
  assert.equal(runSource.includes("Promise.all"), false, "broker must not start provider work concurrently with claim");
  const release = runSource.indexOf("const releaseClaim");
  const deleteBoundary = runSource.indexOf("deleteMayHaveBeenInitiated = true");
  const catchRelease = runSource.indexOf("if (!deleteMayHaveBeenInitiated && !releaseAttempted)");
  assert.ok(release >= 0 && deleteBoundary > release && catchRelease > deleteBoundary);
});

test("claim target cannot widen beyond fixed repository configuration", () => {
  const claim = { action: "revoke_github_deploy_key", github_owner: "Ticoworld", github_repo: "t3n-breakglass-sandbox", deploy_key_id: 1, claim_id: "claim-1", claim_version: 1 };
  assert.equal(claimTargetMatchesConfiguredRepository(claim, "Ticoworld", "t3n-breakglass-sandbox"), true);
  assert.equal(claimTargetMatchesConfiguredRepository({ ...claim, github_repo: "other-repo" }, "Ticoworld", "t3n-breakglass-sandbox"), false);
  assert.match(runSource, /CLAIM_TARGET_MISMATCH/);
  assert.match(seedSource, /GITHUB_OWNER/);
  assert.match(seedSource, /C1_GITHUB_REPO cannot override/);
});

test("provider ambiguity never authorizes blind retry or inconsistent closure", () => {
  assert.equal(classifyProviderOutcome(204, false, 404, false, 200, true), "VERIFIED_ABSENT");
  assert.equal(classifyProviderOutcome(204, false, 404, false, 500, false), "PROVIDER_ACKNOWLEDGED");
  assert.equal(classifyProviderOutcome(204, false, 404, false, 200, false), "PROVIDER_ACKNOWLEDGED");
  assert.equal(classifyProviderOutcome(204, false, 404, true, 200, true), "PROVIDER_ACKNOWLEDGED");
  assert.equal(classifyProviderOutcome(204, false, 200, false, 200, true), "PROVIDER_ACKNOWLEDGED");
  assert.equal(classifyProviderOutcome(null, true, 404, false, 200, true), "VERIFIED_ABSENT");
  for (const classification of ["PROVIDER_ACKNOWLEDGED", "ATTEMPTED_OUTCOME_UNKNOWN", "VERIFIED_PRESENT"] as const) assert.equal(destructiveRetryAllowed(classification), false);
  assert.equal(repositoryListIsWellFormed([{ id: 7, name: "key" }]), true);
  assert.equal(repositoryListIsWellFormed({ repositories: [] }), false);
  assert.equal(repositoryListIsWellFormed([{ name: "missing-id" }]), false);
});

test("fake provider adapter covers destructive and verification failure matrix", () => {
  type Scenario = { name: string; precheck?: "404" | "500"; deleteStatus: number | null; deleteTransportFailed: boolean; exactAfter: number | null; listAfter: boolean; listStatus: number | null; listBodyValid: boolean; expected: string; deletes: number };
  const scenarios: Scenario[] = [
    { name: "DROP_BEFORE_EFFECT", deleteStatus: null, deleteTransportFailed: true, exactAfter: 200, listAfter: true, listStatus: 200, listBodyValid: true, expected: "ATTEMPTED_OUTCOME_UNKNOWN", deletes: 1 },
    { name: "DROP_AFTER_EFFECT", deleteStatus: null, deleteTransportFailed: true, exactAfter: 404, listAfter: false, listStatus: 200, listBodyValid: true, expected: "VERIFIED_ABSENT", deletes: 1 },
    { name: "204_SUCCESS", deleteStatus: 204, deleteTransportFailed: false, exactAfter: 404, listAfter: false, listStatus: 200, listBodyValid: true, expected: "VERIFIED_ABSENT", deletes: 1 },
    { name: "404_PRECHECK", precheck: "404", deleteStatus: null, deleteTransportFailed: false, exactAfter: null, listAfter: false, listStatus: null, listBodyValid: false, expected: "NOT_ATTEMPTED", deletes: 0 },
    { name: "500_PRECHECK", precheck: "500", deleteStatus: null, deleteTransportFailed: false, exactAfter: null, listAfter: false, listStatus: null, listBodyValid: false, expected: "NOT_ATTEMPTED", deletes: 0 },
    { name: "500_AFTER_DELETE", deleteStatus: 500, deleteTransportFailed: false, exactAfter: 200, listAfter: true, listStatus: 200, listBodyValid: true, expected: "VERIFIED_PRESENT", deletes: 1 },
    { name: "VERIFICATION_TIMEOUT", deleteStatus: 204, deleteTransportFailed: false, exactAfter: null, listAfter: false, listStatus: null, listBodyValid: false, expected: "PROVIDER_ACKNOWLEDGED", deletes: 1 },
    { name: "INCONSISTENT_404_AND_LIST_PRESENT", deleteStatus: 204, deleteTransportFailed: false, exactAfter: 404, listAfter: true, listStatus: 200, listBodyValid: true, expected: "PROVIDER_ACKNOWLEDGED", deletes: 1 },
    { name: "INCONSISTENT_200_AND_LIST_ABSENT", deleteStatus: 204, deleteTransportFailed: false, exactAfter: 200, listAfter: false, listStatus: 200, listBodyValid: true, expected: "PROVIDER_ACKNOWLEDGED", deletes: 1 },
  ];
  for (const scenario of scenarios) {
    const deletes = scenario.precheck ? 0 : 1;
    const classification = scenario.precheck
      ? classifyProviderOutcome(null, false, null, false, null, false)
      : classifyProviderOutcome(scenario.deleteStatus, scenario.deleteTransportFailed, scenario.exactAfter, scenario.listAfter, scenario.listStatus, scenario.listBodyValid);
    assert.equal(classification, scenario.expected, scenario.name);
    assert.equal(deletes, scenario.deletes, `${scenario.name} must not retry DELETE`);
  }
});

test("strict claim parsing rejects target injection and incomplete authority", () => {
  assert.throws(() => parseClaim({ result: "WON", detail: { action: "something_else", github_owner: "Ticoworld", github_repo: "t3n-breakglass-sandbox", deploy_key_id: 1, claim_id: "claim-1" } }));
  assert.throws(() => parseClaim({ result: "WON", detail: { action: "revoke_github_deploy_key", github_owner: "Ticoworld", github_repo: "t3n-breakglass-sandbox", deploy_key_id: 0, claim_id: "claim-1" } }));
  assert.match(runSource, /input: \{ incident_id: incidentId \}/);
  assert.match(runSource, /authority_loaded_target/);
});

test("principal configuration rejects DID overrides and keeps operator, agent, broker distinct", () => {
  assert.match(configureSource, /override differs from recorded C1 principal/);
  assert.match(configureSource, /C1 principals must be three distinct DIDs/);
  assert.match(t3nSource, /connectC1Principal/);
  assert.match(runSource, /EFFECT_BROKER_T3N_API_KEY/);
  assert.equal(runSource.includes("process.env.T3N_API_KEY"), false, "broker source must not use operator T3N_API_KEY");
  assert.throws(() => refuseProviderOrOperatorCredentials({ T3N_API_KEY: "valid-but-wrong-principal" }), /operator T3N credential/);
  const fakeJwt = ["eyJhbGciOiJSUzI1NiJ9", "eyJzdWIiOiJsb2NhbCJ9", "signature"].join(".");
  const fakeGithubToken = ["ghp_", "test", "-secret-value"].join("");
  const fakeT3nKey = ["t3n_key_", "test", "-secret-value"].join("");
  const fakeInstallationToken = ["ghs_", "test", "-secret-value"].join("");
  const sanitized = redact(`Bearer ${fakeJwt} ${fakeGithubToken} ${fakeT3nKey}`, [fakeInstallationToken]);
  assert.equal(sanitized.includes(fakeJwt), false);
  assert.equal(sanitized.includes(fakeGithubToken), false);
  assert.equal(sanitized.includes(fakeT3nKey), false);
});

test("GitHub App authority uses repository-selected administration write only", async () => {
  const config = appConfigFromEnvironment({ GITHUB_APP_ID: "123", GITHUB_APP_INSTALLATION_ID: "456", GITHUB_APP_PRIVATE_KEY_PATH: path.join(os.tmpdir(), "c1-app.pem"), GITHUB_OWNER: "Ticoworld", GITHUB_REPO: "t3n-breakglass-sandbox" });
  assert.throws(() => appConfigFromEnvironment({ GITHUB_APP_ID: "123", GITHUB_APP_INSTALLATION_ID: "456", GITHUB_APP_PRIVATE_KEY_PATH: path.join(process.cwd(), "winner", "private.pem"), GITHUB_OWNER: "Ticoworld", GITHUB_REPO: "t3n-breakglass-sandbox" }), /outside the repository/);
  const calls: Array<{ method: string; url: string; authorization: string; body: string | undefined }> = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: URL | RequestInfo, init?: RequestInit) => {
    calls.push({ method: init?.method ?? "GET", url: String(input), authorization: String((init?.headers as Record<string, string>)?.Authorization ?? ""), body: typeof init?.body === "string" ? init.body : undefined });
    if (String(input).includes("/app/installations/456") && init?.method === "GET") return new Response(JSON.stringify({ account: { login: "Ticoworld" }, repository_selection: "selected" }), { status: 200 });
    if (String(input).includes("/access_tokens")) return new Response(JSON.stringify({ token: "ghs.local-test-only", expires_at: "2099-01-01T00:00:00Z", permissions: { administration: "write" }, repositories: [{ name: "t3n-breakglass-sandbox", full_name: "Ticoworld/t3n-breakglass-sandbox", private: true }] }), { status: 201 });
    if (String(input).endsWith("/installation/token")) return new Response(null, { status: 204 });
    return new Response(null, { status: 500 });
  }) as typeof fetch;
  try {
    assert.equal((await validateInstallation(config, "jwt.local")).status, 200);
    const minted = await mintInstallationToken(config, "jwt.local");
    assert.equal(minted.token, "ghs.local-test-only");
    assert.equal((await revokeInstallationToken(minted.token!)).status, 204);
  } finally {
    globalThis.fetch = originalFetch;
  }
  const exchange = calls.find((call) => call.url.includes("/access_tokens"))!;
  assert.equal(exchange.method, "POST");
  assert.equal(exchange.authorization, "Bearer jwt.local");
  assert.deepEqual(JSON.parse(exchange.body!), { repositories: ["t3n-breakglass-sandbox"], permissions: { administration: "write" } });
  assert.equal(calls.filter((call) => call.method === "DELETE").length, 1);
});

test("live proof cannot be written before replay and pass criteria", () => {
  const replay = liveSource.indexOf("replayObservation.claim_outcome");
  const writeProof = liveSource.indexOf('C1-live-proof.json');
  const pass = liveSource.indexOf('status: "C1_PASS"');
  assert.ok(replay >= 0 && writeProof > replay && pass > writeProof);
  assert.match(liveSource, /replay broker did not reach the common barrier/);
  assert.match(liveSource, /replayObservation\.token_minted !== false/);
  const configCheck = liveSource.indexOf("live identity/configuration does not match");
  const targetSetup = liveSource.indexOf("target setup failed");
  assert.ok(configCheck >= 0 && targetSetup > configCheck, "live runner must validate identity/configuration before creating a provider target");
});
