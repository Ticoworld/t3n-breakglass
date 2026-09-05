import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { classifyProviderOutcome } from "../broker/logic.js";
import { appConfigFromEnvironment, mintReadOnlyInstallationToken } from "../broker/github-app.js";
import { verifyBundle } from "../scripts/c1-r6b-r4e-r1-evidence-verify.js";

const root = new URL("../", import.meta.url);
const read = (file: string) => readFile(new URL(file, root), "utf8");
const [broker, live, prepare] = await Promise.all([read("broker/run.ts"), read("scripts/c1-live.ts"), read("broker/prepare-target.ts")]);

const target = { id: 162351194, title: "breakglass-r4e-disposable-20260904", read_only: true, repository: "Ticoworld/t3n-breakglass-sandbox" };
const claimId = "claim-1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const startId = "start-1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const protocolOrder = ["provider_before", "begin-effect", "confirm-effect-start", "pre-delete-authority", "DELETE", "provider_after", "effect_token_revoke", "verifier_issue", "verifier_after", "verifier_revoke", "finalize-effect"];

function validBundle(): Record<string, any> {
  const terminal = { function: "get-incident", result: "FOUND", state: "CLOSED", detail: { incident_id: "R4E-R1-INCIDENT", effect_claim_id: claimId, effect_claim_version: 1, effect_start_id: startId, effect_attempts: 1, final_result_classification: "VERIFIED_ABSENT" } };
  const winner = {
    contender: "broker-a", process_id: 1001, contender_nonce: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ownership_confirmation: "CONFIRMED", token_minted: true, provider_credential_mint_count: 1, destructive_call_count: 1, delete_attempted: true,
    authority_loaded_target: { action: "revoke_github_deploy_key", github_owner: "Ticoworld", github_repo: "t3n-breakglass-sandbox", deploy_key_id: target.id, claim_id: claimId, claim_version: 1 },
    effect_start: { function: "begin-effect", result: "WON", state: "EFFECT_STARTED", effect_attempts: 1 }, effect_start_confirmed: true, effect_start_id: startId,
    before: { exact_get_http_status: 200, list_http_status: 200, target_id: target.id, read_only: true, target_present: true },
    delete: { attempt_number: 1, target_id: target.id, http_status: 204 },
    after: { exact_get_http_status: 404, list_http_status: 200, list_body_valid: true, list_contains_target: false, target_absent: true },
    effect_token: { issued: true, purpose: "effect", requested_permissions: { administration: "write" } },
    effect_token_cleanup: { ok: true, revoke: { success: true, http_status: 204 }, probe: { refused: true } },
    verifier_token: { issued: true, purpose: "verifier", distinct_from_effect_token: true, distinct_from_target_preflight_token: true, mutation_count: 0 },
    independent_provider_verification: { exact_get_http_status: 404, list_get_http_status: 200, target_absent: true, mutation_count: 0 },
    verifier_token_cleanup: { ok: true, revoke: { success: true, http_status: 204 }, probe: { refused: true } },
    finalize: { function: "finalize-effect", result: "WON" }, finalize_request: { incident_id: "R4E-R1-INCIDENT", claim_id: claimId, effect_start_id: startId, classification: "VERIFIED_ABSENT" },
  };
  const loser = { contender: "broker-b", process_id: 1002, contender_nonce: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", ownership_confirmation: "NOT_OWNER", token_minted: false, provider_credential_mint_count: 0, destructive_call_count: 0, delete_attempted: false, provider_calls_after_ownership_loss: 0 };
  return {
    status: "C1_R6B_R4E_R1_PROVIDER_BACKED_PASS", incident_id: "R4E-R1-INCIDENT", incident_count: 1,
    contract: { name: "z:adb9365ee986cc6d0cb4006580782fe6fc7a431f:breakglass-winner-c1", version: "2.0.4", numeric_id: 878, wasm_bytes: 227011, wasm_sha256: "ca7032b112b837b06e4334c10bca8820447f6ea1756b74db9bccd3181ad4d5d0" },
    target,
    target_preflight: { target_preflight: { target_present: true, exact_get: { http_status: 200 }, list_get: { http_status: 200 }, list_contains_target: true }, token_cleanup: { revoked: true, revoke_http_status: 204, same_token_refused: true } },
    incident: { create: { function: "create-incident", result: "WON", detail: { action: "revoke_github_deploy_key", github_owner: "Ticoworld", github_repo: "t3n-breakglass-sandbox", deploy_key_id: target.id } } },
    brokers: { broker_a: winner, broker_b: loser, winner: "broker-a", loser: "broker-b", confirmed_owner_count: 1 },
    pre_delete_authority: { operator_readback: { state: "EFFECT_STARTED", detail: { effect_attempts: 1, effect_claim_id: claimId, effect_start_id: startId } }, delete_allowed_after_this_read: true },
    protocol_order: protocolOrder,
    provider_counters: { preflight_token_mints: 1, effect_token_mints: 1, verifier_token_mints: 1, deploy_key_posts: 0, deploy_key_deletes: 1, provider_mutations: 1 },
    terminal, independent_terminal_reread: terminal,
    replay: { remediation_reserve: { result: "LOST" }, broker: { token_minted: false, provider_credential_mint_count: 0, destructive_call_count: 0, delete_attempted: false, provider_calls_after_ownership_loss: 0 }, final_readback: terminal },
  };
}

test("transport ambiguity takes precedence over same-session absence reads", () => {
  assert.equal(classifyProviderOutcome(null, true, 404, false, 200, true), "ATTEMPTED_OUTCOME_UNKNOWN");
  assert.equal(classifyProviderOutcome(204, false, 404, false, 200, true), "VERIFIED_ABSENT");
});

test("existing-target setup is bounded, repository-fixed, and never writes historical target evidence", () => {
  assert.match(prepare, /C1_TARGET_MODE/);
  assert.match(prepare, /C1_EXISTING_TARGET_ID/);
  assert.match(prepare, /C1_EXISTING_TARGET_TITLE/);
  assert.match(prepare, /mintReadOnlyInstallationToken/);
  assert.match(prepare, /deploy_key_create_count: 0/);
  assert.match(prepare, /C1_TARGET_EVIDENCE_FILE/);
  assert.doesNotMatch(prepare, /target-setup\.json/);
  assert.match(prepare, /existing target ID must be a positive safe integer/);
  assert.match(prepare, /existing target title does not match/);
});

test("read-only verifier token requests read administration permission", async () => {
  const config = appConfigFromEnvironment({ GITHUB_APP_ID: "123", GITHUB_APP_INSTALLATION_ID: "456", GITHUB_APP_PRIVATE_KEY_PATH: "C:\\outside\\app.pem" });
  const calls: Array<{ method: string; body: string }> = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (_input: URL | RequestInfo, init?: RequestInit) => {
    calls.push({ method: init?.method ?? "GET", body: String(init?.body ?? "") });
    return new Response(JSON.stringify({ token: "ghs.read-only", expires_at: "2099-01-01T00:00:00Z", permissions: { administration: "read" }, repositories: [] }), { status: 201 });
  }) as typeof fetch;
  try { await mintReadOnlyInstallationToken(config, "jwt.local", "verifier"); }
  finally { globalThis.fetch = originalFetch; }
  assert.equal(calls.length, 1);
  assert.deepEqual(JSON.parse(calls[0].body), { repositories: ["t3n-breakglass-sandbox"], permissions: { administration: "read" } });
});

test("provider-path source enforces target loading and cleanup order", () => {
  assert.equal(broker.includes("process.env.T3N_API_KEY"), false);
  assert.match(broker, /parseClaimConfirmation/);
  assert.match(broker, /target = confirmation.target/);
  assert.match(broker, /mintEffectInstallationToken/);
  assert.match(broker, /deleteMayHaveBeenInitiated = true/);
  assert.match(broker, /retry_allowed: false/);
  assert.ok(broker.indexOf("parseClaimConfirmation") < broker.indexOf("mintEffectInstallationToken"));
  assert.ok(broker.indexOf("exactKey(effectToken") < broker.indexOf('"begin-effect"'));
  assert.ok(broker.indexOf('"confirm-effect-start"') < broker.indexOf("deleteKey(effectToken"));
  assert.ok(broker.indexOf("const effectCleanup = await revokeAndRefuse") < broker.indexOf("const absent = await independentVerifier"));
  assert.ok(broker.indexOf("mintReadOnlyInstallationToken") < broker.indexOf("finalize(broker"));
  assert.match(live, /C1_PRE_DELETE_RELEASE_FILE/);
  assert.match(live, /operator_authority_verified: true/);
});

const negativeCases: Array<[string, (bundle: Record<string, any>) => void]> = [
  ["target ID mismatch", (b) => { b.target.id = 7; }],
  ["target title mismatch", (b) => { b.target.title = "wrong"; }],
  ["preflight absent", (b) => { b.target_preflight.target_preflight.target_present = false; }],
  ["loser token mint", (b) => { b.brokers.broker_b.token_minted = true; }],
  ["loser provider call", (b) => { b.brokers.broker_b.provider_calls_after_ownership_loss = 1; }],
  ["DELETE before confirmed start", (b) => { b.protocol_order = ["provider_before", "DELETE", ...protocolOrder.slice(1)]; }],
  ["two DELETEs", (b) => { b.brokers.broker_a.destructive_call_count = 2; }],
  ["DELETE target mismatch", (b) => { b.brokers.broker_a.delete.target_id = 7; }],
  ["after target present", (b) => { b.brokers.broker_a.after.target_absent = false; }],
  ["effect token not revoked", (b) => { b.brokers.broker_a.effect_token_cleanup.ok = false; }],
  ["revoked effect token usable", (b) => { b.brokers.broker_a.effect_token_cleanup.probe.refused = false; }],
  ["missing verifier", (b) => { delete b.brokers.broker_a.verifier_token; }],
  ["verifier reuses effect token", (b) => { b.brokers.broker_a.verifier_token.distinct_from_effect_token = false; }],
  ["verifier mutation", (b) => { b.brokers.broker_a.verifier_token.mutation_count = 1; }],
  ["verifier sees present", (b) => { b.brokers.broker_a.independent_provider_verification.target_absent = false; }],
  ["verifier not revoked", (b) => { b.brokers.broker_a.verifier_token_cleanup.ok = false; }],
  ["finalize too early", (b) => { b.protocol_order = ["provider_before", "finalize-effect", ...protocolOrder.slice(1)]; }],
  ["final classification wrong", (b) => { b.brokers.broker_a.finalize_request.classification = "PROVIDER_ACKNOWLEDGED"; }],
  ["replay token mint", (b) => { b.replay.broker.token_minted = true; }],
  ["replay DELETE", (b) => { b.replay.broker.destructive_call_count = 1; }],
  ["final authority reopened", (b) => { b.replay.final_readback.state = "EFFECT_STARTED"; }],
  ["provider counter mismatch", (b) => { b.provider_counters.deploy_key_deletes = 2; }],
  ["wrong effect start finalize", (b) => { b.brokers.broker_a.finalize_request.effect_start_id = "start-1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"; }],
];

test("complete R4E-R1 bundle passes the zero-network offline verifier", () => {
  const result = verifyBundle(validBundle());
  assert.equal(result.network_calls, 0);
  assert.deepEqual(result.errors, []);
  assert.equal(result.ok, true);
});

for (const [name, mutate] of negativeCases) {
  test(`offline verifier rejects ${name}`, () => {
    const bundle = validBundle();
    mutate(bundle);
    assert.equal(verifyBundle(bundle).ok, false, name);
  });
}
