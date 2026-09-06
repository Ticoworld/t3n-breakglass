import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { verifyE2EBundle } from "../c2/e2e-verifier.js";

const liveRunner = await readFile(new URL("../scripts/c2-e2e-r1-live.ts", import.meta.url), "utf8");

const targetId = 271828182;
const policyId = "c2-policy:github-push-c2-e2e-r1-synthetic";
const incidentId = "C2-c2-policy:github-push-c2-b1-e2e-r1-synthetic-0123456789abcdef01234567";
const triggerSha = "abcdefabcdefabcdefabcdefabcdefabcdefabcd";
const fingerprint = "SHA256:syntheticFingerprint";
const privateDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

function validBundle(): Record<string, unknown> {
  const authority = {
    policy_id: policyId,
    repository_id: 1350596128,
    repository_full_name: "Ticoworld/t3n-breakglass-sandbox",
    ref: "refs/heads/c2-breakglass-demo",
    secret_path: ".breakglass-c2/exposed-deploy-key",
    deploy_key_id: targetId,
      expected_deploy_key_title: "breakglass-c2-b1-e2e-r1-synthetic",
    expected_read_only: true,
    expected_public_key_fingerprint: fingerprint,
    expected_private_material_sha256: privateDigest,
    ttl_secs: 900,
    enabled: true,
    provenance: { classification: "LIVE_PROVENANCE" },
  };
  const request = {
    incident_id: incidentId,
    remediation_agent_did: "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019",
    effect_broker_did: "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57",
    deploy_key_id: targetId,
    ttl_secs: 900,
  };
  const winner = {
    contender: "broker-a",
    ownership_confirmation: "CONFIRMED",
    provider_credential_mint_count: 1,
    token_minted: true,
    destructive_call_count: 1,
    delete_attempted: true,
    effect_start: { result: "WON", function: "begin-effect", state: "EFFECT_STARTED", effect_attempts: 1 },
    effect_start_confirmation: { result: "CONFIRMED", function: "confirm-effect-start" },
    effect_start_confirmed: true,
    effect_start_id: "effect-start-1",
    authority_loaded_target: { claim_id: "claim-1" },
    effect_token: { issued: true, minted_after_confirmed_effect_start: true },
    before: { target_present: true, exact_get_http_status: 200, read_after_confirmed_effect_start: true },
    delete: { attempt_number: 1, method: "DELETE", http_status: 204, target_id: targetId },
    after: { target_absent: true },
    effect_token_cleanup: { ok: true, revoke: { http_status: 204 }, probe: { refused: true } },
    verifier_token: { issued: true, distinct_from_effect_token: true, mutation_count: 0 },
    independent_provider_verification: { target_absent: true, exact_get_http_status: 404, mutation_count: 0 },
    verifier_token_cleanup: { ok: true, revoke: { http_status: 204 }, probe: { refused: true } },
    finalize: { result: "WON" },
  };
  const loser = {
    contender: "broker-b",
    ownership_confirmation: "NOT_OWNER",
    token_minted: false,
    provider_credential_mint_count: 0,
    destructive_call_count: 0,
    delete_attempted: false,
    provider_calls_after_ownership_loss: 0,
  };
  return {
    classification: "C2_E2E_R1_FULL_CAUSAL_REMEDIATION_PASS",
    starting_sha: "f66605e924dd1fff81f1cfa522275aa3ab097bad",
    main_sha: "4a077035474337b7a1ad16204820e68ed3020477",
    sandbox_before_sha: "0ef99189955ff8bbdd18b1918937076883581528",
    private_material_sha256: privateDigest,
    fresh_target: {
      id: targetId,
      title: "breakglass-c2-b1-e2e-r1-synthetic",
      repository: "Ticoworld/t3n-breakglass-sandbox",
      read_only: true,
      provider_readback_exact: true,
      private_public_relation_proven: true,
      generated_public_key_fingerprint: fingerprint,
      provider_public_key_fingerprint: fingerprint,
      setup_token: { create_http_status: 201, exact_get_http_status: 200, list_contains_target: true, revoke_http_status: 204, refusal_http_status: 401 },
    },
    policy: { registry_identity: policyId, policy_version: 2, authority_fields: authority, remote_readback: { success: true }, content_sha256: "a".repeat(64) },
    historical_policy_retirement: { historical_policy_id: "c2-policy:github-push-c2-b1-1788654034105-84ba7889df89", retired: true, cleanup_proven: true },
    policy_before_event: { remote_policy_readback_before_trigger: true, marker_persisted_before_trigger: true, trigger_issued_after_marker: true },
    secret_trigger_commit: { parent_sha: "0ef99189955ff8bbdd18b1918937076883581528", sha: triggerSha, only_changed_path: ".breakglass-c2/exposed-deploy-key", fast_forward: true },
    real_delivery: { event_type: "push", repository_id: 1350596128, repository_full_name: "Ticoworld/t3n-breakglass-sandbox", ref: "refs/heads/c2-breakglass-demo", before: "0ef99189955ff8bbdd18b1918937076883581528", after: triggerSha, created: false, forced: false, deleted: false, signature_verified: true, hmac_verified: true, delivery_id: "12345678-1234-1234-1234-123456789012", dedupe_status: "NEW" },
    immutable_before: { status: 404, commit_sha: "0ef99189955ff8bbdd18b1918937076883581528", path: ".breakglass-c2/exposed-deploy-key" },
    immutable_after: { status: 200, commit_sha: triggerSha, path: ".breakglass-c2/exposed-deploy-key", content_sha256: privateDigest },
    transition_classification: "CAUSAL_SECRET_INTRODUCED",
    b1_verifier: { valid: true, reasons: [], context: { expectedStartingSha: "f66605e924dd1fff81f1cfa522275aa3ab097bad", expectedMainSha: "4a077035474337b7a1ad16204820e68ed3020477", expectedBeforeSha: "0ef99189955ff8bbdd18b1918937076883581528" } },
    derived_c1_request: request,
    t3n: {
      create: { result: "WON", function: "create-incident", state: "ACTIVE", detail: { deploy_key_id: targetId, remediation_agent_did: request.remediation_agent_did, effect_broker_did: request.effect_broker_did, action: "revoke_github_deploy_key" } },
      active_readback: { state: "ACTIVE", detail: { deploy_key_id: targetId, effect_attempts: 0 } },
      reservation: { result: "WON", function: "reserve-incident", state: "RESERVED" },
      reserved_readback: { state: "RESERVED", detail: { effect_attempts: 0 } },
      brokers: { broker_a: winner, broker_b: loser, winner: "broker-a", loser: "broker-b", confirmed_owner_count: 1 },
      closed_readback: { state: "CLOSED", detail: { effect_attempts: 1, final_result_classification: "VERIFIED_ABSENT", effect_claim_id: "claim-1", effect_start_id: "effect-start-1" } },
    },
    c2_replay: { classification: "DUPLICATE_SAME", incident_id: incidentId, create_request: request, new_immutable_source_reads: 0, new_t3n_incident_creations: 0, provider_authority_count: 0, provider_mutations: 0 },
    c1_replay: { closed_replay_rejected: true, new_effect_token_mints: 0, new_delete_count: 0, effect_attempts: 1, target_absent: true },
    successful_policy_retirement: { policy_id: policyId, deploy_key_id: targetId, retired: true, terminal_classification: "VERIFIED_ABSENT" },
    mutation_counters: { fixture_setup: { ssh_key_generations: 1, deploy_key_creates: 1 }, causal_source: { secret_trigger_pushes: 1 }, t3n_protocol: { incident_creates: 1, reservations: 1, effect_attempts: 1 }, provider_effect: { deploy_key_deletes: 1 }, independent_verification: { provider_mutations: 0 }, replay: { provider_token_mints: 0, provider_mutations: 0, deploy_key_deletes: 0 } },
    sensitive_value_hygiene: { private_material_in_evidence: false, private_material_in_policy: false, raw_webhook_body_in_evidence: false, app_private_key_in_evidence: false, installation_token_in_evidence: false, webhook_secret_in_evidence: false },
  };
}

test("complete sanitized E2E bundle passes with zero network calls", () => {
  const result = verifyE2EBundle(JSON.parse(JSON.stringify(validBundle())));
  assert.equal(result.ok, true, result.errors.join(", "));
  assert.equal(result.network_calls, 0);
});

test("live B1 adapter emits the canonical source-reader read status", () => {
  assert.match(liveRunner, /b1SourceReader\.read_http_status = afterRead\.status/);
});

test("E2E verifier rejects causal and hygiene substitutions", () => {
  const cases: Array<[string, (bundle: Record<string, any>) => void]> = [
    ["wrong target", (b) => { b.policy.authority_fields.deploy_key_id += 1; }],
    ["wrong fingerprint", (b) => { b.policy.authority_fields.expected_public_key_fingerprint = "SHA256:other"; }],
    ["wrong digest", (b) => { b.immutable_after.content_sha256 = "f".repeat(64); }],
    ["policy after event", (b) => { b.policy_before_event.remote_policy_readback_before_trigger = false; }],
    ["wrong before", (b) => { b.real_delivery.before = "1".repeat(40); }],
    ["wrong after", (b) => { b.real_delivery.after = "2".repeat(40); }],
    ["created push", (b) => { b.real_delivery.created = true; }],
    ["forced push", (b) => { b.real_delivery.forced = true; }],
    ["secret already present before", (b) => { b.immutable_before.status = 200; }],
    ["after digest mismatch", (b) => { b.immutable_after.content_sha256 = "e".repeat(64); }],
    ["raw private key", (b) => { b.untrusted = "-----BEGIN OPENSSH PRIVATE KEY-----"; }],
    ["C1 target substitution", (b) => { b.derived_c1_request.deploy_key_id += 1; }],
  ];
  for (const [name, mutate] of cases) {
    const bundle = JSON.parse(JSON.stringify(validBundle())) as Record<string, any>;
    mutate(bundle);
    assert.equal(verifyE2EBundle(bundle).ok, false, `${name} was accepted`);
  }
});
