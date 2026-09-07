import assert from "node:assert/strict";
import test from "node:test";
import { verifyE2EBundle, type E2EVerificationContext } from "../c2/e2e-verifier.js";
import { buildB1Evidence, serializeB1Evidence } from "../c2/b1-evidence.js";
import { buildB1SourceReaderEvidence } from "../c2/b1-source-reader.js";
import { verifyB1Evidence } from "../c2/b1-verifier.js";
import { R3_B1_SCHEMA } from "../c2/b1-verifier.js";
import { R3_E2E_SCHEMA } from "../c2/e2e-schema.js";

const DEFAULT_CONTEXT: E2EVerificationContext = {
  expectedStartingSha: "f66605e924dd1fff81f1cfa522275aa3ab097bad",
  expectedMainSha: "4a077035474337b7a1ad16204820e68ed3020477",
  expectedBeforeSha: "0ef99189955ff8bbdd18b1918937076883581528",
};

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
    claim_outcome: "CLAIM_WON",
    ownership_confirmation: "CONFIRMED",
    provider_credential_mint_count: 1,
    token_minted: true,
    destructive_call_count: 1,
    delete_attempted: true,
    effect_start: { result: "WON", function: "begin-effect", state: "EFFECT_STARTED", effect_attempts: 1 },
    effect_start_confirmation: { result: "CONFIRMED", function: "confirm-effect-start" },
    effect_start_confirmed: true,
    effect_start_id: "effect-start-1",
    authority_loaded_target: { claim_id: "claim-1", claim_version: 1 },
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
    claim: { result: "LOST" },
    claim_outcome: "CLAIM_LOST",
    claim_proposal: { claim_id: "claim-b", claim_version: 1 },
    claim_confirmation: { result: "LOST", detail: {} },
    ownership_confirmation: "NOT_OWNER",
    token_minted: false,
    provider_credential_mint_count: 0,
    destructive_call_count: 0,
    delete_attempted: false,
    provider_calls_after_ownership_loss: 0,
  };
  return {
    classification: "C2_E2E_R1_FULL_CAUSAL_REMEDIATION_PASS",
    starting_sha: DEFAULT_CONTEXT.expectedStartingSha,
    main_sha: DEFAULT_CONTEXT.expectedMainSha,
    sandbox_before_sha: DEFAULT_CONTEXT.expectedBeforeSha,
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
    secret_trigger_commit: { parent_sha: DEFAULT_CONTEXT.expectedBeforeSha, sha: triggerSha, only_changed_path: ".breakglass-c2/exposed-deploy-key", fast_forward: true },
    real_delivery: { event_type: "push", repository_id: 1350596128, repository_full_name: "Ticoworld/t3n-breakglass-sandbox", ref: "refs/heads/c2-breakglass-demo", before: DEFAULT_CONTEXT.expectedBeforeSha, after: triggerSha, created: false, forced: false, deleted: false, signature_verified: true, hmac_verified: true, delivery_id: "12345678-1234-1234-1234-123456789012", raw_body_sha256: "2".repeat(64), dedupe_status: "NEW" },
    immutable_before: { status: 404, commit_sha: DEFAULT_CONTEXT.expectedBeforeSha, path: ".breakglass-c2/exposed-deploy-key" },
    immutable_after: { status: 200, commit_sha: triggerSha, path: ".breakglass-c2/exposed-deploy-key", content_sha256: privateDigest },
    transition_classification: "CAUSAL_SECRET_INTRODUCED",
    b1_verifier: { valid: true, reasons: [], context: DEFAULT_CONTEXT },
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

function syntheticB1Evidence(bundle: Record<string, any>, context: E2EVerificationContext): Record<string, unknown> {
  const target = bundle.fresh_target;
  const policy = bundle.policy;
  const authority = policy.authority_fields;
  const delivery = bundle.real_delivery;
  const trigger = bundle.secret_trigger_commit;
  const digest = bundle.private_material_sha256;
  return buildB1Evidence({
    starting_sha: context.expectedStartingSha,
    main_sha: context.expectedMainSha,
    b0_before_sha: context.expectedBeforeSha,
    policy_freeze_commit_sha: "1".repeat(40),
    private_material_sha256: digest,
    fresh_deploy_key: target,
    policy: { registry_identity: policy.registry_identity, policy_version: policy.policy_version, authority_fields: authority, remote_readback: { success: true } },
    policy_before_event: { remote_policy_readback_before_trigger: true, marker_persisted_before_trigger: true },
    secret_trigger_commit: { sha: trigger.sha, parent_sha: context.expectedBeforeSha, only_changed_path: ".breakglass-c2/exposed-deploy-key", fast_forward: true },
    real_delivery: { ...delivery, raw_body_sha256: delivery.raw_body_sha256 ?? "2".repeat(64) },
    source_reader_token: buildB1SourceReaderEvidence({
      requested_permissions: { contents: "read" },
      actual_permissions: { contents: "read" },
      administration_write_granted: false,
      immutable_before_http_status: 404,
      immutable_after_http_status: 200,
      revoke_http_status: 204,
      refusal_http_status: 401,
    }),
    immutable_before: { status: 404, commit_sha: context.expectedBeforeSha, path: ".breakglass-c2/exposed-deploy-key" },
    immutable_after: { status: 200, commit_sha: trigger.sha, path: ".breakglass-c2/exposed-deploy-key", content_sha256: digest },
    transition_classification: "CAUSAL_SECRET_INTRODUCED",
    derived_c1_request: bundle.derived_c1_request,
    mutation_counters: { t3n_create_calls: 0, provider_effects: 0 },
    sensitive_value_hygiene: { private_material_in_evidence: false, raw_webhook_body_in_evidence: false },
  });
}

function r3Bundle(): Record<string, any> {
  const bundle = JSON.parse(JSON.stringify(validBundle())) as Record<string, any>;
  const r3PolicyId = "c2-policy:github-push-c2-e2e-r3-synthetic";
  const r3Title = "breakglass-c2-e2e-r3-synthetic";
  bundle.classification = R3_E2E_SCHEMA.classification;
  bundle.fresh_target.title = r3Title;
  bundle.policy.registry_identity = r3PolicyId;
  bundle.policy.authority_fields.policy_id = r3PolicyId;
  bundle.policy.authority_fields.expected_deploy_key_title = r3Title;
  bundle.historical_policy_retirements = [
    { historical_policy_id: "c2-policy:github-push-c2-b1-1788654034105-84ba7889df89", retired: true, cleanup_proven: true },
    { historical_policy_id: "c2-policy:github-push-c2-e2e-r1-1788700798113-e96754eec44a", retired: true, cleanup_proven: true },
    { historical_policy_id: "c2-policy:github-push-c2-e2e-r2-1788774247501-aac76008bd86", retired: true, terminal_classification: "VERIFIED_ABSENT" },
  ];
  bundle.c2_replay = {
    classification: "C2_PUSH_SELECTED", dedupe_status: "DUPLICATE_SAME", replayed: true,
    receipt_replay: true, authority_rederived: false, source_reads: 0, source_observation_accesses: 0,
    active_policy_candidates: 0, incident_id: incidentId, create_request: bundle.derived_c1_request,
    receipt_sha256_before: "c".repeat(64), receipt_sha256_after: "c".repeat(64),
    new_immutable_source_reads: 0, new_t3n_incident_creations: 0, provider_authority_count: 0, provider_mutations: 0,
  };
  bundle.c1_replay = {
    closed_replay_rejected: true, new_effect_token_mints: 0, new_delete_count: 0, provider_calls: 0,
    terminal_unchanged: true, closed_replay_adjudication: { state: "SAFE_CLOSED_REPLAY_DENIED" }, effect_attempts: 1, target_absent: true,
  };
  bundle.successful_policy_retirement = { policy_id: r3PolicyId, deploy_key_id: targetId, retired: true, terminal_classification: "VERIFIED_ABSENT" };
  return bundle;
}

test("complete sanitized E2E bundle passes with zero network calls", () => {
  const result = verifyE2EBundle(JSON.parse(JSON.stringify(validBundle())), DEFAULT_CONTEXT);
  assert.equal(result.ok, true, result.errors.join(", "));
  assert.equal(result.network_calls, 0);
});

test("full E2E verification fails closed without explicit context", () => {
  const result = verifyE2EBundle(JSON.parse(JSON.stringify(validBundle())));
  assert.equal(result.ok, false);
  assert.deepEqual(result.errors, ["explicit E2E verification context is required"]);
});

test("arbitrary future checkpoint passes only when all explicit context values match", () => {
  const future: E2EVerificationContext = { expectedStartingSha: "a".repeat(40), expectedMainSha: "b".repeat(40), expectedBeforeSha: "c".repeat(40) };
  const bundle = JSON.parse(JSON.stringify(validBundle())) as Record<string, any>;
  bundle.starting_sha = future.expectedStartingSha;
  bundle.main_sha = future.expectedMainSha;
  bundle.sandbox_before_sha = future.expectedBeforeSha;
  bundle.secret_trigger_commit.parent_sha = future.expectedBeforeSha;
  bundle.real_delivery.before = future.expectedBeforeSha;
  bundle.immutable_before.commit_sha = future.expectedBeforeSha;
  bundle.b1_verifier.context = future;
  assert.equal(verifyE2EBundle(bundle, future).ok, true);
  assert.equal(verifyE2EBundle(bundle, { ...future, expectedStartingSha: "d".repeat(40) }).ok, false);
  assert.equal(verifyE2EBundle(bundle, { ...future, expectedBeforeSha: "e".repeat(40) }).ok, false);
  assert.equal(verifyE2EBundle(bundle, { ...future, expectedMainSha: "1".repeat(40) }).ok, false);
});

test("the synthetic runner-to-B1-to-E2E adapter pipeline round-trips without network calls", () => {
  const bundle = JSON.parse(JSON.stringify(validBundle())) as Record<string, any>;
  const b1 = syntheticB1Evidence(bundle, DEFAULT_CONTEXT);
  const b1RoundTrip = JSON.parse(serializeB1Evidence(b1).toString("utf8")) as Record<string, unknown>;
  const b1Result = verifyB1Evidence(b1RoundTrip, DEFAULT_CONTEXT);
  assert.deepEqual(b1Result, { valid: true, reasons: [] });
  bundle.b1_evidence = b1RoundTrip;
  bundle.b1_verifier = { valid: b1Result.valid, reasons: b1Result.reasons, context: DEFAULT_CONTEXT };
  const e2eResult = verifyE2EBundle(bundle, DEFAULT_CONTEXT);
  assert.equal(e2eResult.ok, true, e2eResult.errors.join(", "));
  assert.equal(e2eResult.network_calls, 0);
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
    assert.equal(verifyE2EBundle(bundle, DEFAULT_CONTEXT).ok, false, `${name} was accepted`);
  }
});

test("R3 schema uses the shared target/policy namespace and live B1 adapter", () => {
  const bundle = r3Bundle();
  const b1 = syntheticB1Evidence(bundle, DEFAULT_CONTEXT);
  const b1RoundTrip = JSON.parse(serializeB1Evidence(b1).toString("utf8")) as Record<string, unknown>;
  const b1Result = verifyB1Evidence(b1RoundTrip, DEFAULT_CONTEXT, R3_B1_SCHEMA);
  assert.deepEqual(b1Result, { valid: true, reasons: [] });
  bundle.b1_verifier = { valid: true, reasons: [], context: DEFAULT_CONTEXT };
  bundle.b1_evidence = b1RoundTrip;
  const result = verifyE2EBundle(JSON.parse(JSON.stringify(bundle)), DEFAULT_CONTEXT);
  assert.equal(result.ok, true, result.errors.join(", "));
});

test("R3 full verifier is dynamic across arbitrary future checkpoints", () => {
  const contextA: E2EVerificationContext = { expectedStartingSha: "1".repeat(40), expectedMainSha: "2".repeat(40), expectedBeforeSha: "3".repeat(40) };
  const bundle = r3Bundle();
  bundle.starting_sha = contextA.expectedStartingSha;
  bundle.main_sha = contextA.expectedMainSha;
  bundle.sandbox_before_sha = contextA.expectedBeforeSha;
  bundle.secret_trigger_commit.parent_sha = contextA.expectedBeforeSha;
  bundle.real_delivery.before = contextA.expectedBeforeSha;
  bundle.immutable_before.commit_sha = contextA.expectedBeforeSha;
  bundle.b1_verifier.context = contextA;
  bundle.b1_evidence = syntheticB1Evidence(bundle, contextA);
  assert.equal(verifyE2EBundle(bundle, contextA).ok, true);
  assert.equal(verifyE2EBundle(bundle, { ...contextA, expectedStartingSha: "4".repeat(40) }).ok, false);
  assert.equal(verifyE2EBundle(bundle, { ...contextA, expectedBeforeSha: "5".repeat(40) }).ok, false);
  assert.equal(verifyE2EBundle(bundle).ok, false);
});
