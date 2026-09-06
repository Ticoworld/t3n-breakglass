import assert from "node:assert/strict";
import { test } from "node:test";
import { verifyB1Evidence, B1_REPOSITORY, B1_REF, B1_SECRET_PATH, type B1VerificationContext } from "../c2/b1-verifier.js";
import { buildB1Evidence, serializeB1Evidence } from "../c2/b1-evidence.js";

const HISTORICAL_B1_STARTING_SHA = "84df42102b6b7ad7eddf36e786cf6438f2024d1a";
const HISTORICAL_B1_MAIN_SHA = "4a077035474337b7a1ad16204820e68ed3020477";
const HISTORICAL_B1_BEFORE_SHA = "983a95d2e1f6ef44530490bdc4377bb5f3b44514";
const HISTORICAL_CONTEXT: B1VerificationContext = { expectedStartingSha: HISTORICAL_B1_STARTING_SHA, expectedMainSha: HISTORICAL_B1_MAIN_SHA, expectedBeforeSha: HISTORICAL_B1_BEFORE_SHA };

function fixture(): any {
  const target = { id: 123456789, title: "breakglass-c2-b1-test", read_only: true, generated_public_key_fingerprint: "SHA256:test", provider_public_key_fingerprint: "SHA256:test", private_public_relation_proven: true };
  const digest = "a".repeat(64);
  return {
    classification: "C2_B1_REAL_CAUSAL_SECRET_INTRODUCTION_PASS",
    starting_sha: HISTORICAL_B1_STARTING_SHA,
    main_sha: HISTORICAL_B1_MAIN_SHA,
    b0_before_sha: HISTORICAL_B1_BEFORE_SHA,
    policy_freeze_commit_sha: "b".repeat(40),
    private_material_sha256: digest,
    fresh_deploy_key: target,
    policy: { registry_identity: "c2-policy:test", policy_version: 2, authority_fields: { policy_id: "c2-policy:test", repository_id: 1350596128, repository_full_name: B1_REPOSITORY, ref: B1_REF, secret_path: B1_SECRET_PATH, deploy_key_id: target.id, expected_deploy_key_title: target.title, expected_read_only: true, expected_public_key_fingerprint: target.provider_public_key_fingerprint, expected_private_material_sha256: digest, enabled: true, ttl_secs: 900 }, remote_readback: { success: true } },
    policy_before_event: { remote_policy_readback_before_trigger: true, marker_persisted_before_trigger: true },
    secret_trigger_commit: { sha: "c".repeat(40), parent_sha: HISTORICAL_B1_BEFORE_SHA, only_changed_path: B1_SECRET_PATH, fast_forward: true },
    real_delivery: { event_type: "push", repository_id: 1350596128, repository_full_name: B1_REPOSITORY, ref: B1_REF, before: HISTORICAL_B1_BEFORE_SHA, after: "c".repeat(40), created: false, forced: false, deleted: false, signature_verified: true, raw_body_sha256: digest, dedupe_status: "NEW" },
    source_reader_token: { requested_permissions: { contents: "read" }, actual_permissions: { contents: "read" }, administration_write_granted: false, immutable_before_http_status: 404, immutable_after_http_status: 200, revoke_http_status: 204, refusal_http_status: 401 },
    immutable_before: { status: 404, commit_sha: HISTORICAL_B1_BEFORE_SHA, path: B1_SECRET_PATH },
    immutable_after: { status: 200, commit_sha: "c".repeat(40), path: B1_SECRET_PATH, content_sha256: digest },
    transition_classification: "CAUSAL_SECRET_INTRODUCED",
    derived_c1_request: { incident_id: "C2-test", remediation_agent_did: "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019", effect_broker_did: "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57", deploy_key_id: target.id, ttl_secs: 900 },
    mutation_counters: { t3n_create_calls: 0, provider_effects: 0 },
    sensitive_value_hygiene: { private_material_in_evidence: false, raw_webhook_body_in_evidence: false },
  };
}

test("accepts a complete sanitized causal B1 bundle", () => {
  assert.deepEqual(verifyB1Evidence(fixture(), HISTORICAL_CONTEXT), { valid: true, reasons: [] });
});

test("the exact runner evidence shape round-trips with registry_identity and no policy_id", () => {
  const serialized = serializeB1Evidence(buildB1Evidence(fixture()));
  const parsed = JSON.parse(serialized.toString("utf8"));
  assert.equal(parsed.policy.registry_identity, "c2-policy:test");
  assert.equal(parsed.policy.policy_id, undefined);
  assert.deepEqual(verifyB1Evidence(parsed, HISTORICAL_CONTEXT), { valid: true, reasons: [] });
});

test("missing execution context fails closed without historical defaults", () => {
  assert.deepEqual(verifyB1Evidence(fixture(), undefined as unknown as B1VerificationContext), { valid: false, reasons: ["explicit B1 verification context is required"] });
});

test("policy identity absent entirely fails closed", () => {
  const copy = fixture();
  delete copy.policy.registry_identity;
  assert.equal(verifyB1Evidence(JSON.parse(JSON.stringify(copy)), HISTORICAL_CONTEXT).valid, false);
});

test("wrong registry identity fails closed", () => {
  const copy = fixture();
  copy.policy.registry_identity = "c2-policy:other";
  assert.equal(verifyB1Evidence(copy, HISTORICAL_CONTEXT).valid, false);
});

for (const [name, mutate] of [
  ["wrong target", (e: any) => { e.policy.authority_fields.deploy_key_id += 1; }],
  ["wrong fingerprint", (e: any) => { e.policy.authority_fields.expected_public_key_fingerprint = "SHA256:other"; }],
  ["wrong policy digest", (e: any) => { e.policy.authority_fields.expected_private_material_sha256 = "d".repeat(64); }],
  ["policy frozen after event", (e: any) => { e.policy_before_event.remote_policy_readback_before_trigger = false; }],
  ["wrong before SHA", (e: any) => { e.real_delivery.before = "e".repeat(40); }],
  ["wrong after SHA", (e: any) => { e.immutable_after.commit_sha = "f".repeat(40); }],
  ["created push", (e: any) => { e.real_delivery.created = true; }],
  ["forced push", (e: any) => { e.real_delivery.forced = true; }],
  ["before secret already present", (e: any) => { e.immutable_before.status = 200; e.immutable_before.content_sha256 = e.private_material_sha256; }],
  ["after mismatch", (e: any) => { e.immutable_after.content_sha256 = "e".repeat(64); }],
  ["raw private key in evidence", (e: any) => { e.private_key = "-----BEGIN OPENSSH PRIVATE KEY-----"; }],
  ["C1 target substitution", (e: any) => { e.derived_c1_request.deploy_key_id += 1; }],
] as const) {
  test(`rejects ${name}`, () => {
    const result = verifyB1Evidence(fixture(), HISTORICAL_CONTEXT);
    assert.equal(result.valid, true);
    const copy = fixture();
    mutate(copy);
    assert.equal(verifyB1Evidence(copy, HISTORICAL_CONTEXT).valid, false);
  });
}
