import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { buildB1Evidence, serializeB1Evidence } from "../c2/b1-evidence.js";
import { B1_REPOSITORY, B1_REF, B1_SECRET_PATH, verifyB1Evidence, type B1VerificationContext } from "../c2/b1-verifier.js";

const CURRENT_CONTEXT: B1VerificationContext = {
  expectedStartingSha: "3c00f57f8a4d5d0187658cd53c2b2b9f676e5c2c",
  expectedMainSha: "4a077035474337b7a1ad16204820e68ed3020477",
  expectedBeforeSha: "0ef99189955ff8bbdd18b1918937076883581528",
};
const OLD_START = "84df42102b6b7ad7eddf36e786cf6438f2024d1a";
const OLD_BEFORE = "983a95d2e1f6ef44530490bdc4377bb5f3b44514";

function evidenceFor(context: B1VerificationContext): Record<string, unknown> {
  const digest = createHash("sha256").update("r1a synthetic private material", "utf8").digest("hex");
  const after = "f".repeat(40);
  const policyId = "c2-policy:r1a-synthetic";
  const target = { id: 246813579, title: "breakglass-c2-b1-r1a-synthetic", read_only: true, generated_public_key_fingerprint: "SHA256:r1aSynthetic", provider_public_key_fingerprint: "SHA256:r1aSynthetic", private_public_relation_proven: true };
  return buildB1Evidence({
    starting_sha: context.expectedStartingSha,
    main_sha: context.expectedMainSha,
    b0_before_sha: context.expectedBeforeSha,
    policy_freeze_commit_sha: "1".repeat(40),
    private_material_sha256: digest,
    fresh_deploy_key: target,
    policy: { registry_identity: policyId, policy_version: 2, authority_fields: { policy_id: policyId, source_provider: "github", source_event_type: "push", repository_id: 1350596128, repository_full_name: B1_REPOSITORY, ref: B1_REF, secret_path: B1_SECRET_PATH, deploy_key_id: target.id, expected_deploy_key_title: target.title, expected_read_only: true, expected_public_key_fingerprint: target.provider_public_key_fingerprint, expected_private_material_sha256: digest, remediation_agent_did: "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019", effect_broker_did: "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57", ttl_secs: 900, enabled: true }, remote_readback: { success: true } },
    policy_before_event: { remote_policy_readback_before_trigger: true, marker_persisted_before_trigger: true },
    secret_trigger_commit: { sha: after, parent_sha: context.expectedBeforeSha, only_changed_path: B1_SECRET_PATH, fast_forward: true },
    real_delivery: { event_type: "push", repository_id: 1350596128, repository_full_name: B1_REPOSITORY, ref: B1_REF, before: context.expectedBeforeSha, after, created: false, forced: false, deleted: false, signature_verified: true, raw_body_sha256: "2".repeat(64), dedupe_status: "NEW" },
    source_reader_token: { requested_permissions: { contents: "read" }, actual_permissions: { contents: "read" }, administration_write_granted: false, read_http_status: 200, revoke_http_status: 204, refusal_http_status: 401 },
    immutable_before: { status: 404, commit_sha: context.expectedBeforeSha, path: B1_SECRET_PATH },
    immutable_after: { status: 200, commit_sha: after, path: B1_SECRET_PATH, content_sha256: digest },
    transition_classification: "CAUSAL_SECRET_INTRODUCED",
    derived_c1_request: { incident_id: "C2-r1a", remediation_agent_did: "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019", effect_broker_did: "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57", deploy_key_id: target.id, ttl_secs: 900 },
    mutation_counters: { t3n_create_calls: 0, provider_effects: 0 },
    sensitive_value_hygiene: { private_material_in_evidence: false, raw_webhook_body_in_evidence: false },
  });
}

function roundTrip(evidence: Record<string, unknown>): Record<string, unknown> {
  return JSON.parse(serializeB1Evidence(evidence).toString("utf8")) as Record<string, unknown>;
}

test("current R1A checkpoint verifies only with its explicit context", () => {
  const evidence = roundTrip(evidenceFor(CURRENT_CONTEXT));
  assert.deepEqual(verifyB1Evidence(evidence, CURRENT_CONTEXT), { valid: true, reasons: [] });
  assert.equal(verifyB1Evidence(evidence, { ...CURRENT_CONTEXT, expectedStartingSha: OLD_START }).valid, false);
  assert.equal(verifyB1Evidence(evidence, { ...CURRENT_CONTEXT, expectedBeforeSha: OLD_BEFORE }).valid, false);
  assert.equal(verifyB1Evidence({ ...evidence, starting_sha: OLD_START }, CURRENT_CONTEXT).valid, false);
  assert.equal(verifyB1Evidence({ ...evidence, b0_before_sha: OLD_BEFORE }, CURRENT_CONTEXT).valid, false);
});

test("arbitrary future execution checkpoints are accepted only when context matches", () => {
  const future = { expectedStartingSha: "a".repeat(40), expectedMainSha: "b".repeat(40), expectedBeforeSha: "c".repeat(40) } satisfies B1VerificationContext;
  const evidence = roundTrip(evidenceFor(future));
  assert.deepEqual(verifyB1Evidence(evidence, future), { valid: true, reasons: [] });
  assert.equal(verifyB1Evidence(evidence, { ...future, expectedStartingSha: "d".repeat(40) }).valid, false);
  assert.equal(verifyB1Evidence(evidence, { ...future, expectedBeforeSha: "e".repeat(40) }).valid, false);
});
