import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { buildB1Evidence, serializeB1Evidence } from "../c2/b1-evidence.js";
import { verifyB1Evidence, B1_REPOSITORY, B1_REF, B1_SECRET_PATH, type B1VerificationContext } from "../c2/b1-verifier.js";
import { derivePushC1CreateRequest } from "../c2/push-c1.js";
import { createImmutablePushReadPlan } from "../c2/push-read-plan.js";
import { lookupPreExistingPushPolicy, buildC2PushPolicyV2 } from "../c2/push-policy.js";
import { normalizeVerifiedPushEvent } from "../c2/push-source.js";
import { verifyPushSecretTransition } from "../c2/push-transition.js";
import { PUSH_TEST_SECRET, signedPush } from "./c2-push-fixture.js";

const NEW_B1_BEFORE_SHA = "0ef99189955ff8bbdd18b1918937076883581528";
const PREFLIGHT_STARTING_SHA = "3c00f57f8a4d5d0187658cd53c2b2b9f676e5c2c";
const PREFLIGHT_MAIN_SHA = "4a077035474337b7a1ad16204820e68ed3020477";
const PREFLIGHT_CONTEXT: B1VerificationContext = { expectedStartingSha: PREFLIGHT_STARTING_SHA, expectedMainSha: PREFLIGHT_MAIN_SHA, expectedBeforeSha: NEW_B1_BEFORE_SHA };
const SYNTHETIC_AFTER_SHA = "f".repeat(40);
const SYNTHETIC_DELIVERY_ID = "33333333-3333-4333-8333-333333333333";
const DIGEST = createHash("sha256").update("c2-b1-r1 synthetic disposable private material", "utf8").digest("hex");
const FINGERPRINT = "SHA256:c2B1R1SyntheticFingerprint";

test("full synthetic B1 pipeline uses the runner evidence builder and passes round-trip verification", () => {
  const policy = buildC2PushPolicyV2({
    policy_id: "c2-policy:r1-synthetic-current",
    policy_version: 2,
    deploy_key_id: 246813579,
    expected_deploy_key_title: "breakglass-c2-b1-r1-synthetic",
    expected_read_only: true,
    expected_public_key_fingerprint: FINGERPRINT,
    expected_private_material_sha256: DIGEST,
    remediation_agent_did: "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019",
    effect_broker_did: "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57",
    ttl_secs: 900,
    enabled: true,
    actual_creation_timestamp: "2026-09-06T00:00:00.000Z",
    creation_commit_or_registry_identity: "registry:c2-policy:r1-synthetic-current",
    provenance: { classification: "LIVE_PROVENANCE", creation_evidence: "preflight-synthetic-remote-attestation", enabled_before_event_proof: true },
  });
  const request = signedPush({ deliveryId: SYNTHETIC_DELIVERY_ID, before: NEW_B1_BEFORE_SHA, after: SYNTHETIC_AFTER_SHA });
  const event = normalizeVerifiedPushEvent(request, PUSH_TEST_SECRET);
  const lookup = lookupPreExistingPushPolicy(event, [policy]);
  assert.equal(lookup.kind, "MATCH");
  const plan = createImmutablePushReadPlan(event, policy);
  assert.deepEqual(plan, { repository: B1_REPOSITORY, before_sha: NEW_B1_BEFORE_SHA, after_sha: SYNTHETIC_AFTER_SHA, path: B1_SECRET_PATH });
  const transition = verifyPushSecretTransition(
    { repository: B1_REPOSITORY, commit_sha: NEW_B1_BEFORE_SHA, path: B1_SECRET_PATH, status: 404 },
    { repository: B1_REPOSITORY, commit_sha: SYNTHETIC_AFTER_SHA, path: B1_SECRET_PATH, status: 200, content_sha256: DIGEST },
    policy,
    plan,
  );
  assert.equal(transition.classification, "CAUSAL_SECRET_INTRODUCED");
  const derived = derivePushC1CreateRequest(event, policy, transition);
  const evidence = buildB1Evidence({
    starting_sha: PREFLIGHT_STARTING_SHA,
    main_sha: PREFLIGHT_MAIN_SHA,
    b0_before_sha: NEW_B1_BEFORE_SHA,
    policy_freeze_commit_sha: "1".repeat(40),
    private_material_sha256: DIGEST,
    fresh_deploy_key: { id: policy.deploy_key_id, title: policy.expected_deploy_key_title, read_only: true, generated_public_key_fingerprint: FINGERPRINT, provider_public_key_fingerprint: FINGERPRINT, private_public_relation_proven: true },
    policy: { registry_identity: policy.policy_id, policy_version: policy.policy_version, authority_fields: { ...policy }, remote_readback: { success: true } },
    policy_before_event: { remote_policy_readback_before_trigger: true, marker_persisted_before_trigger: true },
    secret_trigger_commit: { sha: SYNTHETIC_AFTER_SHA, parent_sha: NEW_B1_BEFORE_SHA, only_changed_path: B1_SECRET_PATH, fast_forward: true },
    real_delivery: { event_type: "push", repository_id: 1350596128, repository_full_name: B1_REPOSITORY, ref: B1_REF, before: NEW_B1_BEFORE_SHA, after: SYNTHETIC_AFTER_SHA, created: false, forced: false, deleted: false, signature_verified: true, raw_body_sha256: event.raw_body_sha256, dedupe_status: "NEW" },
    source_reader_token: { requested_permissions: { contents: "read" }, actual_permissions: { contents: "read" }, administration_write_granted: false, immutable_before_http_status: 404, immutable_after_http_status: 200, revoke_http_status: 204, refusal_http_status: 401 },
    immutable_before: { status: 404, commit_sha: NEW_B1_BEFORE_SHA, path: B1_SECRET_PATH },
    immutable_after: { status: 200, commit_sha: SYNTHETIC_AFTER_SHA, path: B1_SECRET_PATH, content_sha256: DIGEST },
    transition_classification: transition.classification,
    derived_c1_request: derived.create_request,
    mutation_counters: { t3n_create_calls: 0, provider_effects: 0 },
    sensitive_value_hygiene: { private_material_in_evidence: false, raw_webhook_body_in_evidence: false },
  });
  const roundTrip = JSON.parse(serializeB1Evidence(evidence).toString("utf8"));
  assert.deepEqual(verifyB1Evidence(roundTrip, PREFLIGHT_CONTEXT), { valid: true, reasons: [] });
});
