import type { C1CreateRequest } from "./types.js";

export const B1_STARTING_SHA = "84df42102b6b7ad7eddf36e786cf6438f2024d1a";
export const B1_MAIN_SHA = "4a077035474337b7a1ad16204820e68ed3020477";
export const B1_BEFORE_SHA = "983a95d2e1f6ef44530490bdc4377bb5f3b44514";
export const B1_REPOSITORY = "Ticoworld/t3n-breakglass-sandbox";
export const B1_REF = "refs/heads/c2-breakglass-demo";
export const B1_SECRET_PATH = ".breakglass-c2/exposed-deploy-key";

type JsonObject = Record<string, any>;

function object(value: unknown): JsonObject | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as JsonObject : null;
}

function hex(value: unknown, length: number): boolean {
  return typeof value === "string" && new RegExp(`^[0-9a-f]{${length}}$`, "i").test(value);
}

function requireField(reasons: string[], condition: unknown, reason: string): void {
  if (!condition) reasons.push(reason);
}

/**
 * Offline verifier for the sanitized B1 bundle.  It intentionally checks the
 * causal ordering and target identity without ever needing private material.
 */
export function verifyB1Evidence(value: unknown): { valid: boolean; reasons: string[] } {
  const e = object(value);
  const reasons: string[] = [];
  if (!e) return { valid: false, reasons: ["evidence is not an object"] };

  requireField(reasons, e.classification === "C2_B1_REAL_CAUSAL_SECRET_INTRODUCTION_PASS", "classification is not the B1 causal pass");
  requireField(reasons, e.starting_sha === B1_STARTING_SHA, "starting SHA is not the frozen B1 checkpoint");
  requireField(reasons, e.main_sha === B1_MAIN_SHA, "main SHA changed");
  requireField(reasons, e.b0_before_sha === B1_BEFORE_SHA, "B0 baseline is not exact");

  const target = object(e.fresh_deploy_key);
  const policy = object(e.policy);
  const authority = object(policy?.authority_fields);
  const delivery = object(e.real_delivery);
  const trigger = object(e.secret_trigger_commit);
  const ordering = object(e.policy_before_event);
  const source = object(e.source_reader_token);
  const before = object(e.immutable_before);
  const after = object(e.immutable_after);
  const request = object(e.derived_c1_request) as C1CreateRequest | null;
  const counters = object(e.mutation_counters);

  requireField(reasons, target?.id && Number.isSafeInteger(target.id) && target.id > 0, "fresh deploy-key ID is missing");
  requireField(reasons, target?.read_only === true, "fresh deploy key is not read-only");
  requireField(reasons, typeof target?.title === "string" && target.title.startsWith("breakglass-c2-b1-"), "fresh deploy-key title is not B1-scoped");
  requireField(reasons, target?.generated_public_key_fingerprint === target?.provider_public_key_fingerprint, "generated/provider public fingerprints differ");
  requireField(reasons, target?.private_public_relation_proven === true, "private/public relation was not proven");
  requireField(reasons, typeof e.private_material_sha256 === "string" && /^[0-9a-f]{64}$/.test(e.private_material_sha256), "private-material digest is malformed");

  requireField(reasons, policy?.policy_id && policy.policy_version === 2, "policy identity/version is missing");
  requireField(reasons, authority?.repository_id === 1350596128 && authority.repository_full_name === B1_REPOSITORY, "policy repository binding is not exact");
  requireField(reasons, authority?.ref === B1_REF && authority.secret_path === B1_SECRET_PATH, "policy ref/path binding is not exact");
  requireField(reasons, authority?.deploy_key_id === target?.id, "policy target ID differs from installed target");
  requireField(reasons, authority?.expected_deploy_key_title === target?.title && authority.expected_read_only === true, "policy target metadata differs");
  requireField(reasons, authority?.expected_public_key_fingerprint === target?.provider_public_key_fingerprint, "policy public fingerprint differs");
  requireField(reasons, authority?.expected_private_material_sha256 === e.private_material_sha256, "policy private-material digest differs");
  requireField(reasons, authority?.enabled === true && authority?.ttl_secs === 900, "policy authority bounds are not exact");
  requireField(reasons, policy?.remote_readback?.success === true, "policy remote readback did not succeed");
  requireField(reasons, hex(e.policy_freeze_commit_sha, 40), "policy freeze commit SHA is missing");
  requireField(reasons, ordering?.remote_policy_readback_before_trigger === true, "policy was not proven before trigger");
  requireField(reasons, ordering?.marker_persisted_before_trigger === true, "policy frozen marker was not persisted before trigger");

  requireField(reasons, trigger?.parent_sha === B1_BEFORE_SHA, "secret commit parent is not the exact B0 baseline");
  requireField(reasons, hex(trigger?.sha, 40) && trigger.sha !== B1_BEFORE_SHA, "secret commit SHA is invalid");
  requireField(reasons, trigger?.only_changed_path === B1_SECRET_PATH, "secret commit changed an unexpected path");
  requireField(reasons, trigger?.fast_forward === true, "secret commit was not fast-forward");

  requireField(reasons, delivery?.event_type === "push" && delivery.repository_id === 1350596128 && delivery.repository_full_name === B1_REPOSITORY, "delivery source identity is not exact");
  requireField(reasons, delivery?.ref === B1_REF && delivery.before === B1_BEFORE_SHA && delivery.after === trigger?.sha, "delivery ref or before/after identity is not exact");
  requireField(reasons, delivery?.created === false && delivery?.forced === false && delivery?.deleted === false, "delivery flags are not authority-safe");
  requireField(reasons, delivery?.signature_verified === true && typeof delivery.raw_body_sha256 === "string", "delivery HMAC/digest evidence is missing");
  requireField(reasons, delivery?.dedupe_status === "NEW", "delivery was not durably NEW");

  requireField(reasons, source?.requested_permissions?.contents === "read", "source token was not requested Contents:read");
  requireField(reasons, source?.actual_permissions?.contents === "read" && source?.administration_write_granted === false, "source token permissions are too broad");
  requireField(reasons, source?.read_http_status === 200 && source?.revoke_http_status === 204 && (source?.refusal_http_status === 401 || source?.refusal_http_status === 403), "source token lifecycle is incomplete");
  requireField(reasons, before?.status === 404 && before?.commit_sha === B1_BEFORE_SHA && before.path === B1_SECRET_PATH, "immutable BEFORE proof is not exact");
  requireField(reasons, after?.status === 200 && after?.commit_sha === trigger?.sha && after.path === B1_SECRET_PATH && after.content_sha256 === e.private_material_sha256, "immutable AFTER digest proof is not exact");
  requireField(reasons, e.transition_classification === "CAUSAL_SECRET_INTRODUCED", "transition is not causal");

  const requestKeys = request ? Object.keys(request).sort().join(",") : "";
  requireField(reasons, requestKeys === "deploy_key_id,effect_broker_did,incident_id,remediation_agent_did,ttl_secs", "derived C1 request shape is not exact");
  requireField(reasons, request?.deploy_key_id === target?.id && request?.ttl_secs === 900, "derived C1 request target/TTL differs");
  requireField(reasons, request?.remediation_agent_did === "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019", "derived remediation DID differs");
  requireField(reasons, request?.effect_broker_did === "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57", "derived broker DID differs");
  requireField(reasons, counters?.t3n_create_calls === 0 && counters?.provider_effects === 0, "forbidden downstream mutation counter is non-zero");
  requireField(reasons, e.sensitive_value_hygiene?.private_material_in_evidence === false && e.sensitive_value_hygiene?.raw_webhook_body_in_evidence === false, "sensitive material hygiene failed");

  const serialized = JSON.stringify(e);
  requireField(reasons, !/BEGIN (?:OPENSSH|RSA|EC) PRIVATE KEY/.test(serialized), "raw private key material appears in evidence");
  requireField(reasons, !Object.prototype.hasOwnProperty.call(e, "private_key"), "private_key field appears in evidence");
  return { valid: reasons.length === 0, reasons };
}
