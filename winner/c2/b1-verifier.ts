import type { C1CreateRequest } from "./types.js";
import { R3_E2E_SCHEMA } from "./e2e-schema.js";

export interface B1VerificationContext {
  expectedStartingSha: string;
  expectedMainSha: string;
  expectedBeforeSha: string;
}

export const B1_REPOSITORY = "Ticoworld/t3n-breakglass-sandbox";
export const B1_REF = "refs/heads/c2-breakglass-demo";
export const B1_SECRET_PATH = ".breakglass-c2/exposed-deploy-key";

export interface B1VerificationSchema {
  classification: "C2_B1_REAL_CAUSAL_SECRET_INTRODUCTION_PASS";
  targetTitlePrefix: string;
  policyIdPrefix?: string;
  repository: string;
  repositoryId: number;
  ref: string;
  secretPath: string;
  remediationDid: string;
  brokerDid: string;
  ttlSecs: number;
}

const DEFAULT_SCHEMA: B1VerificationSchema = {
  classification: "C2_B1_REAL_CAUSAL_SECRET_INTRODUCTION_PASS",
  targetTitlePrefix: "breakglass-c2-b1-",
  repository: B1_REPOSITORY,
  repositoryId: 1350596128,
  ref: B1_REF,
  secretPath: B1_SECRET_PATH,
  remediationDid: "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019",
  brokerDid: "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57",
  ttlSecs: 900,
};

export const R3_B1_SCHEMA: B1VerificationSchema = {
  classification: "C2_B1_REAL_CAUSAL_SECRET_INTRODUCTION_PASS",
  targetTitlePrefix: R3_E2E_SCHEMA.targetTitlePrefix,
  policyIdPrefix: R3_E2E_SCHEMA.policyIdPrefix,
  repository: R3_E2E_SCHEMA.repository,
  repositoryId: R3_E2E_SCHEMA.repositoryId,
  ref: R3_E2E_SCHEMA.ref,
  secretPath: R3_E2E_SCHEMA.secretPath,
  remediationDid: R3_E2E_SCHEMA.remediationDid,
  brokerDid: R3_E2E_SCHEMA.brokerDid,
  ttlSecs: R3_E2E_SCHEMA.ttlSecs,
};

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
export function verifyB1Evidence(value: unknown, context: B1VerificationContext, schema: B1VerificationSchema = DEFAULT_SCHEMA): { valid: boolean; reasons: string[] } {
  const e = object(value);
  const reasons: string[] = [];
  if (!e) return { valid: false, reasons: ["evidence is not an object"] };
  if (!context) return { valid: false, reasons: ["explicit B1 verification context is required"] };
  const expectedStartingSha = context.expectedStartingSha;
  const expectedMainSha = context.expectedMainSha;
  const expectedBeforeSha = context.expectedBeforeSha;

  requireField(reasons, e.classification === schema.classification, "classification is not the B1 causal pass");
  requireField(reasons, hex(expectedStartingSha, 40) && e.starting_sha === expectedStartingSha, "starting SHA does not match the explicit execution context");
  requireField(reasons, hex(expectedMainSha, 40) && e.main_sha === expectedMainSha, "main SHA does not match the explicit execution context");
  requireField(reasons, hex(expectedBeforeSha, 40) && e.b0_before_sha === expectedBeforeSha, "B1 baseline is not exact");

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
  requireField(reasons, typeof target?.title === "string" && target.title.startsWith(schema.targetTitlePrefix), "fresh deploy-key title is not scoped to the selected E2E schema");
  requireField(reasons, target?.generated_public_key_fingerprint === target?.provider_public_key_fingerprint, "generated/provider public fingerprints differ");
  requireField(reasons, target?.private_public_relation_proven === true, "private/public relation was not proven");
  requireField(reasons, typeof e.private_material_sha256 === "string" && /^[0-9a-f]{64}$/.test(e.private_material_sha256), "private-material digest is malformed");

  requireField(reasons, policy?.registry_identity && policy.policy_version === 2 && (!schema.policyIdPrefix || policy.registry_identity.startsWith(schema.policyIdPrefix)), "policy identity/version is missing or not scoped to the selected E2E schema");
  requireField(reasons, policy?.registry_identity === authority?.policy_id, "policy registry identity does not match authority identity");
  requireField(reasons, authority?.repository_id === schema.repositoryId && authority.repository_full_name === schema.repository, "policy repository binding is not exact");
  requireField(reasons, authority?.ref === schema.ref && authority.secret_path === schema.secretPath, "policy ref/path binding is not exact");
  requireField(reasons, authority?.deploy_key_id === target?.id, "policy target ID differs from installed target");
  requireField(reasons, authority?.expected_deploy_key_title === target?.title && authority?.expected_read_only === true, "policy target metadata differs");
  requireField(reasons, authority?.expected_public_key_fingerprint === target?.provider_public_key_fingerprint, "policy public fingerprint differs");
  requireField(reasons, authority?.expected_private_material_sha256 === e.private_material_sha256, "policy private-material digest differs");
  requireField(reasons, authority?.enabled === true && authority?.ttl_secs === schema.ttlSecs, "policy authority bounds are not exact");
  requireField(reasons, policy?.remote_readback?.success === true, "policy remote readback did not succeed");
  requireField(reasons, hex(e.policy_freeze_commit_sha, 40), "policy freeze commit SHA is missing");
  requireField(reasons, ordering?.remote_policy_readback_before_trigger === true, "policy was not proven before trigger");
  requireField(reasons, ordering?.marker_persisted_before_trigger === true, "policy frozen marker was not persisted before trigger");

  requireField(reasons, trigger?.parent_sha === expectedBeforeSha, "secret commit parent is not the exact B1 baseline");
  requireField(reasons, hex(trigger?.sha, 40) && trigger?.sha !== expectedBeforeSha, "secret commit SHA is invalid");
  requireField(reasons, trigger?.only_changed_path === schema.secretPath, "secret commit changed an unexpected path");
  requireField(reasons, trigger?.fast_forward === true, "secret commit was not fast-forward");

  requireField(reasons, delivery?.event_type === "push" && delivery.repository_id === schema.repositoryId && delivery.repository_full_name === schema.repository, "delivery source identity is not exact");
  requireField(reasons, delivery?.ref === schema.ref && delivery.before === expectedBeforeSha && delivery.after === trigger?.sha, "delivery ref or before/after identity is not exact");
  requireField(reasons, delivery?.created === false && delivery?.forced === false && delivery?.deleted === false, "delivery flags are not authority-safe");
  requireField(reasons, delivery?.signature_verified === true && typeof delivery.raw_body_sha256 === "string", "delivery HMAC/digest evidence is missing");
  requireField(reasons, delivery?.dedupe_status === "NEW", "delivery was not durably NEW");

  requireField(reasons, source?.requested_permissions?.contents === "read", "source token was not requested Contents:read");
  requireField(reasons, source?.actual_permissions?.contents === "read" && source?.administration_write_granted === false, "source token permissions are too broad");
  requireField(reasons, source?.immutable_before_http_status === 404 && source?.immutable_after_http_status === 200 && source?.revoke_http_status === 204 && (source?.refusal_http_status === 401 || source?.refusal_http_status === 403), "source token lifecycle is incomplete");
  requireField(reasons, before?.status === 404 && before?.commit_sha === expectedBeforeSha && before.path === schema.secretPath, "immutable BEFORE proof is not exact");
  requireField(reasons, after?.status === 200 && after?.commit_sha === trigger?.sha && after.path === schema.secretPath && after.content_sha256 === e.private_material_sha256, "immutable AFTER digest proof is not exact");
  requireField(reasons, e.transition_classification === "CAUSAL_SECRET_INTRODUCED", "transition is not causal");

  const requestKeys = request ? Object.keys(request).sort().join(",") : "";
  requireField(reasons, requestKeys === "deploy_key_id,effect_broker_did,incident_id,remediation_agent_did,ttl_secs", "derived C1 request shape is not exact");
  requireField(reasons, request?.deploy_key_id === target?.id && request?.ttl_secs === schema.ttlSecs, "derived C1 request target/TTL differs");
  requireField(reasons, request?.remediation_agent_did === schema.remediationDid, "derived remediation DID differs");
  requireField(reasons, request?.effect_broker_did === schema.brokerDid, "derived broker DID differs");
  requireField(reasons, counters?.t3n_create_calls === 0 && counters?.provider_effects === 0, "forbidden downstream mutation counter is non-zero");
  requireField(reasons, e.sensitive_value_hygiene?.private_material_in_evidence === false && e.sensitive_value_hygiene?.raw_webhook_body_in_evidence === false, "sensitive material hygiene failed");

  const serialized = JSON.stringify(e);
  requireField(reasons, !/BEGIN (?:OPENSSH|RSA|EC) PRIVATE KEY/.test(serialized), "raw private key material appears in evidence");
  requireField(reasons, !Object.prototype.hasOwnProperty.call(e, "private_key"), "private_key field appears in evidence");
  return { valid: reasons.length === 0, reasons };
}
