import type { NormalizedPushEvent } from "./types.js";
import {
  C2_PUSH_EVENT_TYPE,
  C2_PUSH_REF,
  C2_PUSH_REPOSITORY,
  C2_PUSH_REPOSITORY_ID,
  C2_PUSH_SECRET_PATH,
} from "./push-source.js";

export type PushPolicyProvenanceClass = "LIVE_PROVENANCE" | "LOCAL_TEST_FIXTURE";

export interface PushPolicyProvenance {
  classification: PushPolicyProvenanceClass;
  creation_evidence: string;
  enabled_before_event_proof: boolean;
}

/**
 * This is a shape for a future live registry record, not a pre-filled target.
 * The builder requires actual target and provenance facts from its caller.
 */
export interface C2PushPolicyV2 {
  policy_id: string;
  policy_version: number;
  source_provider: "github";
  source_event_type: typeof C2_PUSH_EVENT_TYPE;
  repository_id: typeof C2_PUSH_REPOSITORY_ID;
  repository_full_name: typeof C2_PUSH_REPOSITORY;
  ref: typeof C2_PUSH_REF;
  secret_path: typeof C2_PUSH_SECRET_PATH;
  deploy_key_id: number;
  expected_deploy_key_title: string;
  expected_read_only: true;
  expected_public_key_fingerprint: string;
  expected_private_material_sha256: string;
  remediation_agent_did: string;
  effect_broker_did: string;
  ttl_secs: number;
  enabled: boolean;
  actual_creation_timestamp: string;
  creation_commit_or_registry_identity: string;
  provenance: PushPolicyProvenance;
}

export type C2PushPolicyV2Input = Omit<C2PushPolicyV2, "source_provider" | "source_event_type" | "repository_id" | "repository_full_name" | "ref" | "secret_path">;

export interface PushPolicyValidation {
  valid: boolean;
  live: boolean;
  reasons: string[];
}

export function validateC2PushPolicyV2(
  policy: C2PushPolicyV2,
  options: { requireLiveProvenance?: boolean } = {},
): PushPolicyValidation {
  const reasons: string[] = [];
  if (!policy.policy_id || !Number.isSafeInteger(policy.policy_version) || policy.policy_version <= 0) reasons.push("policy identity/version is invalid");
  if (policy.source_provider !== "github" || policy.source_event_type !== C2_PUSH_EVENT_TYPE) reasons.push("source is not the frozen GitHub push source");
  if (policy.repository_id !== C2_PUSH_REPOSITORY_ID || policy.repository_full_name !== C2_PUSH_REPOSITORY) reasons.push("repository binding is not exact");
  if (policy.ref !== C2_PUSH_REF || policy.secret_path !== C2_PUSH_SECRET_PATH) reasons.push("ref/path binding is not exact");
  if (!Number.isSafeInteger(policy.deploy_key_id) || policy.deploy_key_id <= 0 || !policy.expected_deploy_key_title || policy.expected_read_only !== true) reasons.push("deploy-key target binding is incomplete");
  if (!/^SHA256\/[A-Za-z0-9+/]+={0,2}$/.test(policy.expected_public_key_fingerprint)) reasons.push("public-key fingerprint is malformed");
  if (!/^[0-9a-f]{64}$/.test(policy.expected_private_material_sha256)) reasons.push("private-material digest is malformed");
  if (!policy.remediation_agent_did || !policy.effect_broker_did) reasons.push("C1 principal binding is incomplete");
  if (!Number.isSafeInteger(policy.ttl_secs) || policy.ttl_secs <= 0 || policy.ttl_secs > 86_400) reasons.push("TTL is not bounded");
  if (!policy.actual_creation_timestamp || !Number.isFinite(Date.parse(policy.actual_creation_timestamp))) reasons.push("actual creation timestamp is missing or malformed");
  if (!policy.creation_commit_or_registry_identity) reasons.push("creation commit/registry identity is missing");
  if (!policy.provenance.creation_evidence) reasons.push("creation evidence is missing");
  if (policy.provenance.enabled_before_event_proof !== true) reasons.push("enabled-before-event proof is missing");

  const live = policy.provenance.classification === "LIVE_PROVENANCE" && reasons.length === 0;
  if (options.requireLiveProvenance === true && policy.provenance.classification !== "LIVE_PROVENANCE") reasons.push("policy is a local fixture, not live provenance");
  return { valid: reasons.length === 0, live, reasons };
}

export function buildC2PushPolicyV2(input: C2PushPolicyV2Input): C2PushPolicyV2 {
  const policy: C2PushPolicyV2 = {
    ...input,
    source_provider: "github",
    source_event_type: C2_PUSH_EVENT_TYPE,
    repository_id: C2_PUSH_REPOSITORY_ID,
    repository_full_name: C2_PUSH_REPOSITORY,
    ref: C2_PUSH_REF,
    secret_path: C2_PUSH_SECRET_PATH,
  };
  const validation = validateC2PushPolicyV2(policy);
  if (!validation.valid) throw new Error(`invalid C2 push policy v2: ${validation.reasons.join(", ")}`);
  return policy;
}

export type PushPolicyLookupResult =
  | { kind: "MATCH"; policy: C2PushPolicyV2 }
  | { kind: "NO_MATCH"; reason: string }
  | { kind: "DISABLED"; policy: C2PushPolicyV2 };

export function lookupPreExistingPushPolicy(
  event: NormalizedPushEvent,
  policies: readonly C2PushPolicyV2[],
  options: { allowLocalFixture?: boolean } = {},
): PushPolicyLookupResult {
  const policy = policies.find((candidate) =>
    candidate.source_provider === event.provider &&
    candidate.source_event_type === event.event_type &&
    candidate.repository_id === event.repository_id &&
    candidate.repository_full_name === event.repository_full_name &&
    candidate.ref === event.ref,
  );
  if (!policy) return { kind: "NO_MATCH", reason: "no pre-existing push policy matches the authenticated repository/ref" };
  if (!policy.enabled) return { kind: "DISABLED", policy };
  const validation = validateC2PushPolicyV2(policy, { requireLiveProvenance: options.allowLocalFixture !== true });
  if (!validation.valid) return { kind: "NO_MATCH", reason: `policy is not usable: ${validation.reasons.join(", ")}` };
  return { kind: "MATCH", policy };
}
