import { createHash } from "node:crypto";
import type { C1CreateRequest, C2Policy, NormalizedGithubEvent } from "./types.js";
import { C2_ACTION } from "./types.js";

export class C2TargetBindingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "C2TargetBindingError";
  }
}

export function deriveIncidentId(event: NormalizedGithubEvent, policy: C2Policy): string {
  const causalMaterial = `${policy.policy_id}\n${policy.policy_version}\n${event.raw_body_sha256}`;
  const digest = createHash("sha256").update(causalMaterial, "utf8").digest("hex");
  return `C2-${policy.policy_id}-${digest.slice(0, 24)}`;
}

export function deriveC1CreateRequest(
  event: NormalizedGithubEvent,
  policy: C2Policy,
): { incident_id: string; create_request: C1CreateRequest } {
  if (policy.action !== C2_ACTION) throw new C2TargetBindingError("policy action is not the frozen C1 action");
  if (policy.target_reference.repository_full_name !== policy.repository_identity.full_name) {
    throw new C2TargetBindingError("policy target repository does not match policy repository identity");
  }
  if (event.repository_full_name !== policy.repository_identity.full_name) {
    throw new C2TargetBindingError("authenticated repository is not the policy repository");
  }
  const target = policy.target_reference;
  if (!Number.isSafeInteger(target.deploy_key_id) || target.deploy_key_id <= 0) {
    throw new C2TargetBindingError("exact deploy-key target is missing or invalid");
  }
  if (!target.expected_title || target.expected_read_only !== true) {
    throw new C2TargetBindingError("target binding metadata is incomplete");
  }
  if (!Number.isSafeInteger(policy.ttl_secs) || policy.ttl_secs <= 0 || policy.ttl_secs > 86_400) {
    throw new C2TargetBindingError("policy TTL is not bounded");
  }
  const incident_id = deriveIncidentId(event, policy);
  return {
    incident_id,
    create_request: {
      incident_id,
      remediation_agent_did: policy.remediation_agent_did,
      effect_broker_did: policy.effect_broker_did,
      deploy_key_id: target.deploy_key_id,
      ttl_secs: policy.ttl_secs,
    },
  };
}
