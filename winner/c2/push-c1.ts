import { createHash } from "node:crypto";
import type { C1CreateRequest, NormalizedPushEvent } from "./types.js";
import { C2_PUSH_REF, C2_PUSH_REPOSITORY, C2_PUSH_REPOSITORY_ID } from "./push-source.js";
import { validateC2PushPolicyV2, type C2PushPolicyV2 } from "./push-policy.js";
import type { PushTransitionResult } from "./push-transition.js";

export class PushAuthorityBoundaryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PushAuthorityBoundaryError";
  }
}

export function derivePushIncidentId(event: NormalizedPushEvent, policy: C2PushPolicyV2): string {
  const material = `${policy.policy_id}\n${policy.policy_version}\n${event.delivery_id}\n${event.raw_body_sha256}`;
  const digest = createHash("sha256").update(material, "utf8").digest("hex");
  return `C2-${policy.policy_id}-${digest.slice(0, 24)}`;
}

/**
 * The default boundary requires live policy provenance. Local tests must opt
 * into fixture mode explicitly; no caller can accidentally use fixture v2 as
 * live authority.
 */
export function derivePushC1CreateRequest(
  event: NormalizedPushEvent,
  policy: C2PushPolicyV2,
  transition: PushTransitionResult,
  options: { allowLocalFixture?: boolean } = {},
): { incident_id: string; create_request: C1CreateRequest } {
  const validation = validateC2PushPolicyV2(policy);
  if (!validation.valid) throw new PushAuthorityBoundaryError(`policy is invalid: ${validation.reasons.join(", ")}`);
  if (!options.allowLocalFixture && !validation.live) throw new PushAuthorityBoundaryError("policy lacks live provenance");
  if (!policy.enabled) throw new PushAuthorityBoundaryError("policy is disabled");
  if (event.repository_id !== C2_PUSH_REPOSITORY_ID || event.repository_full_name !== C2_PUSH_REPOSITORY || event.ref !== C2_PUSH_REF || event.deleted) {
    throw new PushAuthorityBoundaryError("push does not match the frozen repository/ref");
  }
  if (transition.classification !== "CAUSAL_SECRET_INTRODUCED") {
    throw new PushAuthorityBoundaryError(`secret transition is not causal: ${transition.classification}`);
  }

  const incident_id = derivePushIncidentId(event, policy);
  return {
    incident_id,
    create_request: {
      incident_id,
      remediation_agent_did: policy.remediation_agent_did,
      effect_broker_did: policy.effect_broker_did,
      deploy_key_id: policy.deploy_key_id,
      ttl_secs: policy.ttl_secs,
    },
  };
}
