import { createHash } from "node:crypto";

import { canonicalize } from "../runtime/integrity.js";
import type { C2PushPolicyV2 } from "./push-policy.js";
import type { PushTransitionResult } from "./push-transition.js";
import type { NormalizedPushEvent } from "./types.js";

export interface PushBindingIdentityInput {
  policy: C2PushPolicyV2;
  event: NormalizedPushEvent;
  transition: PushTransitionResult;
  incidentId: string;
  dedupeKey: string;
  registryIdentity: string;
  policyContentHash: string;
  eventBindingIdentity?: string;
}

export function pushEventBindingIdentity(input: PushBindingIdentityInput): string {
  return createHash("sha256").update(canonicalize({
    policy_id: input.policy.policy_id,
    policy_version: input.policy.policy_version,
    registry_identity: input.registryIdentity,
    policy_content_hash: input.policyContentHash,
    dedupe_key: input.dedupeKey,
    delivery_id: input.event.delivery_id,
    event_type: input.event.event_type,
    repository_id: input.event.repository_id,
    repository_full_name: input.event.repository_full_name,
    ref: input.event.ref,
    before: input.event.before,
    after: input.event.after,
    raw_body_sha256: input.event.raw_body_sha256,
    transition: input.transition.classification,
    before_digest: input.transition.before_digest,
    after_digest: input.transition.after_digest,
    incident_id: input.incidentId,
  }), "utf8").digest("hex");
}
