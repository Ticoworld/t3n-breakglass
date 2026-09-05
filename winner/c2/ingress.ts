import type { C2Policy, C2IngressAccepted, C2IngressRejected, RawGithubRequest } from "./types.js";
import { normalizeVerifiedGithubEvent, GithubIngressError } from "./github-source.js";
import { reserveDedupe, finalizeDedupe } from "./dedupe.js";
import { lookupPreExistingPolicy } from "./policy.js";
import { deriveC1CreateRequest, C2TargetBindingError } from "./derive-incident.js";

export type C2IngressResult = C2IngressAccepted | C2IngressRejected;

/**
 * Local C2-A boundary. It returns a C1 request plan and deliberately has no
 * provider, T3N, network, or operator-call capability.
 */
export async function processGithubWebhook(
  request: RawGithubRequest,
  webhookSecret: string,
  dedupeDirectory: string,
  policies?: readonly C2Policy[],
): Promise<C2IngressResult> {
  let event;
  try {
    event = normalizeVerifiedGithubEvent(request, webhookSecret);
  } catch (error) {
    if (error instanceof GithubIngressError) {
      throw error;
    }
    throw new Error("github ingress verification failed", { cause: error });
  }

  const dedupe = await reserveDedupe(dedupeDirectory, event);
  if (dedupe.status === "CONFLICT") {
    return {
      classification: "C2_SOURCE_REJECTED",
      reason: "delivery identity was previously reserved with a different authenticated payload digest",
      dedupe,
      event,
    };
  }

  // A durable decision is authoritative for this delivery identity. This
  // prevents a later policy edit from retroactively creating authority.
  if (dedupe.status === "DUPLICATE_SAME" && dedupe.record.state !== "RESERVED") {
    if (dedupe.record.state === "ACCEPTED" && dedupe.record.create_request && dedupe.record.derived_incident_id) {
      const currentPolicy = lookupPreExistingPolicy(event, policies);
      if (currentPolicy.kind === "MATCH" && currentPolicy.policy.policy_id === dedupe.record.policy_id && currentPolicy.policy.policy_version === dedupe.record.policy_version) {
        return {
          classification: "C2_SOURCE_SELECTED",
          dedupe,
          event,
          policy: currentPolicy.policy,
          incident_id: dedupe.record.derived_incident_id,
          create_request: dedupe.record.create_request,
        };
      }
      return {
        classification: "C2_SOURCE_REJECTED",
        reason: "duplicate already has a durable accepted incident reference; current policy is not the original policy version",
        dedupe,
        event,
        incident_id: dedupe.record.derived_incident_id,
      };
    }
    return {
      classification: "C2_SOURCE_REJECTED",
      reason: `duplicate already has a durable terminal decision: ${dedupe.record.decision ?? "REJECTED"}`,
      dedupe,
      event,
    };
  }

  const lookup = lookupPreExistingPolicy(event, policies);
  if (lookup.kind !== "MATCH") {
    const classification = lookup.kind === "NO_MATCH"
      ? "C2_NO_MATCHING_POLICY"
      : lookup.kind === "DISABLED" ? "C2_POLICY_DISABLED" : "C2_POLICY_STALE";
    const policy = "policy" in lookup ? lookup.policy : undefined;
    const reason = "reason" in lookup ? lookup.reason : "policy is disabled";
    await finalizeDedupe(dedupeDirectory, dedupe, {
      state: "REJECTED",
      decision: classification,
      reason,
      policy_id: policy?.policy_id,
      policy_version: policy?.policy_version,
    });
    return {
      classification,
      reason,
      dedupe,
      event,
      policy,
    } as C2IngressRejected;
  }

  const derived = (() => {
    try {
      return { value: deriveC1CreateRequest(event, lookup.policy) };
    } catch (error) {
      if (error instanceof C2TargetBindingError) return { error };
      throw error;
    }
  })();
  if ("error" in derived && derived.error) {
    await finalizeDedupe(dedupeDirectory, dedupe, {
      state: "REJECTED",
      decision: "C2_TARGET_NOT_BOUND",
      policy_id: lookup.policy.policy_id,
      policy_version: lookup.policy.policy_version,
    });
    return {
      classification: "C2_TARGET_NOT_BOUND",
      reason: derived.error.message,
      dedupe,
      event,
      policy: lookup.policy,
    };
  }

  const finalRecord = await finalizeDedupe(dedupeDirectory, dedupe, {
    state: "ACCEPTED",
    decision: "C2_SOURCE_SELECTED",
    policy_id: lookup.policy.policy_id,
    policy_version: lookup.policy.policy_version,
    derived_incident_id: derived.value.incident_id,
    create_request: derived.value.create_request,
  });
  const finalDedupe = { ...dedupe, record: finalRecord };
  return {
    classification: "C2_SOURCE_SELECTED",
    dedupe: finalDedupe,
    event,
    policy: lookup.policy,
    incident_id: derived.value.incident_id,
    create_request: derived.value.create_request,
  };
}
