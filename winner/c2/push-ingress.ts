import type { C1CreateRequest, DedupeResult, NormalizedPushEvent, RawGithubRequest } from "./types.js";
import { reserveDedupe, finalizeDedupe } from "./dedupe.js";
import { normalizeVerifiedPushEvent } from "./push-source.js";
import { lookupPreExistingPushPolicy, type C2PushPolicyV2 } from "./push-policy.js";
import { createImmutablePushReadPlan, PushAuthorityEligibilityError, type ImmutablePushReadPlan } from "./push-read-plan.js";
import { derivePushC1CreateRequest } from "./push-c1.js";
import { verifyPushSecretTransition, type ImmutablePathObservation, type PushTransitionClassification } from "./push-transition.js";

export type PushIngressResult =
  | {
      classification: "C2_PUSH_SELECTED";
      dedupe: DedupeResult;
      event: NormalizedPushEvent;
      policy: C2PushPolicyV2;
      read_plan: ImmutablePushReadPlan | null;
      incident_id: string;
      create_request: C1CreateRequest;
      replayed: boolean;
    }
  | {
      classification: "C2_PUSH_REJECTED" | "C2_PUSH_NO_MATCHING_POLICY" | "C2_PUSH_POLICY_DISABLED" | "C2_PUSH_TRANSITION_REJECTED" | "C2_PUSH_NOT_AUTHORITY_ELIGIBLE";
      reason: string;
      dedupe: DedupeResult;
      event: NormalizedPushEvent;
      policy?: C2PushPolicyV2;
      transition?: PushTransitionClassification;
    };

/**
 * Local orchestration boundary. The observations represent the output of a
 * future Contents:read source-reader; this function itself performs no GitHub
 * or T3N calls.
 */
export async function processPushWebhook(
  request: RawGithubRequest,
  webhookSecret: string,
  dedupeDirectory: string,
  policies: readonly C2PushPolicyV2[],
  observations: { before: ImmutablePathObservation; after: ImmutablePathObservation },
  options: { allowLocalFixture?: boolean } = {},
): Promise<PushIngressResult> {
  const event = normalizeVerifiedPushEvent(request, webhookSecret);
  const dedupe = await reserveDedupe(dedupeDirectory, event);
  if (dedupe.status === "CONFLICT") {
    return {
      classification: "C2_PUSH_REJECTED",
      reason: "delivery identity was previously reserved with a different authenticated payload digest",
      dedupe,
      event,
    };
  }

  if (dedupe.status === "DUPLICATE_SAME" && dedupe.record.state !== "RESERVED") {
    if (dedupe.record.state === "ACCEPTED" && dedupe.record.create_request && dedupe.record.derived_incident_id) {
      const policy = policies.find((candidate) => candidate.policy_id === dedupe.record.policy_id && candidate.policy_version === dedupe.record.policy_version);
      if (policy) {
        return {
          classification: "C2_PUSH_SELECTED",
          dedupe,
          event,
          policy,
          read_plan: null,
          incident_id: dedupe.record.derived_incident_id,
          create_request: dedupe.record.create_request,
          replayed: true,
        };
      }
    }
    return {
      classification: "C2_PUSH_REJECTED",
      reason: `duplicate already has a durable terminal decision: ${dedupe.record.decision ?? "REJECTED"}`,
      dedupe,
      event,
    };
  }

  const lookup = lookupPreExistingPushPolicy(event, policies, options);
  if (lookup.kind !== "MATCH") {
    const classification = lookup.kind === "NO_MATCH" ? "C2_PUSH_NO_MATCHING_POLICY" : "C2_PUSH_POLICY_DISABLED";
    await finalizeDedupe(dedupeDirectory, dedupe, {
      state: "REJECTED",
      decision: classification,
      reason: lookup.kind === "NO_MATCH" ? lookup.reason : "policy is disabled",
      policy_id: "policy" in lookup ? lookup.policy.policy_id : undefined,
      policy_version: "policy" in lookup ? lookup.policy.policy_version : undefined,
    });
    return {
      classification,
      reason: lookup.kind === "NO_MATCH" ? lookup.reason : "policy is disabled",
      dedupe,
      event,
      policy: "policy" in lookup ? lookup.policy : undefined,
    };
  }

  const policy = lookup.policy;
  let readPlan: ImmutablePushReadPlan;
  try {
    readPlan = createImmutablePushReadPlan(event, policy, options);
  } catch (error) {
    if (error instanceof PushAuthorityEligibilityError) {
      await finalizeDedupe(dedupeDirectory, dedupe, { state: "REJECTED", decision: error.code, reason: error.message, policy_id: policy.policy_id, policy_version: policy.policy_version });
      return { classification: "C2_PUSH_NOT_AUTHORITY_ELIGIBLE", reason: error.message, dedupe, event, policy };
    }
    const reason = error instanceof Error ? error.message : "immutable read plan could not be created";
    await finalizeDedupe(dedupeDirectory, dedupe, { state: "REJECTED", decision: "C2_PUSH_REJECTED", reason, policy_id: policy.policy_id, policy_version: policy.policy_version });
    return { classification: "C2_PUSH_REJECTED", reason, dedupe, event, policy };
  }

  const transition = verifyPushSecretTransition(observations.before, observations.after, policy, readPlan);
  if (transition.classification !== "CAUSAL_SECRET_INTRODUCED") {
    const reason = `immutable content transition rejected: ${transition.classification}`;
    await finalizeDedupe(dedupeDirectory, dedupe, { state: "REJECTED", decision: "C2_PUSH_TRANSITION_REJECTED", reason, policy_id: policy.policy_id, policy_version: policy.policy_version });
    return { classification: "C2_PUSH_TRANSITION_REJECTED", reason, dedupe, event, policy, transition: transition.classification };
  }

  const derived = derivePushC1CreateRequest(event, policy, transition, options);
  const finalRecord = await finalizeDedupe(dedupeDirectory, dedupe, {
    state: "ACCEPTED",
    decision: "C2_PUSH_SELECTED",
    policy_id: policy.policy_id,
    policy_version: policy.policy_version,
    derived_incident_id: derived.incident_id,
    create_request: derived.create_request,
  });
  return {
    classification: "C2_PUSH_SELECTED",
    dedupe: { ...dedupe, record: finalRecord },
    event,
    policy,
    read_plan: readPlan,
    incident_id: derived.incident_id,
    create_request: derived.create_request,
    replayed: false,
  };
}
