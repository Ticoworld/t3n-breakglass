import type { C1CreateRequest, DedupeResult, NormalizedPushEvent, RawGithubRequest } from "./types.js";
import { reserveDedupe, finalizeDedupe } from "./dedupe.js";
import { normalizeVerifiedPushEvent } from "./push-source.js";
import { lookupPreExistingPushPolicy, type C2PushPolicyV2, type PushPolicyLookupOptions } from "./push-policy.js";
import { createImmutablePushReadPlan, PushAuthorityEligibilityError, type ImmutablePushReadPlan } from "./push-read-plan.js";
import { derivePushC1CreateRequest } from "./push-c1.js";
import { verifyPushSecretTransition, type ImmutablePathObservation, type PushTransitionClassification } from "./push-transition.js";

export type PushIngressResult =
  | {
      classification: "C2_PUSH_SELECTED";
      dedupe: DedupeResult;
      event: NormalizedPushEvent;
      policy?: C2PushPolicyV2;
      read_plan: ImmutablePushReadPlan | null;
      incident_id: string;
      create_request: C1CreateRequest;
      replayed: boolean;
      authority_rederived: boolean;
      source_reads: number;
      receipt_replay?: boolean;
    }
  | {
      classification: "C2_PUSH_REJECTED" | "C2_PUSH_NO_MATCHING_POLICY" | "C2_PUSH_POLICY_DISABLED" | "C2_PUSH_POLICY_AMBIGUOUS" | "C2_PUSH_TRANSITION_REJECTED" | "C2_PUSH_NOT_AUTHORITY_ELIGIBLE";
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
  options: PushPolicyLookupOptions = {},
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
    if (dedupe.record.state === "ACCEPTED") {
      const receipt = validateAcceptedReceipt(dedupe.record, event, dedupe.key);
      if (!receipt.valid) return { classification: "C2_PUSH_REJECTED", reason: receipt.reason, dedupe, event };
      if (duplicateNonRetiredPolicyIdentity(policies, dedupe.record.policy_id!, options)) {
        return { classification: "C2_PUSH_POLICY_AMBIGUOUS", reason: "durable replay references a duplicated non-retired policy identity; refusing to select by input order", dedupe, event };
      }
      return {
        classification: "C2_PUSH_SELECTED",
        dedupe,
        event,
        read_plan: null,
        incident_id: dedupe.record.derived_incident_id!,
        create_request: dedupe.record.create_request!,
        replayed: true,
        authority_rederived: false,
        source_reads: 0,
        receipt_replay: true,
      };
    }
    return {
      classification: "C2_PUSH_REJECTED",
      reason: `duplicate already has a durable terminal decision: ${dedupe.record.decision ?? "REJECTED"}`,
      dedupe,
      event,
    };
  }

  if (dedupe.status === "DUPLICATE_SAME" && dedupe.record.state === "RESERVED") {
    return { classification: "C2_PUSH_REJECTED", reason: "duplicate delivery has an unresolved durable reservation; no accepted replay is available", dedupe, event };
  }

  const lookup = lookupPreExistingPushPolicy(event, policies, options);
  if (lookup.kind !== "MATCH") {
    const classification = lookup.kind === "NO_MATCH" ? "C2_PUSH_NO_MATCHING_POLICY" : lookup.kind === "AMBIGUOUS" ? "C2_PUSH_POLICY_AMBIGUOUS" : "C2_PUSH_POLICY_DISABLED";
    const reason = lookup.kind === "NO_MATCH" || lookup.kind === "AMBIGUOUS" ? lookup.reason : "policy is disabled";
    await finalizeDedupe(dedupeDirectory, dedupe, {
      state: "REJECTED",
      decision: classification,
      reason,
      policy_id: "policy" in lookup ? lookup.policy.policy_id : undefined,
      policy_version: "policy" in lookup ? lookup.policy.policy_version : undefined,
    });
    return {
      classification,
      reason,
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
    authority_rederived: true,
    source_reads: 2,
  };
}

function isStoredCreateRequest(value: unknown, incidentId: string): value is C1CreateRequest {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const request = value as Record<string, unknown>;
  const keys = Object.keys(request).sort().join(",");
  return keys === "deploy_key_id,effect_broker_did,incident_id,remediation_agent_did,ttl_secs" &&
    request.incident_id === incidentId && typeof request.remediation_agent_did === "string" && request.remediation_agent_did.length > 0 &&
    typeof request.effect_broker_did === "string" && request.effect_broker_did.length > 0 &&
    typeof request.deploy_key_id === "number" && Number.isSafeInteger(request.deploy_key_id) && request.deploy_key_id > 0 &&
    typeof request.ttl_secs === "number" && Number.isSafeInteger(request.ttl_secs) && request.ttl_secs > 0 && request.ttl_secs <= 86_400;
}

function validateAcceptedReceipt(record: DedupeResult["record"], event: NormalizedPushEvent, expectedDedupeKey: string): { valid: boolean; reason: string } {
  if (record.state !== "ACCEPTED") return { valid: false, reason: "durable delivery is not an accepted receipt" };
  const expectedSourceEventId = `${event.delivery_id}:${event.event_type}:${event.repository_id}:${event.repository_full_name}`;
  const identity = record.event_identity;
  if (!identity || record.dedupe_key !== expectedDedupeKey || record.source_event_id !== expectedSourceEventId || identity.delivery_id !== event.delivery_id || identity.event_type !== event.event_type || identity.repository_full_name !== event.repository_full_name) {
    return { valid: false, reason: "durable accepted receipt source identity is corrupted" };
  }
  if (typeof record.source_event_digest !== "string" || !/^[0-9a-f]{64}$/i.test(record.source_event_digest)) return { valid: false, reason: "durable accepted receipt has no valid source-event digest" };
  const policyVersion = record.policy_version;
  if (typeof record.policy_id !== "string" || record.policy_id.length === 0 || typeof policyVersion !== "number" || !Number.isSafeInteger(policyVersion) || policyVersion <= 0) return { valid: false, reason: "durable accepted receipt has incomplete policy identity/version" };
  if (record.decision !== "C2_PUSH_SELECTED") return { valid: false, reason: "durable accepted receipt has no accepted decision" };
  if (typeof record.derived_incident_id !== "string" || record.derived_incident_id.length === 0) return { valid: false, reason: "durable accepted receipt has no incident identity" };
  if (!isStoredCreateRequest(record.create_request, record.derived_incident_id)) return { valid: false, reason: "durable accepted receipt has no exact C1 create request" };
  return { valid: true, reason: "durable accepted receipt is complete" };
}

function duplicateNonRetiredPolicyIdentity(
  policies: readonly C2PushPolicyV2[],
  policyId: string,
  options: PushPolicyLookupOptions,
): boolean {
  return policies.filter((candidate) => candidate.policy_id === policyId && options.retiredPolicyIds?.has(candidate.policy_id) !== true).length > 1;
}
