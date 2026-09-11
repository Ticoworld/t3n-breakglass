import type { C1CreateRequest, DedupeResult, NormalizedPushEvent, RawGithubRequest } from "./types.js";
import { DEFAULT_RESERVED_RECOVERY_MS, finalizeDedupe, reserveDedupe } from "./dedupe.js";
import { normalizeVerifiedPushEvent } from "./push-source.js";
import { lookupPreExistingPushPolicy, pushPolicyContentHash, type C2PushPolicyV2, type PushPolicyLookupOptions } from "./push-policy.js";
import { createImmutablePushReadPlan, PushAuthorityEligibilityError, type ImmutablePushReadPlan } from "./push-read-plan.js";
import { derivePushC1CreateRequest, PushAuthorityBoundaryError } from "./push-c1.js";
import { verifyPushSecretTransition, type ImmutablePathObservation, type PushTransitionClassification } from "./push-transition.js";
import { pushEventBindingIdentity } from "./push-binding.js";
import type { GithubPushSourceReader, PushSourceReaderResult } from "./push-source-reader.js";

export class PolicyAlreadyBoundError extends Error {
  constructor(message = "policy is already bound to another verified event") {
    super(message);
    this.name = "PolicyAlreadyBoundError";
  }
}

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
      classification: "C2_PUSH_REJECTED" | "C2_PUSH_NO_MATCHING_POLICY" | "C2_PUSH_POLICY_DISABLED" | "C2_PUSH_POLICY_AMBIGUOUS" | "C2_PUSH_TRANSITION_REJECTED" | "C2_PUSH_NOT_AUTHORITY_ELIGIBLE" | "C2_PUSH_POLICY_ALREADY_BOUND";
      reason: string;
      dedupe: DedupeResult;
      event: NormalizedPushEvent;
      policy?: C2PushPolicyV2;
      transition?: PushTransitionClassification;
    };

/** Compatibility/test boundary with caller-supplied observations. */
export async function processPushWebhook(
  request: RawGithubRequest,
  webhookSecret: string,
  dedupeDirectory: string,
  policies: readonly C2PushPolicyV2[],
  observations: { before: ImmutablePathObservation; after: ImmutablePathObservation },
  options: PushPolicyLookupOptions = {},
): Promise<PushIngressResult> {
  return processPushWebhookWithObservationProvider(
    request,
    webhookSecret,
    dedupeDirectory,
    policies,
    async () => observations,
    options,
  );
}

/** Maintained boundary: immutable observations are produced by the reusable source reader. */
export async function processPushWebhookWithSourceReader(
  request: RawGithubRequest,
  webhookSecret: string,
  dedupeDirectory: string,
  policies: readonly C2PushPolicyV2[],
  sourceReader: Pick<GithubPushSourceReader, "readPlan">,
  options: PushPolicyLookupOptions = {},
): Promise<PushIngressResult> {
  return processPushWebhookWithObservationProvider(
    request,
    webhookSecret,
    dedupeDirectory,
    policies,
    async (readPlan) => {
      const result: PushSourceReaderResult = await sourceReader.readPlan(readPlan);
      return { before: result.before, after: result.after };
    },
    options,
  );
}

async function processPushWebhookWithObservationProvider(
  request: RawGithubRequest,
  webhookSecret: string,
  dedupeDirectory: string,
  policies: readonly C2PushPolicyV2[],
  readObservations: (readPlan: ImmutablePushReadPlan) => Promise<{ before: ImmutablePathObservation; after: ImmutablePathObservation }>,
  options: PushPolicyLookupOptions,
): Promise<PushIngressResult> {
  const event = normalizeVerifiedPushEvent(request, webhookSecret);
  const dedupe = await reserveDedupe(dedupeDirectory, event, {
    stateIntegrityKey: options.stateIntegrityKey,
    recoverReserved: options.recoverReserved,
  });
  if (dedupe.status === "CONFLICT") {
    return { classification: "C2_PUSH_REJECTED", reason: "delivery identity was previously reserved with a different authenticated payload digest", dedupe, event };
  }

  if (dedupe.status === "DUPLICATE_SAME" && dedupe.record.state === "ACCEPTED") {
    const receipt = validateAcceptedReceipt(dedupe.record, event, dedupe.key);
    if (!receipt.valid) return { classification: "C2_PUSH_REJECTED", reason: receipt.reason, dedupe, event };
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

  if (dedupe.status === "DUPLICATE_SAME" && dedupe.record.state === "REJECTED") {
    return {
      classification: "C2_PUSH_REJECTED",
      reason: "durable terminal decision is rejected and cannot be re-authorized",
      dedupe,
      event,
    };
  }

  const reservedRecoveryMs = options.reservedRecoveryMs ?? DEFAULT_RESERVED_RECOVERY_MS;
  const reservedRecoveryDue = dedupe.status === "DUPLICATE_SAME" && dedupe.record.state === "RESERVED" &&
    options.recoverReserved === true && Date.now() - Date.parse(dedupe.record.reserved_at!) >= reservedRecoveryMs;
  if (dedupe.status === "DUPLICATE_SAME" && dedupe.record.state === "RESERVED" && !reservedRecoveryDue) {
    return { classification: "C2_PUSH_REJECTED", reason: "duplicate delivery has an unresolved durable reservation; no accepted replay is available", dedupe, event };
  }
  const resumedReservation = reservedRecoveryDue;
  const finalizeOptions = { stateIntegrityKey: options.stateIntegrityKey, allowReservedRecovery: resumedReservation };

  const lookup = lookupPreExistingPushPolicy(event, policies, options);
  if (lookup.kind !== "MATCH") {
    const classification = lookup.kind === "NO_MATCH" ? "C2_PUSH_NO_MATCHING_POLICY" : lookup.kind === "AMBIGUOUS" ? "C2_PUSH_POLICY_AMBIGUOUS" : "C2_PUSH_POLICY_DISABLED";
    const reason = lookup.kind === "NO_MATCH" || lookup.kind === "AMBIGUOUS" ? lookup.reason : "policy is disabled";
    await finalizeDedupe(dedupeDirectory, dedupe, { state: "REJECTED", decision: classification, reason, policy_id: "policy" in lookup ? lookup.policy.policy_id : undefined, policy_version: "policy" in lookup ? lookup.policy.policy_version : undefined }, finalizeOptions);
    return { classification, reason, dedupe, event, policy: "policy" in lookup ? lookup.policy : undefined };
  }

  const policy = lookup.policy;
  let readPlan: ImmutablePushReadPlan;
  try {
    readPlan = createImmutablePushReadPlan(event, policy, options);
  } catch (error) {
    const reason = error instanceof Error ? error.message : "immutable read plan could not be created";
    const classification = error instanceof PushAuthorityEligibilityError ? "C2_PUSH_NOT_AUTHORITY_ELIGIBLE" : "C2_PUSH_REJECTED";
    await finalizeDedupe(dedupeDirectory, dedupe, { state: "REJECTED", decision: classification, reason, policy_id: policy.policy_id, policy_version: policy.policy_version }, finalizeOptions);
    return { classification, reason, dedupe, event, policy };
  }

  let observations: { before: ImmutablePathObservation; after: ImmutablePathObservation };
  try {
    observations = await readObservations(readPlan);
  } catch (error) {
    const reason = error instanceof Error ? error.message : "immutable source reads failed";
    await finalizeDedupe(dedupeDirectory, dedupe, { state: "REJECTED", decision: "C2_PUSH_REJECTED", reason: `immutable source reader failed: ${reason}`, policy_id: policy.policy_id, policy_version: policy.policy_version }, finalizeOptions);
    return { classification: "C2_PUSH_REJECTED", reason: `immutable source reader failed: ${reason}`, dedupe, event, policy };
  }

  const transition = verifyPushSecretTransition(observations.before, observations.after, policy, readPlan);
  if (transition.classification !== "CAUSAL_SECRET_INTRODUCED") {
    const reason = `immutable content transition rejected: ${transition.classification}`;
    await finalizeDedupe(dedupeDirectory, dedupe, { state: "REJECTED", decision: "C2_PUSH_TRANSITION_REJECTED", reason, policy_id: policy.policy_id, policy_version: policy.policy_version }, finalizeOptions);
    return { classification: "C2_PUSH_TRANSITION_REJECTED", reason, dedupe, event, policy, transition: transition.classification };
  }

  let derived: { incident_id: string; create_request: C1CreateRequest };
  try { derived = derivePushC1CreateRequest(event, policy, transition, options); }
  catch (error) {
    const reason = error instanceof Error ? error.message : "C1 authority derivation failed";
    await finalizeDedupe(dedupeDirectory, dedupe, { state: "REJECTED", decision: "C2_PUSH_REJECTED", reason, policy_id: policy.policy_id, policy_version: policy.policy_version }, finalizeOptions);
    return { classification: "C2_PUSH_REJECTED", reason, dedupe, event, policy };
  }

  const metadata = options.policyMetadata?.(policy) ?? { registryIdentity: policy.creation_commit_or_registry_identity, policyContentHash: pushPolicyContentHash(policy) };
  if (!metadata?.registryIdentity || !metadata.policyContentHash) {
    const reason = "policy registry metadata is missing";
    await finalizeDedupe(dedupeDirectory, dedupe, { state: "REJECTED", decision: "C2_PUSH_REJECTED", reason, policy_id: policy.policy_id, policy_version: policy.policy_version }, finalizeOptions);
    return { classification: "C2_PUSH_REJECTED", reason, dedupe, event, policy };
  }
  const bindingInput = {
    policy,
    event,
    transition,
    incidentId: derived.incident_id,
    dedupeKey: dedupe.key,
    registryIdentity: metadata.registryIdentity,
    policyContentHash: metadata.policyContentHash,
  };
  const eventBindingIdentity = pushEventBindingIdentity(bindingInput);
  if (options.requirePolicyBinding === true && !options.bindVerifiedPolicy) {
    const reason = "maintained ingress requires an atomic verified policy binding";
    await finalizeDedupe(dedupeDirectory, dedupe, { state: "REJECTED", decision: "C2_PUSH_REJECTED", reason, policy_id: policy.policy_id, policy_version: policy.policy_version }, finalizeOptions);
    return { classification: "C2_PUSH_REJECTED", reason, dedupe, event, policy };
  }
  if (options.bindVerifiedPolicy) {
    try {
      const binding = await options.bindVerifiedPolicy({ ...bindingInput, eventBindingIdentity });
      if (binding.eventBindingIdentity !== eventBindingIdentity) throw new Error("policy binding identity does not match the verified event");
    } catch (error) {
      if (!(error instanceof PolicyAlreadyBoundError)) throw error;
      const reason = error.message;
      await finalizeDedupe(dedupeDirectory, dedupe, { state: "REJECTED", decision: "C2_PUSH_POLICY_ALREADY_BOUND", reason, policy_id: policy.policy_id, policy_version: policy.policy_version }, finalizeOptions);
      return { classification: "C2_PUSH_POLICY_ALREADY_BOUND", reason, dedupe, event, policy };
    }
  }

  const finalRecord = await finalizeDedupe(dedupeDirectory, dedupe, {
    state: "ACCEPTED",
    decision: "C2_PUSH_SELECTED",
    policy_id: policy.policy_id,
    policy_version: policy.policy_version,
    registry_identity: metadata.registryIdentity,
    policy_content_hash: metadata.policyContentHash,
    event_binding_identity: eventBindingIdentity,
    action: policy.action,
    expected_target_title: policy.expected_deploy_key_title,
    derived_incident_id: derived.incident_id,
    create_request: derived.create_request,
  }, finalizeOptions);
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
  return Object.keys(request).sort().join(",") === "deploy_key_id,effect_broker_did,incident_id,remediation_agent_did,ttl_secs" &&
    request.incident_id === incidentId && typeof request.remediation_agent_did === "string" && request.remediation_agent_did.length > 0 &&
    typeof request.effect_broker_did === "string" && request.effect_broker_did.length > 0 &&
    typeof request.deploy_key_id === "number" && Number.isSafeInteger(request.deploy_key_id) && request.deploy_key_id > 0 &&
    typeof request.ttl_secs === "number" && Number.isSafeInteger(request.ttl_secs) && request.ttl_secs > 0 && request.ttl_secs <= 86_400;
}

function validateAcceptedReceipt(record: DedupeResult["record"], event: NormalizedPushEvent, expectedDedupeKey: string): { valid: boolean; reason: string } {
  if (record.state !== "ACCEPTED") return { valid: false, reason: "durable delivery is not an accepted receipt" };
  const expectedSourceEventId = `${event.delivery_id}:${event.event_type}:${event.repository_id}:${event.repository_full_name}`;
  const identity = record.event_identity;
  const normalized = record.normalized_event as Partial<NormalizedPushEvent>;
  if (!identity || record.dedupe_key !== expectedDedupeKey || record.source_event_id !== expectedSourceEventId || identity.delivery_id !== event.delivery_id || identity.event_type !== event.event_type || identity.repository_full_name !== event.repository_full_name || record.source_event_digest !== event.raw_body_sha256 || normalized.delivery_id !== event.delivery_id || normalized.event_type !== event.event_type || normalized.repository_id !== event.repository_id || normalized.repository_full_name !== event.repository_full_name || normalized.ref !== event.ref || normalized.before !== event.before || normalized.after !== event.after) return { valid: false, reason: "durable accepted receipt source identity is corrupted" };
  const policyVersion = record.policy_version;
  if (typeof record.policy_id !== "string" || record.policy_id.length === 0 || typeof policyVersion !== "number" || !Number.isSafeInteger(policyVersion) || policyVersion <= 0) return { valid: false, reason: "durable accepted receipt has incomplete policy identity/version" };
  if (typeof record.registry_identity !== "string" || typeof record.policy_content_hash !== "string" || typeof record.event_binding_identity !== "string" || typeof record.action !== "string") return { valid: false, reason: "durable accepted receipt has incomplete authority binding" };
  if (typeof record.expected_target_title !== "string" || record.expected_target_title.length === 0) return { valid: false, reason: "durable accepted receipt has no exact target title" };
  if (record.decision !== "C2_PUSH_SELECTED") return { valid: false, reason: "durable accepted receipt has no accepted decision" };
  if (typeof record.derived_incident_id !== "string" || record.derived_incident_id.length === 0) return { valid: false, reason: "durable accepted receipt has no incident identity" };
  if (!isStoredCreateRequest(record.create_request, record.derived_incident_id)) return { valid: false, reason: "durable accepted receipt has no exact C1 create request" };
  return { valid: true, reason: "durable accepted receipt is complete" };
}
