export type BrokerOwnershipState =
  | "CONFIRMED_OWNER"
  | "NON_OWNER_EARLY_CLAIM_LOST"
  | "NON_OWNER_CONFIRM_REJECTED"
  | "INVALID_INDETERMINATE";

export interface NormalizedBrokerOutcome {
  contender: string | null;
  state: BrokerOwnershipState;
  claim_outcome: string | null;
  ownership_confirmation: string | null;
  claim_id: string | null;
  claim_version: number | null;
  provider_credential_mint_count: number | null;
  destructive_call_count: number | null;
  delete_attempted: boolean | null;
  provider_calls_after_ownership_loss: number | null;
  reason: string;
}

export interface BrokerAdjudication {
  valid: boolean;
  confirmed_owner_count: number;
  safe_non_owner_count: number;
  owner_contender: string | null;
  outcomes: NormalizedBrokerOutcome[];
  reason: string;
}

type JsonObject = Record<string, any>;

function object(value: unknown): JsonObject {
  return value && typeof value === "object" && !Array.isArray(value) ? value as JsonObject : {};
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function positiveClaimVersion(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function numberOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function claimIdentity(value: unknown): { claim_id: string; claim_version: number } | null {
  const candidate = object(value);
  return nonEmptyString(candidate.claim_id) && positiveClaimVersion(candidate.claim_version)
    ? { claim_id: candidate.claim_id, claim_version: candidate.claim_version }
    : null;
}

function providerSafeForNonOwner(value: JsonObject): boolean {
  const tokenCount = value.provider_credential_mint_count;
  const destructiveCount = value.destructive_call_count;
  const deleteCount = value.delete_count;
  const deleteAttempted = value.delete_attempted;
  const providerCallsAfterLoss = value.provider_calls_after_ownership_loss;
  const destructiveCountsAreZero = (destructiveCount === undefined || destructiveCount === 0) && (deleteCount === undefined || deleteCount === 0);
  return value.token_minted === false && tokenCount === 0 && destructiveCountsAreZero &&
    (deleteAttempted === undefined || deleteAttempted === false) && providerCallsAfterLoss === 0;
}

function normalizedBase(value: JsonObject, state: BrokerOwnershipState, reason: string, identity: { claim_id: string; claim_version: number } | null = null): NormalizedBrokerOutcome {
  return {
    contender: nonEmptyString(value.contender) ? value.contender : null,
    state,
    claim_outcome: typeof value.claim_outcome === "string" ? value.claim_outcome : null,
    ownership_confirmation: typeof value.ownership_confirmation === "string" ? value.ownership_confirmation : null,
    claim_id: identity?.claim_id ?? null,
    claim_version: identity?.claim_version ?? null,
    provider_credential_mint_count: numberOrNull(value.provider_credential_mint_count),
    destructive_call_count: numberOrNull(value.destructive_call_count ?? value.delete_count),
    delete_attempted: typeof value.delete_attempted === "boolean" ? value.delete_attempted : null,
    provider_calls_after_ownership_loss: numberOrNull(value.provider_calls_after_ownership_loss),
    reason,
  };
}

function hasContender(value: JsonObject): boolean {
  return nonEmptyString(value.contender);
}

function hasNoConfirmationAfterEarlyLoss(value: JsonObject): boolean {
  // The live child omits ownership_confirmation.  The historical sanitized
  // R2 summary used this explicit marker instead of preserving an omitted
  // property.  Neither value is a confirmation result.
  return value.ownership_confirmation === undefined || value.ownership_confirmation === null || value.ownership_confirmation === "NOT_EMITTED_AFTER_EARLY_LOSS";
}

/**
 * Normalize one persisted broker result.  This is deliberately independent
 * of contender ordering and treats an early committed CLAIM_LOST as a
 * terminal non-owner; it does not require a synthetic confirm-claim call.
 */
export function adjudicateBrokerResult(value: unknown): NormalizedBrokerOutcome {
  const result = object(value);
  const claim = object(result.claim);
  if (!hasContender(result)) return normalizedBase(result, "INVALID_INDETERMINATE", "contender identity is missing");
  const ownerIdentity = claimIdentity(result.authority_loaded_target) ?? claimIdentity(object(result.claim_confirmation).detail);
  if (result.ownership_confirmation === "CONFIRMED" && result.claim_outcome === "CLAIM_WON" && claim.result !== "LOST" && ownerIdentity) {
    return normalizedBase(result, "CONFIRMED_OWNER", "persisted claim was confirmed as the owner", ownerIdentity);
  }

  const hasProposal = claimIdentity(result.claim_proposal) !== null;
  // Some persisted child results expose only the normalized claim_outcome;
  // when a claim result object is present it must agree with CLAIM_LOST.
  const claimWasLost = result.claim_outcome === "CLAIM_LOST" && (claim.result === undefined || claim.result === "LOST");
  if (claimWasLost && !hasProposal && hasNoConfirmationAfterEarlyLoss(result) && providerSafeForNonOwner(result)) {
    return normalizedBase(result, "NON_OWNER_EARLY_CLAIM_LOST", "claim-effect returned LOST before a confirmation-stage proposal", null);
  }

  const confirmation = object(result.claim_confirmation);
  if (result.claim_outcome === "CLAIM_LOST" && hasProposal && result.ownership_confirmation === "NOT_OWNER" && confirmation.result !== "CONFIRMED" && providerSafeForNonOwner(result)) {
    return normalizedBase(result, "NON_OWNER_CONFIRM_REJECTED", "provisional claim was rejected at confirmation", claimIdentity(result.claim_proposal));
  }

  let reason = "broker result did not match a safe ownership state";
  if (result.ownership_confirmation === "CONFIRMED" && result.claim_outcome !== "CLAIM_WON") reason = "confirmed ownership contradicts claim outcome";
  else if (result.claim_outcome === "CLAIM_WON" && result.ownership_confirmation !== "CONFIRMED") reason = "CLAIM_WON is missing persisted confirmation";
  else if (result.claim_outcome === "CLAIM_LOST" && !providerSafeForNonOwner(result)) reason = "non-owner crossed the provider authority boundary";
  else if (result.claim_outcome === undefined) reason = "claim outcome is missing";
  return normalizedBase(result, "INVALID_INDETERMINATE", reason, ownerIdentity);
}

/**
 * Adjudicate the complete broker race.  Exactly one confirmed owner is
 * required, and every other contender must be a safe terminal non-owner.
 */
export function adjudicateBrokerResults(values: readonly unknown[]): BrokerAdjudication {
  const outcomes = values.map(adjudicateBrokerResult);
  const owners = outcomes.filter((outcome) => outcome.state === "CONFIRMED_OWNER");
  const invalid = outcomes.filter((outcome) => outcome.state === "INVALID_INDETERMINATE");
  const safeNonOwners = outcomes.filter((outcome) => outcome.state === "NON_OWNER_EARLY_CLAIM_LOST" || outcome.state === "NON_OWNER_CONFIRM_REJECTED");
  const contenders = outcomes.map((outcome) => outcome.contender).filter((contender): contender is string => contender !== null);
  const uniqueContenders = new Set(contenders).size === contenders.length;
  const exactOwnerCount = owners.length === 1;
  const noInvalid = invalid.length === 0;
  const allOthersSafe = safeNonOwners.length === outcomes.length - owners.length;
  const valid = exactOwnerCount && noInvalid && allOthersSafe && uniqueContenders;
  return {
    valid,
    confirmed_owner_count: owners.length,
    safe_non_owner_count: safeNonOwners.length,
    owner_contender: owners.length === 1 ? owners[0].contender : null,
    outcomes,
    reason: valid ? "exactly one owner and all other contenders are safe non-owners" :
      owners.length !== 1 ? `expected exactly one confirmed owner, found ${owners.length}` :
        invalid.length > 0 ? "one or more broker outcomes are invalid or indeterminate" :
          !uniqueContenders ? "broker contender identities are not unique" :
          "one or more non-owner contenders are not provider-safe",
  };
}
