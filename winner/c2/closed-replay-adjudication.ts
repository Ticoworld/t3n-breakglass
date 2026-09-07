export type ClosedReplayBrokerState =
  | "SAFE_CLOSED_REPLAY_DENIED"
  | "SAFE_CLOSED_REPLAY_LOST"
  | "INVALID_CLOSED_REPLAY";

export interface ClosedReplayAdjudication {
  valid: boolean;
  state: ClosedReplayBrokerState;
  reason: string;
}

type JsonObject = Record<string, any>;

const EXPECTED_TARGET_ID = 162525303;
const EXPECTED_FINAL_CLASSIFICATION = "VERIFIED_ABSENT";
const EXPECTED_EXPIRY_NOTE = "incident expired according to cluster time";

export interface ClosedReplayAdjudicationOptions {
  expectedDeployKeyId?: number;
  expectedExpiryNote?: string;
}

function object(value: unknown): JsonObject {
  return value && typeof value === "object" && !Array.isArray(value) ? value as JsonObject : {};
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function effective(snapshot: unknown, field: string): unknown {
  const response = object(snapshot);
  const detail = object(response.detail);
  return response[field] ?? detail[field];
}

function exactClosedTerminal(snapshot: unknown, expectedDeployKeyId: number): { valid: boolean; reason: string } {
  const response = object(snapshot);
  if (response.result !== "FOUND") return { valid: false, reason: "terminal-before did not return FOUND" };
  if (effective(response, "state") !== "CLOSED") return { valid: false, reason: "terminal-before was not CLOSED" };
  if (effective(response, "effect_attempts") !== 1) return { valid: false, reason: "terminal-before effect_attempts was not exactly one" };
  if (effective(response, "final_result_classification") !== EXPECTED_FINAL_CLASSIFICATION) return { valid: false, reason: "terminal-before was not VERIFIED_ABSENT" };
  if (effective(response, "deploy_key_id") !== expectedDeployKeyId) return { valid: false, reason: "terminal-before target did not match the expected closed target" };
  if (!nonEmptyString(effective(response, "effect_claim_id"))) return { valid: false, reason: "terminal-before has no effect claim identity" };
  if (!nonEmptyString(effective(response, "effect_start_id"))) return { valid: false, reason: "terminal-before has no effect-start identity" };
  return { valid: true, reason: "terminal-before is an independently verified CLOSED/VERIFIED_ABSENT incident" };
}

function providerBoundarySafe(result: JsonObject): boolean {
  const deleteCount = result.delete_count;
  return result.token_minted === false && result.provider_credential_mint_count === 0 && result.destructive_call_count === 0 &&
    (deleteCount === undefined || deleteCount === 0) && result.delete_attempted === false &&
    result.provider_calls_after_ownership_loss === 0 && !Object.prototype.hasOwnProperty.call(result, "effect_token") &&
    !Object.prototype.hasOwnProperty.call(result, "effect_start") && !Object.prototype.hasOwnProperty.call(result, "authority_loaded_target");
}

function rawClaim(result: JsonObject): JsonObject | null {
  const claim = result.claim;
  if (!claim || typeof claim !== "object" || Array.isArray(claim)) return null;
  return claim as JsonObject;
}

function hasClaimIdentity(value: unknown): boolean {
  const candidate = object(value);
  return nonEmptyString(candidate.claim_id) && Number.isSafeInteger(candidate.claim_version) && candidate.claim_version > 0;
}

/**
 * CLOSED replay has a different trust boundary from a live ownership race:
 * an independently read terminal snapshot proves that this claim attempt is
 * a replay of an already completed incident.  A DENIED result is accepted
 * only for the documented expiry branch and only with zero provider authority.
 */
export function adjudicateClosedReplayBrokerResult(terminalBefore: unknown, brokerResult: unknown, options: ClosedReplayAdjudicationOptions = {}): ClosedReplayAdjudication {
  const terminal = exactClosedTerminal(terminalBefore, options.expectedDeployKeyId ?? EXPECTED_TARGET_ID);
  if (!terminal.valid) return { valid: false, state: "INVALID_CLOSED_REPLAY", reason: terminal.reason };

  const result = object(brokerResult);
  if (!nonEmptyString(result.contender)) return { valid: false, state: "INVALID_CLOSED_REPLAY", reason: "closed replay broker contender identity is missing" };
  if (!providerBoundarySafe(result)) return { valid: false, state: "INVALID_CLOSED_REPLAY", reason: "closed replay broker crossed the provider authority boundary" };
  if (result.ownership_confirmation === "CONFIRMED" || Object.prototype.hasOwnProperty.call(result, "claim_proposal") || hasClaimIdentity(result.authority_loaded_target)) {
    return { valid: false, state: "INVALID_CLOSED_REPLAY", reason: "closed replay exposed ownership or a claim proposal" };
  }

  const claim = rawClaim(result);
  if (!claim || claim.function !== "claim-effect" || claim.state !== "CLOSED") {
    return { valid: false, state: "INVALID_CLOSED_REPLAY", reason: "closed replay has no exact CLOSED claim-effect response" };
  }
  if (claim.result === "DENIED" && result.claim_outcome === "CLAIM_DENIED") {
    if (claim.note !== (options.expectedExpiryNote ?? EXPECTED_EXPIRY_NOTE)) return { valid: false, state: "INVALID_CLOSED_REPLAY", reason: "DENIED replay note was not the documented expiry denial" };
    if (hasClaimIdentity(claim.detail)) return { valid: false, state: "INVALID_CLOSED_REPLAY", reason: "DENIED replay exposed a claim identity" };
    return { valid: true, state: "SAFE_CLOSED_REPLAY_DENIED", reason: EXPECTED_EXPIRY_NOTE };
  }
  if (claim.result === "LOST" && result.claim_outcome === "CLAIM_LOST") {
    if (hasClaimIdentity(claim.detail)) return { valid: false, state: "INVALID_CLOSED_REPLAY", reason: "LOST replay exposed a claim identity" };
    return { valid: true, state: "SAFE_CLOSED_REPLAY_LOST", reason: "closed replay claim was lost without provider authority" };
  }
  return { valid: false, state: "INVALID_CLOSED_REPLAY", reason: "closed replay claim result/outcome was not a supported terminal denial or loss" };
}

const TERMINAL_FIELDS = [
  "action",
  "github_owner",
  "github_repo",
  "deploy_key_id",
  "remediation_agent_did",
  "effect_broker_did",
  "effect_attempts",
  "reservation_id",
  "reservation_version",
  "effect_claim_id",
  "effect_claim_version",
  "effect_start_id",
  "final_result_classification",
  "state",
] as const;

export function closedTerminalAuthorityProjection(snapshot: unknown): JsonObject {
  const projected: JsonObject = {};
  for (const field of TERMINAL_FIELDS) projected[field] = effective(snapshot, field) ?? null;
  return projected;
}

export function closedTerminalAuthorityUnchanged(before: unknown, after: unknown): boolean {
  return JSON.stringify(closedTerminalAuthorityProjection(before)) === JSON.stringify(closedTerminalAuthorityProjection(after));
}
