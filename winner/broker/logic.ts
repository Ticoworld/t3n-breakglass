export type ProviderClassification = "NOT_ATTEMPTED" | "PROVIDER_ACKNOWLEDGED" | "ATTEMPTED_OUTCOME_UNKNOWN" | "VERIFIED_ABSENT" | "VERIFIED_PRESENT";

export type ClaimIdentity = { claim_id?: string; claim_version?: number };
export type ClaimTarget = ClaimIdentity & { action?: string; github_owner?: string; github_repo?: string; deploy_key_id?: number };

export type ClaimResult = {
  result?: string;
  detail?: ClaimTarget;
};

function objectResult(raw: unknown): Record<string, unknown> {
  const value = typeof raw === "string" ? JSON.parse(raw) : raw;
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("C1 claim response was not a JSON object");
  return value as Record<string, unknown>;
}

function validClaimIdentity(detail: ClaimIdentity | undefined): detail is Required<ClaimIdentity> {
  return Boolean(detail && typeof detail.claim_id === "string" && detail.claim_id.length > 0 && typeof detail.claim_version === "number" && Number.isSafeInteger(detail.claim_version) && detail.claim_version > 0);
}

function hasOnlyKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).every((key) => keys.includes(key));
}

export function parseClaimProposal(raw: unknown): { proposed: boolean; claim?: Required<ClaimIdentity>; result: unknown } {
  const result = objectResult(raw);
  if (result.result !== "PROPOSED") return { proposed: false, result };
  const detail = result.detail && typeof result.detail === "object" && !Array.isArray(result.detail) ? result.detail as ClaimIdentity : undefined;
  if (!detail || !hasOnlyKeys(detail as Record<string, unknown>, ["claim_id", "claim_version"]) || !validClaimIdentity(detail)) throw new Error("claim proposal did not return only a complete claim identity");
  return { proposed: true, claim: detail, result };
}

export function parseClaimConfirmation(raw: unknown): { confirmed: boolean; target?: Required<ClaimTarget>; result: unknown } {
  const result = objectResult(raw);
  if (result.result !== "CONFIRMED") {
    const detail = result.detail;
    if (detail && typeof detail === "object" && !Array.isArray(detail) && Object.keys(detail).length > 0) throw new Error("non-owner claim confirmation exposed unexpected detail");
    return { confirmed: false, result };
  }
  const detail = result.detail && typeof result.detail === "object" && !Array.isArray(result.detail) ? result.detail as ClaimTarget : undefined;
  if (!detail || detail.action !== "revoke_github_deploy_key" || !detail.github_owner || !detail.github_repo || typeof detail.deploy_key_id !== "number" || !Number.isSafeInteger(detail.deploy_key_id) || detail.deploy_key_id <= 0 || !validClaimIdentity(detail)) {
    throw new Error("claim confirmation did not return a complete authority-loaded target");
  }
  return { confirmed: true, target: detail as Required<ClaimTarget>, result };
}

/** Compatibility parser for old unit fixtures; the live broker uses proposal + confirmation. */
export function parseClaim(raw: unknown): { won: boolean; claim?: Required<ClaimTarget>; result: unknown } {
  const result = objectResult(raw);
  if (result.result !== "WON") return { won: false, result };
  const detail = result.detail && typeof result.detail === "object" && !Array.isArray(result.detail) ? result.detail as ClaimTarget : undefined;
  if (!detail || detail.action !== "revoke_github_deploy_key" || !detail.github_owner || !detail.github_repo || typeof detail.deploy_key_id !== "number" || !Number.isSafeInteger(detail.deploy_key_id) || detail.deploy_key_id <= 0 || !validClaimIdentity(detail)) {
    throw new Error("claim winner did not return a complete authority-loaded target");
  }
  return { won: true, claim: detail as Required<ClaimTarget>, result };
}

export function classifyProviderOutcome(deleteStatus: number | null, deleteTransportFailed: boolean, exactGetStatus: number | null, listContainsTarget: boolean, listGetStatus: number | null, listBodyValid: boolean): ProviderClassification {
  if (deleteStatus === null && !deleteTransportFailed) return "NOT_ATTEMPTED";
  if (exactGetStatus === 404 && listGetStatus === 200 && listBodyValid && !listContainsTarget) return "VERIFIED_ABSENT";
  if (deleteTransportFailed) return "ATTEMPTED_OUTCOME_UNKNOWN";
  if (deleteStatus === 204) return "PROVIDER_ACKNOWLEDGED";
  return "VERIFIED_PRESENT";
}

export function destructiveRetryAllowed(_classification: ProviderClassification): false { return false; }

export function targetMustComeFromClaim(input: unknown, claim: Required<ClaimTarget>): boolean {
  return input === undefined && claim.action === "revoke_github_deploy_key" && Boolean(claim.github_owner && claim.github_repo && claim.deploy_key_id);
}

export function claimTargetMatchesConfiguredRepository(claim: Required<ClaimTarget>, owner: string, repository: string): boolean {
  return claim.github_owner === owner && claim.github_repo === repository;
}

export function processMustRefusePat(environment: NodeJS.ProcessEnv): boolean { return Boolean(environment.GITHUB_PAT); }
