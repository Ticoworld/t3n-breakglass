export type ProviderClassification = "NOT_ATTEMPTED" | "PROVIDER_ACKNOWLEDGED" | "ATTEMPTED_OUTCOME_UNKNOWN" | "VERIFIED_ABSENT" | "VERIFIED_PRESENT";

export type ClaimResult = {
  result?: string;
  detail?: { action?: string; github_owner?: string; github_repo?: string; deploy_key_id?: number; claim_id?: string; claim_version?: number };
};

export function parseClaim(raw: unknown): { won: boolean; claim?: NonNullable<ClaimResult["detail"]>; result: unknown } {
  const result = typeof raw === "string" ? JSON.parse(raw) : raw;
  const typed = result as ClaimResult;
  if (typed.result !== "WON") return { won: false, result };
  const detail = typed.detail;
  if (!detail || detail.action !== "revoke_github_deploy_key" || !detail.github_owner || !detail.github_repo || typeof detail.deploy_key_id !== "number" || !Number.isSafeInteger(detail.deploy_key_id) || detail.deploy_key_id <= 0 || !detail.claim_id) {
    throw new Error("claim winner did not return a complete authority-loaded target");
  }
  return { won: true, claim: detail, result };
}

export function classifyProviderOutcome(deleteStatus: number | null, deleteTransportFailed: boolean, exactGetStatus: number | null, listContainsTarget: boolean): ProviderClassification {
  if (deleteStatus === null && !deleteTransportFailed) return "NOT_ATTEMPTED";
  if (exactGetStatus === 404 && !listContainsTarget) return "VERIFIED_ABSENT";
  if (deleteTransportFailed) return "ATTEMPTED_OUTCOME_UNKNOWN";
  if (deleteStatus === 204) return "PROVIDER_ACKNOWLEDGED";
  return "VERIFIED_PRESENT";
}

export function destructiveRetryAllowed(_classification: ProviderClassification): false { return false; }

export function targetMustComeFromClaim(input: unknown, claim: NonNullable<ClaimResult["detail"]>): boolean {
  return input === undefined && claim.action === "revoke_github_deploy_key" && Boolean(claim.github_owner && claim.github_repo && claim.deploy_key_id);
}

export function processMustRefusePat(environment: NodeJS.ProcessEnv): boolean { return Boolean(environment.GITHUB_PAT); }
