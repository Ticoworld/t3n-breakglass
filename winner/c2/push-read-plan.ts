import type { NormalizedPushEvent } from "./types.js";
import { lookupPreExistingPushPolicy, type C2PushPolicyV2 } from "./push-policy.js";

export interface ImmutablePushReadPlan {
  repository: "Ticoworld/t3n-breakglass-sandbox";
  before_sha: string;
  after_sha: string;
  path: ".breakglass-c2/exposed-deploy-key";
}

export class PushPolicyMismatchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PushPolicyMismatchError";
  }
}

export class PushAuthorityEligibilityError extends Error {
  readonly code = "C2_PUSH_NOT_AUTHORITY_ELIGIBLE" as const;

  constructor(public readonly reasons: string[]) {
    super(`push is not authority eligible: ${reasons.join(", ")}`);
    this.name = "PushAuthorityEligibilityError";
  }
}

const ZERO_SHA = "0".repeat(40);

export function assertPushAuthorityEligible(event: NormalizedPushEvent): void {
  const reasons: string[] = [];
  if (event.created) reasons.push("created push");
  if (event.forced) reasons.push("forced push");
  if (event.deleted) reasons.push("deleted push");
  if (event.before === ZERO_SHA) reasons.push("zero before SHA");
  if (event.after === ZERO_SHA) reasons.push("zero after SHA");
  if (event.before === event.after) reasons.push("before and after SHAs are equal");
  if (reasons.length > 0) throw new PushAuthorityEligibilityError(reasons);
}

/**
 * Produces only immutable provider reads. The event supplies commit IDs; the
 * policy supplies the repository/ref/path. No event field can select a path.
 */
export function createImmutablePushReadPlan(
  event: NormalizedPushEvent,
  policy: C2PushPolicyV2,
  options: { allowLocalFixture?: boolean } = {},
): ImmutablePushReadPlan {
  assertPushAuthorityEligible(event);
  const lookup = lookupPreExistingPushPolicy(event, [policy], options);
  if (lookup.kind !== "MATCH") throw new PushPolicyMismatchError(lookup.kind === "DISABLED" ? "push policy is disabled" : lookup.reason);
  if (event.deleted || event.ref !== policy.ref || event.repository_id !== policy.repository_id || event.repository_full_name !== policy.repository_full_name) {
    throw new PushPolicyMismatchError("authenticated push does not match the exact policy repository/ref");
  }
  return {
    repository: policy.repository_full_name,
    before_sha: event.before,
    after_sha: event.after,
    path: policy.secret_path,
  };
}
