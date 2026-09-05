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

/**
 * Produces only immutable provider reads. The event supplies commit IDs; the
 * policy supplies the repository/ref/path. No event field can select a path.
 */
export function createImmutablePushReadPlan(
  event: NormalizedPushEvent,
  policy: C2PushPolicyV2,
  options: { allowLocalFixture?: boolean } = {},
): ImmutablePushReadPlan {
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
