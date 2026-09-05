import type { ImmutablePushReadPlan } from "./push-read-plan.js";
import type { ImmutablePathObservation } from "./push-transition.js";
import { C2_PUSH_REPOSITORY } from "./push-source.js";

export interface PushSourceReaderTokenRequest {
  repositories: [typeof C2_PUSH_REPOSITORY];
  permissions: { contents: "read" };
}

export interface ImmutableContentReadOperation {
  method: "GET";
  repository: typeof C2_PUSH_REPOSITORY;
  path: string;
  ref: string;
}

/** The future installation-token request has no Administration or write scope. */
export function pushSourceReaderTokenRequest(): PushSourceReaderTokenRequest {
  return {
    repositories: [C2_PUSH_REPOSITORY],
    permissions: { contents: "read" },
  };
}

/** Exactly two immutable GETs; no mutable branch-head read is permitted. */
export function immutableContentReadOperations(plan: ImmutablePushReadPlan): [ImmutableContentReadOperation, ImmutableContentReadOperation] {
  return [
    { method: "GET", repository: plan.repository, path: plan.path, ref: plan.before_sha },
    { method: "GET", repository: plan.repository, path: plan.path, ref: plan.after_sha },
  ];
}

/**
 * A future network adapter may implement this interface. It must hash the
 * response body in memory and return only status/digest metadata.
 */
export interface PushImmutableContentReader {
  read(operation: ImmutableContentReadOperation): Promise<ImmutablePathObservation>;
}
