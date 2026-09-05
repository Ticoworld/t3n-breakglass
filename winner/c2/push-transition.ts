import { createHash } from "node:crypto";
import { C2_PUSH_REPOSITORY, C2_PUSH_SECRET_PATH } from "./push-source.js";
import type { C2PushPolicyV2 } from "./push-policy.js";

export type PushTransitionClassification =
  | "CAUSAL_SECRET_INTRODUCED"
  | "NO_SECRET_TRANSITION"
  | "SECRET_ALREADY_PRESENT_BEFORE"
  | "AFTER_MISSING"
  | "AFTER_DIGEST_MISMATCH"
  | "TARGET_POLICY_MISMATCH";

export interface ImmutablePathObservation {
  repository: string;
  commit_sha: string;
  path: string;
  status: 200 | 404;
  content_sha256?: string;
}

export interface PushTransitionResult {
  classification: PushTransitionClassification;
  before_digest: string | null;
  after_digest: string | null;
}

export interface ExpectedImmutableRefs {
  before_sha: string;
  after_sha: string;
}

/** Hash a dedicated secret buffer and overwrite the working copy afterward. */
export function digestPrivateMaterial(material: Uint8Array): string {
  const working = Buffer.from(material);
  try {
    return createHash("sha256").update(working).digest("hex");
  } finally {
    working.fill(0);
    if (Buffer.isBuffer(material)) material.fill(0);
  }
}

function isDigest(value: string | undefined): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function matchesTarget(observation: ImmutablePathObservation): boolean {
  return observation.repository === C2_PUSH_REPOSITORY && observation.path === C2_PUSH_SECRET_PATH && /^[0-9a-f]{40}$/i.test(observation.commit_sha);
}

/**
 * Compares only provider-returned digests/statuses. Secret bytes never enter
 * this function or its result.
 */
export function verifyPushSecretTransition(
  before: ImmutablePathObservation,
  after: ImmutablePathObservation,
  policy: C2PushPolicyV2,
  expectedRefs?: ExpectedImmutableRefs,
): PushTransitionResult {
  if (!matchesTarget(before) || !matchesTarget(after) ||
      (expectedRefs !== undefined && (before.commit_sha.toLowerCase() !== expectedRefs.before_sha.toLowerCase() || after.commit_sha.toLowerCase() !== expectedRefs.after_sha.toLowerCase()))) {
    return { classification: "TARGET_POLICY_MISMATCH", before_digest: before.content_sha256 ?? null, after_digest: after.content_sha256 ?? null };
  }

  const beforeDigest = before.status === 200 && isDigest(before.content_sha256) ? before.content_sha256 : null;
  const afterDigest = after.status === 200 && isDigest(after.content_sha256) ? after.content_sha256 : null;

  if (after.status === 404) return { classification: "AFTER_MISSING", before_digest: beforeDigest, after_digest: null };
  if (afterDigest !== policy.expected_private_material_sha256) {
    return { classification: "AFTER_DIGEST_MISMATCH", before_digest: beforeDigest, after_digest: afterDigest };
  }
  if (before.status === 200 && beforeDigest === policy.expected_private_material_sha256) {
    return { classification: "SECRET_ALREADY_PRESENT_BEFORE", before_digest: beforeDigest, after_digest: afterDigest };
  }
  if (before.status === 404 && before.content_sha256 === undefined) {
    return { classification: "CAUSAL_SECRET_INTRODUCED", before_digest: beforeDigest, after_digest: afterDigest };
  }
  if (before.status === 200 && beforeDigest !== null && beforeDigest !== policy.expected_private_material_sha256) {
    return { classification: "CAUSAL_SECRET_INTRODUCED", before_digest: beforeDigest, after_digest: afterDigest };
  }
  return { classification: "NO_SECRET_TRANSITION", before_digest: beforeDigest, after_digest: afterDigest };
}
