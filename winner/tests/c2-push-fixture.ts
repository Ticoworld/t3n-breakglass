import { createHash, createHmac } from "node:crypto";
import type { RawGithubRequest } from "../c2/types.js";
import {
  C2_PUSH_EVENT_TYPE,
  C2_PUSH_REF,
  C2_PUSH_REPOSITORY,
  C2_PUSH_REPOSITORY_ID,
} from "../c2/push-source.js";
import { buildC2PushPolicyV2, type C2PushPolicyV2 } from "../c2/push-policy.js";
import type { ImmutablePathObservation } from "../c2/push-transition.js";

export const PUSH_TEST_SECRET = "c2-push-local-fixture-secret";
export const PUSH_DELIVERY_ID = "22222222-2222-4222-8222-222222222222";
export const PUSH_BEFORE_SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
export const PUSH_AFTER_SHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
export const PUSH_PRIVATE_MATERIAL = "test-only-disposable-private-material";
export const PUSH_PRIVATE_MATERIAL_SHA256 = createHash("sha256").update(PUSH_PRIVATE_MATERIAL, "utf8").digest("hex");

export interface PushFixtureOverrides {
  eventType?: string;
  deliveryId?: string;
  repositoryId?: number;
  repositoryFullName?: string;
  ref?: string;
  before?: string;
  after?: string;
  deleted?: boolean;
  forced?: boolean;
  created?: boolean;
  senderLogin?: string;
  extraPayload?: Record<string, unknown>;
}

export function signedPush(overrides: PushFixtureOverrides = {}): RawGithubRequest {
  const payload = {
    ref: overrides.ref ?? C2_PUSH_REF,
    before: overrides.before ?? PUSH_BEFORE_SHA,
    after: overrides.after ?? PUSH_AFTER_SHA,
    created: overrides.created ?? false,
    deleted: overrides.deleted ?? false,
    forced: overrides.forced ?? false,
    repository: {
      id: overrides.repositoryId ?? C2_PUSH_REPOSITORY_ID,
      full_name: overrides.repositoryFullName ?? C2_PUSH_REPOSITORY,
    },
    sender: { login: overrides.senderLogin ?? "Ticoworld" },
    commits: [{ message: "ordinary commit message", modified: [".breakglass-c2/exposed-deploy-key"] }],
    ...overrides.extraPayload,
  };
  const body = Buffer.from(JSON.stringify(payload), "utf8");
  return {
    headers: {
      "X-GitHub-Event": overrides.eventType ?? C2_PUSH_EVENT_TYPE,
      "X-GitHub-Delivery": overrides.deliveryId ?? PUSH_DELIVERY_ID,
      "X-Hub-Signature-256": `sha256=${createHmac("sha256", PUSH_TEST_SECRET).update(body).digest("hex")}`,
    },
    body,
  };
}

export function withBody(request: RawGithubRequest, body: Uint8Array): RawGithubRequest {
  return { ...request, body };
}

export function fixturePolicy(overrides: Partial<C2PushPolicyV2> = {}): C2PushPolicyV2 {
  return buildC2PushPolicyV2({
    policy_id: "c2-push-local-policy",
    policy_version: 2,
    deploy_key_id: 987654321,
    expected_deploy_key_title: "c2-push-local-target",
    expected_read_only: true,
    expected_public_key_fingerprint: "SHA256/c2LocalFixtureFingerprint",
    expected_private_material_sha256: PUSH_PRIVATE_MATERIAL_SHA256,
    remediation_agent_did: "did:t3n:c2-push-local-agent",
    effect_broker_did: "did:t3n:c2-push-local-broker",
    ttl_secs: 900,
    enabled: true,
    actual_creation_timestamp: "2026-09-05T09:00:00.000Z",
    creation_commit_or_registry_identity: "local-fixture:c2-push-policy",
    provenance: {
      classification: "LOCAL_TEST_FIXTURE",
      creation_evidence: "local-fixture-only",
      enabled_before_event_proof: true,
    },
    ...overrides,
  });
}

export function observation(
  commit_sha: string,
  status: 200 | 404,
  content_sha256?: string,
): ImmutablePathObservation {
  return {
    repository: C2_PUSH_REPOSITORY,
    commit_sha,
    path: ".breakglass-c2/exposed-deploy-key",
    status,
    ...(content_sha256 === undefined ? {} : { content_sha256 }),
  };
}
