import { createHmac } from "node:crypto";
import type { RawGithubRequest } from "../c2/types.js";

export const TEST_SECRET = "c2-local-fixture-secret";
export const TEST_REPOSITORY = "Ticoworld/t3n-breakglass-sandbox";
export const TEST_DELIVERY_ID = "11111111-1111-4111-8111-111111111111";

export interface FixtureOverrides {
  action?: string;
  eventType?: string;
  deliveryId?: string;
  repositoryFullName?: string;
  repositoryId?: number;
  alertNumber?: number;
  secretType?: string;
  alertState?: string;
  createdAt?: string;
  extraAlert?: Record<string, unknown>;
  extraRepository?: Record<string, unknown>;
  extraPayload?: Record<string, unknown>;
}

export function signedFixture(overrides: FixtureOverrides = {}): RawGithubRequest {
  const payload = {
    action: overrides.action ?? "created",
    repository: {
      id: overrides.repositoryId ?? 42424242,
      full_name: overrides.repositoryFullName ?? TEST_REPOSITORY,
      ...overrides.extraRepository,
    },
    alert: {
      number: overrides.alertNumber ?? 17,
      secret_type: overrides.secretType ?? "openssh_private_key",
      state: overrides.alertState ?? "open",
      created_at: overrides.createdAt ?? "2026-09-05T10:00:00.000Z",
      ...overrides.extraAlert,
    },
    ...overrides.extraPayload,
  };
  const body = Buffer.from(JSON.stringify(payload), "utf8");
  return {
    headers: {
      "X-GitHub-Event": overrides.eventType ?? "secret_scanning_alert",
      "X-GitHub-Delivery": overrides.deliveryId ?? TEST_DELIVERY_ID,
      "X-Hub-Signature-256": `sha256=${createHmac("sha256", TEST_SECRET).update(body).digest("hex")}`,
    },
    body,
  };
}

export function withBody(request: RawGithubRequest, body: string): RawGithubRequest {
  return { ...request, body: Buffer.from(body, "utf8") };
}
