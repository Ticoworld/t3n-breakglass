import { createHash } from "node:crypto";
import { TextDecoder } from "node:util";
import { GithubIngressError, verifyGithubWebhookSignature } from "./github-source.js";
import type { NormalizedPushEvent, RawGithubRequest } from "./types.js";

export const C2_PUSH_EVENT_TYPE = "push" as const;
export const C2_PUSH_REPOSITORY_ID = 1350596128 as const;
export const C2_PUSH_REPOSITORY = "Ticoworld/t3n-breakglass-sandbox" as const;
export const C2_PUSH_REF = "refs/heads/c2-breakglass-demo" as const;
export const C2_PUSH_SECRET_PATH = ".breakglass-c2/exposed-deploy-key" as const;

function header(headers: Record<string, string | undefined>, name: string): string | undefined {
  const expected = name.toLowerCase();
  return Object.entries(headers).find(([key]) => key.toLowerCase() === expected)?.[1];
}

function requiredHeader(headers: Record<string, string | undefined>, name: string): string {
  const value = header(headers, name);
  if (!value) throw new GithubIngressError("MISSING_HEADER", `${name} is required`);
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function requiredString(value: unknown, field: string, maxLength = 256): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maxLength) {
    throw new GithubIngressError("MALFORMED_PAYLOAD", `${field} must be a bounded non-empty string`);
  }
  return value;
}

function requiredSha(value: unknown, field: string, allowZero: boolean): string {
  const sha = requiredString(value, field, 40);
  if (!/^[0-9a-f]{40}$/i.test(sha) || (!allowZero && /^0+$/i.test(sha))) {
    throw new GithubIngressError("MALFORMED_PAYLOAD", `${field} must be a valid ${allowZero ? "" : "non-zero "}40-hex SHA`);
  }
  return sha.toLowerCase();
}

function requiredBoolean(value: unknown, field: string): boolean {
  if (typeof value !== "boolean") throw new GithubIngressError("MALFORMED_PAYLOAD", `${field} must be boolean`);
  return value;
}

function decodeVerifiedBody(body: Uint8Array): unknown {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(body);
  } catch {
    throw new GithubIngressError("MALFORMED_BODY", "verified body is not valid UTF-8");
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new GithubIngressError("MALFORMED_BODY", "verified body is not valid JSON");
  }
}

/**
 * Push has its own normalizer. Authentication is shared with C2-A, but no
 * secret-scanning fields or semantics are accepted here.
 */
export function normalizeVerifiedPushEvent(
  request: RawGithubRequest,
  webhookSecret: string,
): NormalizedPushEvent {
  verifyGithubWebhookSignature(request, webhookSecret);

  const eventType = requiredHeader(request.headers, "x-github-event");
  if (eventType !== C2_PUSH_EVENT_TYPE) {
    throw new GithubIngressError("UNEXPECTED_EVENT_TYPE", "only the push event is allowlisted");
  }
  const deliveryId = requiredHeader(request.headers, "x-github-delivery");
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(deliveryId)) {
    throw new GithubIngressError("MALFORMED_DELIVERY_ID", "X-GitHub-Delivery must be a GUID");
  }

  const payload = decodeVerifiedBody(request.body);
  if (!isRecord(payload)) throw new GithubIngressError("MALFORMED_PAYLOAD", "push JSON must be an object");
  const repository = payload.repository;
  const sender = payload.sender;
  if (!isRecord(repository) || !isRecord(sender)) {
    throw new GithubIngressError("MALFORMED_PAYLOAD", "repository and sender objects are required");
  }

  if (repository.id !== C2_PUSH_REPOSITORY_ID) {
    throw new GithubIngressError("WRONG_REPOSITORY", "repository.id is not the frozen repository");
  }
  if (repository.full_name !== C2_PUSH_REPOSITORY) {
    throw new GithubIngressError("WRONG_REPOSITORY", "repository.full_name is not the frozen repository");
  }
  if (payload.ref !== C2_PUSH_REF) {
    throw new GithubIngressError("WRONG_REF", "ref is not the frozen branch");
  }
  if (payload.deleted !== false) {
    throw new GithubIngressError("UNSAFE_PUSH", "deleted pushes are not accepted");
  }

  return {
    provider: "github",
    event_type: C2_PUSH_EVENT_TYPE,
    action: C2_PUSH_EVENT_TYPE,
    delivery_id: deliveryId,
    repository_id: C2_PUSH_REPOSITORY_ID,
    repository_full_name: C2_PUSH_REPOSITORY,
    ref: C2_PUSH_REF,
    before: requiredSha(payload.before, "before", true),
    after: requiredSha(payload.after, "after", false),
    deleted: false,
    forced: requiredBoolean(payload.forced, "forced"),
    created: requiredBoolean(payload.created, "created"),
    sender_login: requiredString(sender.login, "sender.login"),
    raw_body_sha256: createHash("sha256").update(Buffer.from(request.body)).digest("hex"),
  };
}
