import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { TextDecoder } from "node:util";
import type { HeaderMap, NormalizedGithubEvent, RawGithubRequest } from "./types.js";
import {
  C2_SIGNAL_SECRET_TYPE,
  C2_SOURCE_ACTION,
  C2_SOURCE_EVENT_TYPE,
} from "./types.js";

export class GithubIngressError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message);
    this.name = "GithubIngressError";
  }
}

function header(headers: HeaderMap, name: string): string | undefined {
  const expected = name.toLowerCase();
  const entry = Object.entries(headers).find(([key]) => key.toLowerCase() === expected);
  return entry?.[1];
}

function requireHeader(headers: HeaderMap, name: string): string {
  const value = header(headers, name);
  if (!value) throw new GithubIngressError("MISSING_HEADER", `${name} is required`);
  return value;
}

function isDeliveryId(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new GithubIngressError("MALFORMED_PAYLOAD", `${field} must be a non-empty string`);
  }
  return value;
}

function requirePositiveInteger(value: unknown, field: string): number {
  if (!Number.isSafeInteger(value) || Number(value) <= 0) {
    throw new GithubIngressError("MALFORMED_PAYLOAD", `${field} must be a positive safe integer`);
  }
  return Number(value);
}

function parseIsoDate(value: unknown, field: string): string {
  const text = requireString(value, field);
  const time = Date.parse(text);
  if (!Number.isFinite(time)) throw new GithubIngressError("MALFORMED_PAYLOAD", `${field} must be an ISO date`);
  return new Date(time).toISOString();
}

/** Verify exact bytes before decoding or parsing the JSON body. */
export function verifyGithubWebhookSignature(request: RawGithubRequest, secret: string): void {
  if (!secret) throw new GithubIngressError("MISSING_WEBHOOK_SECRET", "webhook secret is required");
  const supplied = header(request.headers, "x-hub-signature-256");
  if (!supplied) throw new GithubIngressError("MISSING_SIGNATURE", "X-Hub-Signature-256 is required");
  if (!/^sha256=[0-9a-f]{64}$/.test(supplied)) {
    throw new GithubIngressError("MALFORMED_SIGNATURE", "X-Hub-Signature-256 must be sha256=<64 lowercase hex characters>");
  }

  const expected = createHmac("sha256", secret).update(Buffer.from(request.body)).digest();
  const received = Buffer.from(supplied.slice("sha256=".length), "hex");
  if (received.length !== expected.length || !timingSafeEqual(received, expected)) {
    throw new GithubIngressError("INVALID_SIGNATURE", "webhook signature did not match the retained raw body");
  }
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

/** The only fields surviving normalization are mechanically checked facts. */
export function normalizeVerifiedGithubEvent(
  request: RawGithubRequest,
  secret: string,
): NormalizedGithubEvent {
  verifyGithubWebhookSignature(request, secret);

  const eventType = requireHeader(request.headers, "x-github-event");
  if (eventType !== C2_SOURCE_EVENT_TYPE) {
    throw new GithubIngressError("UNEXPECTED_EVENT_TYPE", `event ${eventType} is not allowlisted`);
  }
  const deliveryId = requireHeader(request.headers, "x-github-delivery");
  if (!isDeliveryId(deliveryId)) throw new GithubIngressError("MALFORMED_DELIVERY_ID", "X-GitHub-Delivery must be a GUID");

  const payload = decodeVerifiedBody(request.body);
  if (!isRecord(payload)) throw new GithubIngressError("MALFORMED_PAYLOAD", "webhook JSON must be an object");
  if (payload.action !== C2_SOURCE_ACTION) {
    throw new GithubIngressError("UNEXPECTED_ACTION", "only a created secret-scanning alert is allowlisted");
  }
  const repository = payload.repository;
  const alert = payload.alert;
  if (!isRecord(repository) || !isRecord(alert)) {
    throw new GithubIngressError("MALFORMED_PAYLOAD", "repository and alert objects are required");
  }

  const repositoryId = requirePositiveInteger(repository.id, "repository.id");
  const repositoryFullName = requireString(repository.full_name, "repository.full_name");
  const secretType = requireString(alert.secret_type, "alert.secret_type");
  if (secretType !== C2_SIGNAL_SECRET_TYPE) {
    throw new GithubIngressError("UNEXPECTED_SECRET_TYPE", "the policy only accepts OpenSSH private-key alerts");
  }
  if (alert.state !== "open") {
    throw new GithubIngressError("UNEXPECTED_ALERT_STATE", "the policy only accepts open created alerts");
  }

  return {
    provider: "github",
    event_type: C2_SOURCE_EVENT_TYPE,
    action: C2_SOURCE_ACTION,
    delivery_id: deliveryId,
    repository_id: repositoryId,
    repository_full_name: repositoryFullName,
    alert_number: requirePositiveInteger(alert.number, "alert.number"),
    secret_type: C2_SIGNAL_SECRET_TYPE,
    alert_state: "open",
    source_event_time: parseIsoDate(alert.created_at, "alert.created_at"),
    raw_body_sha256: createHash("sha256").update(Buffer.from(request.body)).digest("hex"),
  };
}
