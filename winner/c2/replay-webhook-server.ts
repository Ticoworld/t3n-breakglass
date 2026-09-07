import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { writeAtomicJson } from "../scripts/result-file.js";
import { GithubIngressError } from "./github-source.js";
import { normalizeVerifiedPushEvent } from "./push-source.js";
import type { NormalizedPushEvent, RawGithubRequest } from "./types.js";

export const R2B_REPLAY_ROUTE = "/c2-b0/github-push";
export const R2B_MAX_BODY_BYTES = 1_048_576;
const ZERO_SHA = "0".repeat(40);

export interface R2BReplayServerConfig {
  webhookSecret: string;
  capturePath: string;
  expectedDeliveryId: string;
  expectedBefore: string;
  expectedAfter: string;
  route?: string;
}

export interface R2BReplayCapture {
  received_at: string;
  request: {
    method: string | null;
    url: string | null;
    remote_address: string | null;
    user_agent: string | null;
    content_type: string | null;
    content_length: number | null;
  };
  delivery_id: string;
  event: "push";
  repository_id: number;
  repository_full_name: string;
  ref: string;
  before: string;
  after: string;
  created: boolean;
  forced: boolean;
  deleted: false;
  raw_body_sha256: string;
  signature_verified: true;
  raw_body_persisted: false;
  webhook_secret_persisted: false;
  authority_processing_attempted: false;
  source_reader_calls: 0;
  c1_request_created: false;
  redelivery: true;
  classification: "R2B_REDELIVERY_CAPTURED";
}

export interface R2BReplayServerHandle {
  server: Server;
  getCapture(): { request: RawGithubRequest; event: NormalizedPushEvent; evidence: R2BReplayCapture } | null;
  close(): Promise<void>;
}

function requestMetadata(request: IncomingMessage): R2BReplayCapture["request"] {
  const contentLength = request.headers["content-length"];
  const parsedLength = typeof contentLength === "string" && /^\d+$/.test(contentLength) ? Number(contentLength) : null;
  return {
    method: request.method ?? null,
    url: request.url ?? null,
    remote_address: request.socket.remoteAddress ?? null,
    user_agent: typeof request.headers["user-agent"] === "string" ? request.headers["user-agent"].slice(0, 256) : null,
    content_type: typeof request.headers["content-type"] === "string" ? request.headers["content-type"].slice(0, 128) : null,
    content_length: parsedLength,
  };
}

async function readBoundedBody(request: IncomingMessage): Promise<Buffer | null> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > R2B_MAX_BODY_BYTES) return null;
    chunks.push(buffer);
  }
  return Buffer.concat(chunks, size);
}

function reply(response: ServerResponse, status: number, body: string): void {
  response.statusCode = status;
  response.setHeader("content-type", "text/plain; charset=utf-8");
  response.end(body);
}

function isExpectedEvent(event: NormalizedPushEvent, config: R2BReplayServerConfig): boolean {
  return event.delivery_id === config.expectedDeliveryId &&
    event.before === config.expectedBefore.toLowerCase() &&
    event.after === config.expectedAfter.toLowerCase() &&
    event.created === false && event.forced === false && event.deleted === false;
}

/**
 * R2B-only receiver. It authenticates exactly one GitHub redelivery, writes
 * sanitized metadata, and keeps the authenticated bytes only in process
 * memory for the subsequent durable-receipt replay call.
 */
export function createR2BReplayWebhookServer(config: R2BReplayServerConfig): R2BReplayServerHandle {
  if (!config.webhookSecret) throw new Error("webhook secret is required");
  const route = config.route ?? R2B_REPLAY_ROUTE;
  let captured: { request: RawGithubRequest; event: NormalizedPushEvent; evidence: R2BReplayCapture } | null = null;

  const server = createServer(async (request, response) => {
    if (request.method !== "POST" || request.url !== route) {
      request.resume();
      reply(response, 404, "not found");
      return;
    }
    if (captured) {
      request.resume();
      reply(response, 409, "replay already captured");
      return;
    }

    const body = await readBoundedBody(request);
    if (body === null) {
      reply(response, 413, "request too large");
      return;
    }

    let event: NormalizedPushEvent;
    try {
      event = normalizeVerifiedPushEvent({ headers: request.headers as Record<string, string | undefined>, body }, config.webhookSecret);
      if (!isExpectedEvent(event, config)) throw new GithubIngressError("UNEXPECTED_REDELIVERY", "delivery is not the frozen historical R2 event");
    } catch (error) {
      const status = error instanceof GithubIngressError && ["MISSING_SIGNATURE", "MALFORMED_SIGNATURE", "INVALID_SIGNATURE"].includes(error.code) ? 401 : 400;
      reply(response, status, "delivery rejected");
      return;
    }

    const evidence: R2BReplayCapture = {
      received_at: new Date().toISOString(),
      request: requestMetadata(request),
      delivery_id: event.delivery_id,
      event: event.event_type,
      repository_id: event.repository_id,
      repository_full_name: event.repository_full_name,
      ref: event.ref,
      before: event.before,
      after: event.after,
      created: event.created,
      forced: event.forced,
      deleted: event.deleted,
      raw_body_sha256: event.raw_body_sha256,
      signature_verified: true,
      raw_body_persisted: false,
      webhook_secret_persisted: false,
      authority_processing_attempted: false,
      source_reader_calls: 0,
      c1_request_created: false,
      redelivery: true,
      classification: "R2B_REDELIVERY_CAPTURED",
    };
    captured = { request: { headers: request.headers as Record<string, string | undefined>, body }, event, evidence };
    await writeAtomicJson(config.capturePath, evidence);
    reply(response, 202, "redelivery captured");
  });

  return {
    server,
    getCapture: () => captured,
    close: () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}

export function authorityEligibleR2BReplay(event: NormalizedPushEvent): boolean {
  return event.created === false && event.forced === false && event.deleted === false && event.before !== ZERO_SHA && event.after !== ZERO_SHA && event.before !== event.after;
}
