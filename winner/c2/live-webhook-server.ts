import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { writeAtomicJson } from "../scripts/result-file.js";
import { reserveDedupe } from "./dedupe.js";
import { GithubIngressError } from "./github-source.js";
import { normalizeVerifiedPushEvent } from "./push-source.js";

export const C2_B0_ROUTE = "/c2-b0/github-push";
export const C2_B0_MAX_BODY_BYTES = 1_048_576;

export interface C2B0LiveServerConfig {
  webhookSecret: string;
  capturePath: string;
  dedupeDirectory: string;
  route?: string;
}

function safeRequestMetadata(request: IncomingMessage): Record<string, unknown> {
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

async function readBoundedBody(request: IncomingMessage, limit: number): Promise<Uint8Array | null> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > limit) return null;
    chunks.push(buffer);
  }
  return Buffer.concat(chunks, size);
}

function response(response: ServerResponse, status: number, message: string): void {
  response.statusCode = status;
  response.setHeader("content-type", "text/plain; charset=utf-8");
  response.end(message);
}

/**
 * B0-only receiver. It authenticates and captures one delivery, then stops.
 * It never calls the source reader, immutable transition verifier, or C1 path.
 */
export function createC2B0LiveWebhookServer(config: C2B0LiveServerConfig): Server {
  if (!config.webhookSecret) throw new Error("C2_WEBHOOK_SECRET is required");
  const route = config.route ?? C2_B0_ROUTE;

  return createServer(async (request, reply) => {
    if (request.method !== "POST" || request.url !== route) {
      request.resume();
      response(reply, 404, "not found");
      return;
    }

    const body = await readBoundedBody(request, C2_B0_MAX_BODY_BYTES);
    if (body === null) {
      response(reply, 413, "request too large");
      return;
    }

    let event;
    try {
      event = normalizeVerifiedPushEvent({ headers: request.headers as Record<string, string | undefined>, body }, config.webhookSecret);
    } catch (error) {
      const status = error instanceof GithubIngressError && ["MISSING_SIGNATURE", "MALFORMED_SIGNATURE", "INVALID_SIGNATURE"].includes(error.code) ? 401 : 400;
      response(reply, status, "delivery rejected");
      return;
    }

    const dedupe = await reserveDedupe(config.dedupeDirectory, event);
    const captured = {
      received_at: new Date().toISOString(),
      request: safeRequestMetadata(request),
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
      normalized: {
        repository_id: event.repository_id,
        repository_full_name: event.repository_full_name,
        ref: event.ref,
        before: event.before,
        after: event.after,
        created: event.created,
        deleted: event.deleted,
        forced: event.forced,
        sender_login: event.sender_login,
      },
      signature_verified: true,
      raw_body_persisted: false,
      webhook_secret_persisted: false,
      authority_processing_attempted: false,
      authority_eligible: false,
      authority_reason: "B0_DELIVERY_ONLY",
      source_reader_calls: 0,
      c1_request_created: false,
      dedupe: { status: dedupe.status, key: dedupe.key },
    };
    await writeAtomicJson(config.capturePath, captured);
    response(reply, 202, "delivery captured");
  });
}
