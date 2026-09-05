import { createHash } from "node:crypto";
import { mkdir, open, readFile } from "node:fs/promises";
import path from "node:path";
import { writeAtomicJson } from "../scripts/result-file.js";
import type { C1CreateRequest, DedupeRecord, DedupeResult, NormalizedGithubEvent } from "./types.js";

export function dedupeKey(event: NormalizedGithubEvent): string {
  const identity = `${event.delivery_id}\n${event.event_type}\n${event.repository_id}\n${event.repository_full_name}`;
  return createHash("sha256").update(identity, "utf8").digest("hex");
}

function recordPath(directory: string, key: string): string {
  return path.join(directory, `${key}.json`);
}

function newRecord(event: NormalizedGithubEvent, key: string): DedupeRecord {
  return {
    dedupe_key: key,
    source_event_id: `${event.delivery_id}:${event.event_type}:${event.repository_id}:${event.repository_full_name}`,
    event_identity: {
      delivery_id: event.delivery_id,
      event_type: event.event_type,
      repository_full_name: event.repository_full_name,
    },
    source_event_digest: event.raw_body_sha256,
    normalized_event: event,
    state: "RESERVED",
    updated_at: new Date().toISOString(),
  };
}

export async function reserveDedupe(
  directory: string,
  event: NormalizedGithubEvent,
): Promise<DedupeResult> {
  await mkdir(directory, { recursive: true });
  const key = dedupeKey(event);
  const file = recordPath(directory, key);
  const candidate = newRecord(event, key);
  try {
    const handle = await open(file, "wx");
    try {
      await handle.writeFile(`${JSON.stringify(candidate, null, 2)}\n`, "utf8");
    } finally {
      await handle.close();
    }
    return { status: "NEW", key, record: candidate };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  }

  const existing = JSON.parse(await readFile(file, "utf8")) as DedupeRecord;
  if (existing.source_event_digest !== event.raw_body_sha256) {
    return { status: "CONFLICT", key, record: existing };
  }
  return { status: "DUPLICATE_SAME", key, record: existing };
}

export async function finalizeDedupe(
  directory: string,
  reservation: DedupeResult,
  update: Partial<Pick<DedupeRecord, "state" | "decision" | "reason" | "policy_id" | "policy_version" | "derived_incident_id" | "create_request">>,
): Promise<DedupeRecord> {
  const record: DedupeRecord = {
    ...reservation.record,
    ...update,
    updated_at: new Date().toISOString(),
  };
  await writeAtomicJson(recordPath(directory, reservation.key), record);
  return record;
}

export function storedCreateRequest(record: DedupeRecord): C1CreateRequest | undefined {
  return record.create_request;
}
