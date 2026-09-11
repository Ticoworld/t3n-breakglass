import { createHash, randomBytes } from "node:crypto";
import { chmod, link, mkdir, open, readFile, readdir, stat, unlink } from "node:fs/promises";
import path from "node:path";

import { writeAtomicJson } from "../scripts/result-file.js";
import {
  RECEIPT_INTEGRITY_DOMAIN,
  type IntegrityKeyInput,
  parseStrictJson,
  signEnvelope,
  verifyEnvelope,
} from "../runtime/integrity.js";
import type { C1CreateRequest, DedupeRecord, DedupeResult, NormalizedSourceEvent } from "./types.js";

export const DEDUPE_SCHEMA_VERSION = 3 as const;
export const DEFAULT_RESERVED_RECOVERY_MS = 5 * 60 * 1000;

export class DedupeIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DedupeIntegrityError";
  }
}

export interface DedupeOptions {
  reservedRecoveryMs?: number;
  stateIntegrityKey?: IntegrityKeyInput;
  recoverReserved?: boolean;
}

export function dedupeKey(event: NormalizedSourceEvent): string {
  const identity = `${event.delivery_id}\n${event.event_type}\n${event.repository_id}\n${event.repository_full_name}`;
  return createHash("sha256").update(identity, "utf8").digest("hex");
}

function recordPath(directory: string, key: string): string {
  if (!/^[0-9a-f]{64}$/i.test(key)) throw new DedupeIntegrityError("receipt key is not a safe storage identifier");
  return path.join(directory, `${key}.json`);
}

function integrityKey(input?: IntegrityKeyInput): IntegrityKeyInput {
  const value = input ?? process.env.BREAKGLASS_STATE_INTEGRITY_KEY;
  if (!value) throw new DedupeIntegrityError("BREAKGLASS_STATE_INTEGRITY_KEY is required for maintained receipt storage");
  return value;
}

function withoutIntegrityFields(record: DedupeRecord): Record<string, unknown> {
  const { key_id: _keyId, mac: _mac, ...payload } = record;
  return payload;
}

function signRecord(record: Omit<DedupeRecord, "key_id" | "mac">, key: IntegrityKeyInput): DedupeRecord {
  const { key_id: _keyId, mac: _mac, ...payload } = record as DedupeRecord;
  const envelope = signEnvelope(RECEIPT_INTEGRITY_DOMAIN, payload, key);
  return { ...payload, key_id: envelope.key_id, mac: envelope.mac } as DedupeRecord;
}

function stripUndefined<T extends Record<string, unknown>>(value: T): T {
  return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined)) as T;
}

function validTimestamp(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function validStoredCreateRequest(value: unknown, incidentId?: string): value is C1CreateRequest {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const request = value as Record<string, unknown>;
  const keys = Object.keys(request).sort().join(",");
  return keys === "deploy_key_id,effect_broker_did,incident_id,remediation_agent_did,ttl_secs" &&
    typeof request.incident_id === "string" && (!incidentId || request.incident_id === incidentId) &&
    typeof request.remediation_agent_did === "string" && request.remediation_agent_did.length > 0 &&
    typeof request.effect_broker_did === "string" && request.effect_broker_did.length > 0 &&
    typeof request.deploy_key_id === "number" && Number.isSafeInteger(request.deploy_key_id) && request.deploy_key_id > 0 &&
    typeof request.ttl_secs === "number" && Number.isSafeInteger(request.ttl_secs) && request.ttl_secs > 0 && request.ttl_secs <= 86_400;
}

export function validateDedupeRecord(
  value: unknown,
  expectedKey?: string,
  options: { requireCompleteAccepted?: boolean; stateIntegrityKey?: IntegrityKeyInput; verifyIntegrity?: boolean } = {},
): DedupeRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new DedupeIntegrityError("receipt is not an object");
  const record = value as Record<string, unknown>;
  if (record.schema_version !== DEDUPE_SCHEMA_VERSION) {
    if (record.schema_version === 2 || record.schema_version === undefined) throw new DedupeIntegrityError("receipt is LEGACY_UNVERIFIED");
    throw new DedupeIntegrityError("receipt schema version is unsupported");
  }
  if (typeof record.key_id !== "string" || record.key_id.length === 0 || typeof record.mac !== "string" || !/^[0-9a-f]{64}$/i.test(record.mac)) throw new DedupeIntegrityError("receipt integrity envelope is incomplete");
  if (typeof record.dedupe_key !== "string" || !/^[0-9a-f]{64}$/i.test(record.dedupe_key) || (expectedKey && record.dedupe_key !== expectedKey)) throw new DedupeIntegrityError("receipt dedupe key is invalid");
  if (typeof record.source_event_id !== "string" || record.source_event_id.length === 0 || typeof record.source_event_digest !== "string" || !/^[0-9a-f]{64}$/i.test(record.source_event_digest)) throw new DedupeIntegrityError("receipt source identity/digest is invalid");
  if (!record.event_identity || typeof record.event_identity !== "object" || typeof (record.event_identity as Record<string, unknown>).delivery_id !== "string" || typeof (record.event_identity as Record<string, unknown>).event_type !== "string" || typeof (record.event_identity as Record<string, unknown>).repository_full_name !== "string") throw new DedupeIntegrityError("receipt event identity is invalid");
  if (!record.normalized_event || typeof record.normalized_event !== "object" || Array.isArray(record.normalized_event)) throw new DedupeIntegrityError("receipt normalized event is missing");
  if (record.state !== "RESERVED" && record.state !== "ACCEPTED" && record.state !== "REJECTED") throw new DedupeIntegrityError("receipt state is invalid");
  if (!validTimestamp(record.updated_at)) throw new DedupeIntegrityError("receipt updated timestamp is invalid");
  if (typeof record.reservation_id !== "string" || record.reservation_id.length < 16 || !validTimestamp(record.reserved_at)) throw new DedupeIntegrityError("receipt reservation metadata is incomplete");
  if (record.state === "ACCEPTED" && options.requireCompleteAccepted !== false) {
    const missing: string[] = [];
    if (typeof record.policy_id !== "string") missing.push("policy_id");
    if (!Number.isSafeInteger(record.policy_version)) missing.push("policy_version");
    if (typeof record.registry_identity !== "string") missing.push("registry_identity");
    if (typeof record.policy_content_hash !== "string") missing.push("policy_content_hash");
    if (typeof record.event_binding_identity !== "string") missing.push("event_binding_identity");
    if (typeof record.action !== "string") missing.push("action");
    if (typeof record.expected_target_title !== "string") missing.push("expected_target_title");
    if (typeof record.derived_incident_id !== "string") missing.push("derived_incident_id");
    if (!validStoredCreateRequest(record.create_request, typeof record.derived_incident_id === "string" ? record.derived_incident_id : undefined)) missing.push("create_request");
    if (missing.length > 0) throw new DedupeIntegrityError(`accepted receipt is incomplete: ${missing.join(",")}`);
    if (!validTimestamp(record.accepted_at)) throw new DedupeIntegrityError("accepted receipt timestamp is invalid");
    if (record.decision !== "C2_PUSH_SELECTED") throw new DedupeIntegrityError("accepted receipt decision is invalid");
  }
  const typed = record as unknown as DedupeRecord;
  if (options.verifyIntegrity !== false) {
    const key = integrityKey(options.stateIntegrityKey);
    try {
      verifyEnvelope<Record<string, unknown>>(RECEIPT_INTEGRITY_DOMAIN, { key_id: typed.key_id, payload: withoutIntegrityFields(typed), mac: typed.mac }, key);
    } catch (error) {
      throw new DedupeIntegrityError(error instanceof Error ? error.message : String(error));
    }
  }
  return typed;
}

function newRecord(event: NormalizedSourceEvent, key: string, keyInput: IntegrityKeyInput): DedupeRecord {
  const now = new Date().toISOString();
  return signRecord({
    schema_version: DEDUPE_SCHEMA_VERSION,
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
    reservation_id: randomBytes(16).toString("hex"),
    reserved_at: now,
    updated_at: now,
  }, keyInput);
}

async function ensureDirectory(directory: string): Promise<void> {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  try { await chmod(directory, 0o700); } catch { /* Windows does not expose POSIX modes. */ }
}

async function createExclusiveJson(file: string, value: unknown): Promise<void> {
  const temporary = `${file}.${process.pid}.${Date.now()}.${randomBytes(6).toString("hex")}.tmp`;
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, "utf8");
    await handle.sync();
  } finally { await handle.close(); }
  try { await link(temporary, file); }
  finally { try { await unlink(temporary); } catch { /* complete file may have been linked */ } }
}

async function withReceiptLock<T>(file: string, operation: () => Promise<T>): Promise<T> {
  const lock = `${file}.lock`;
  for (;;) {
    try {
      const handle = await open(lock, "wx", 0o600);
      await handle.close();
      try { return await operation(); }
      finally { try { await unlink(lock); } catch { /* another cleanup path removed it */ } }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      try {
        const age = Date.now() - (await stat(lock)).mtimeMs;
        if (age > 30_000) await unlink(lock);
      } catch { /* concurrent owner may have released it */ }
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
  }
}

async function readRecord(file: string, key: string, keyInput: IntegrityKeyInput, requireCompleteAccepted = false): Promise<DedupeRecord> {
  let decoded: unknown;
  try { decoded = parseStrictJson(await readFile(file, "utf8")); }
  catch (error) { throw new DedupeIntegrityError(`receipt cannot be parsed: ${String(error)}`); }
  return validateDedupeRecord(decoded, key, { requireCompleteAccepted, stateIntegrityKey: keyInput });
}

export async function reserveDedupe(directory: string, event: NormalizedSourceEvent, options: DedupeOptions = {}): Promise<DedupeResult> {
  const keyInput = integrityKey(options.stateIntegrityKey);
  await ensureDirectory(directory);
  const key = dedupeKey(event);
  const file = recordPath(directory, key);
  const candidate = newRecord(event, key, keyInput);
  try {
    await createExclusiveJson(file, candidate);
    return { status: "NEW", key, record: candidate };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  }

  return withReceiptLock(file, async () => {
    const existing = await readRecord(file, key, keyInput, false);
    if (existing.source_event_digest !== event.raw_body_sha256) return { status: "CONFLICT", key, record: existing };
    if (existing.state === "RESERVED") {
      const reservedAt = Date.parse(existing.reserved_at!);
      const recoveryMs = options.reservedRecoveryMs ?? DEFAULT_RESERVED_RECOVERY_MS;
      // A stale reservation is recoverable only by the same exact event. It is
      // never freed for a second authority derivation or silently rejected.
      if (options.recoverReserved !== true || Date.now() - reservedAt < recoveryMs) return { status: "DUPLICATE_SAME", key, record: existing };
    }
    return { status: "DUPLICATE_SAME", key, record: existing };
  });
}

export async function finalizeDedupe(
  directory: string,
  reservation: DedupeResult,
  update: Partial<Pick<DedupeRecord, "state" | "decision" | "reason" | "policy_id" | "policy_version" | "registry_identity" | "policy_content_hash" | "event_binding_identity" | "action" | "expected_target_title" | "derived_incident_id" | "create_request">>,
  options: { stateIntegrityKey?: IntegrityKeyInput; allowReservedRecovery?: boolean } = {},
): Promise<DedupeRecord> {
  if ((reservation.status !== "NEW" && !(reservation.status === "DUPLICATE_SAME" && options.allowReservedRecovery === true)) || reservation.record.state !== "RESERVED") throw new DedupeIntegrityError("only a RESERVED receipt may be finalized");
  const keyInput = integrityKey(options.stateIntegrityKey);
  const file = recordPath(directory, reservation.key);
  return withReceiptLock(file, async () => {
    const current = await readRecord(file, reservation.key, keyInput, true);
    if (current.state !== "RESERVED" || current.reservation_id !== reservation.record.reservation_id) throw new DedupeIntegrityError("receipt reservation was changed or already finalized");
    const now = new Date().toISOString();
    const safeUpdate = stripUndefined(update as Record<string, unknown>);
    const next = {
      ...current,
      ...safeUpdate,
      ...(update.state === "ACCEPTED" ? { accepted_at: now } : {}),
      updated_at: now,
    } as Omit<DedupeRecord, "key_id" | "mac">;
    const record = signRecord(next, keyInput);
    validateDedupeRecord(record, reservation.key, { stateIntegrityKey: keyInput });
    await writeAtomicJson(file, record);
    return record;
  });
}

export async function listDedupeRecords(directory: string, options: { stateIntegrityKey?: IntegrityKeyInput } = {}): Promise<DedupeRecord[]> {
  const keyInput = integrityKey(options.stateIntegrityKey);
  await ensureDirectory(directory);
  const entries = await readdir(directory, { withFileTypes: true });
  const records: DedupeRecord[] = [];
  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
    const key = entry.name.slice(0, -5);
    records.push(await readRecord(path.join(directory, entry.name), key, keyInput, true));
  }
  return records;
}

export async function findDedupeRecord(directory: string, event: NormalizedSourceEvent, options: { stateIntegrityKey?: IntegrityKeyInput } = {}): Promise<DedupeRecord | null> {
  const keyInput = integrityKey(options.stateIntegrityKey);
  const file = recordPath(directory, dedupeKey(event));
  try { return await readRecord(file, dedupeKey(event), keyInput, true); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT" || error instanceof DedupeIntegrityError && String(error.message).includes("ENOENT")) return null;
    throw error;
  }
}

export function storedCreateRequest(record: DedupeRecord): C1CreateRequest | undefined {
  return record.create_request;
}
