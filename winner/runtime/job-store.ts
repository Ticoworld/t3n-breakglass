import { createHash, randomBytes } from "node:crypto";
import { chmod, link, mkdir, open, readFile, readdir, stat, unlink } from "node:fs/promises";
import path from "node:path";

import type { C1CreateRequest } from "../c2/types.js";
import { writeAtomicJson } from "../scripts/result-file.js";
import { JOB_INTEGRITY_DOMAIN, canonicalize, parseStrictJson, type IntegrityKeyInput, signEnvelope, verifyEnvelope } from "./integrity.js";

export type RuntimeJobState = "PENDING" | "HANDOFF_READY" | "PROCESSING" | "RETRY_READY" | "RECONCILE_REQUIRED" | "CLOSED" | "FAILED" | "STATE_CONFLICT";

export interface RuntimeJob {
  schema_version: 2;
  key_id: string;
  mac: string;
  job_id: string;
  incident_id: string;
  receipt_key: string;
  policy_id: string;
  policy_version: number;
  deploy_key_id: number;
  expected_target_title: string;
  create_request: C1CreateRequest;
  state: RuntimeJobState;
  created_at: string;
  updated_at: string;
  remote_state?: string | null;
  claim_id?: string | null;
  claim_version?: number | null;
  effect_start_id?: string | null;
  provider_classification?: string | null;
  last_error?: string | null;
  last_result_file?: string | null;
  recovery_attempts?: number;
  /** Fresh operator-authorized routing input for the broker. */
  operator_handoff_id?: string | null;
  /** Last routing input consumed by this broker process. */
  broker_consumed_handoff_id?: string | null;
}

export class RuntimeStateIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RuntimeStateIntegrityError";
  }
}

function stateKey(input?: IntegrityKeyInput): IntegrityKeyInput {
  const value = input ?? process.env.BREAKGLASS_STATE_INTEGRITY_KEY;
  if (!value) throw new RuntimeStateIntegrityError("BREAKGLASS_STATE_INTEGRITY_KEY is required for runtime state");
  return value;
}

function fileKey(incidentId: string): string { return createHash("sha256").update(incidentId, "utf8").digest("hex"); }
function validString(value: unknown): value is string { return typeof value === "string" && value.length > 0; }
function validTime(value: unknown): value is string { return validString(value) && Number.isFinite(Date.parse(value)); }

function validCreateRequest(value: unknown): value is C1CreateRequest {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const request = value as Record<string, unknown>;
  return Object.keys(request).sort().join(",") === "deploy_key_id,effect_broker_did,incident_id,remediation_agent_did,ttl_secs" && validString(request.incident_id) && validString(request.remediation_agent_did) && validString(request.effect_broker_did) && typeof request.deploy_key_id === "number" && Number.isSafeInteger(request.deploy_key_id) && request.deploy_key_id > 0 && typeof request.ttl_secs === "number" && Number.isSafeInteger(request.ttl_secs) && request.ttl_secs > 0 && request.ttl_secs <= 86_400;
}

function unsignedJob(value: RuntimeJob): Record<string, unknown> {
  const { key_id: _keyId, mac: _mac, ...payload } = value;
  return payload;
}

function signJob(value: Omit<RuntimeJob, "key_id" | "mac">, key: IntegrityKeyInput): RuntimeJob {
  const { key_id: _keyId, mac: _mac, ...payload } = value as RuntimeJob;
  const envelope = signEnvelope(JOB_INTEGRITY_DOMAIN, payload, key);
  return { ...payload, key_id: envelope.key_id, mac: envelope.mac } as RuntimeJob;
}

export function validateRuntimeJob(value: unknown, input?: IntegrityKeyInput): RuntimeJob {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new RuntimeStateIntegrityError("runtime job is not an object");
  const job = value as Record<string, unknown>;
  if (job.schema_version === 1) throw new RuntimeStateIntegrityError("legacy unkeyed runtime job is not trusted");
  if (job.schema_version !== 2 || !validString(job.key_id) || typeof job.mac !== "string" || !/^[0-9a-f]{64}$/i.test(job.mac) || !validString(job.job_id) || !validString(job.incident_id) || !/^[0-9a-f]{64}$/.test(String(job.receipt_key)) || !validString(job.policy_id) || !Number.isSafeInteger(job.policy_version) || !Number.isSafeInteger(job.deploy_key_id) || !validString(job.expected_target_title) || !validCreateRequest(job.create_request) || !["PENDING", "HANDOFF_READY", "PROCESSING", "RETRY_READY", "RECONCILE_REQUIRED", "CLOSED", "FAILED", "STATE_CONFLICT"].includes(String(job.state)) || !validTime(job.created_at) || !validTime(job.updated_at)) throw new RuntimeStateIntegrityError("runtime job is incomplete");
  if ((job.claim_id !== undefined && job.claim_id !== null && !validString(job.claim_id)) || (job.effect_start_id !== undefined && job.effect_start_id !== null && !validString(job.effect_start_id))) throw new RuntimeStateIntegrityError("runtime job claim/effect identity is invalid");
  if (job.create_request && (job as Record<string, unknown>).incident_id !== (job.create_request as C1CreateRequest).incident_id) throw new RuntimeStateIntegrityError("runtime job incident/request identity differs");
  if ((job.operator_handoff_id !== undefined && job.operator_handoff_id !== null && !validString(job.operator_handoff_id)) ||
      (job.broker_consumed_handoff_id !== undefined && job.broker_consumed_handoff_id !== null && !validString(job.broker_consumed_handoff_id))) {
    throw new RuntimeStateIntegrityError("runtime job operator handoff identity is invalid");
  }
  const key = stateKey(input);
  try { verifyEnvelope(JOB_INTEGRITY_DOMAIN, { key_id: job.key_id, payload: unsignedJob(job as unknown as RuntimeJob), mac: job.mac }, key); }
  catch (error) { throw new RuntimeStateIntegrityError(`runtime job integrity verification failed: ${error instanceof Error ? error.message : String(error)}`); }
  return job as unknown as RuntimeJob;
}

async function ensureDirectory(directory: string): Promise<void> {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  try { await chmod(directory, 0o700); } catch { /* Windows */ }
}

async function createExclusiveJson(file: string, value: unknown): Promise<void> {
  const temporary = `${file}.${process.pid}.${Date.now()}.${randomBytes(6).toString("hex")}.tmp`;
  const handle = await open(temporary, "wx", 0o600);
  try { await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, "utf8"); await handle.sync(); }
  finally { await handle.close(); }
  try { await link(temporary, file); }
  finally { try { await unlink(temporary); } catch { /* complete file may have been linked */ } }
}

async function readJob(file: string, key: IntegrityKeyInput): Promise<RuntimeJob> {
  try { return validateRuntimeJob(parseStrictJson(await readFile(file, "utf8")), key); }
  catch (error) { if (error instanceof RuntimeStateIntegrityError) throw error; throw new RuntimeStateIntegrityError(`cannot read runtime job ${file}: ${String(error)}`); }
}

interface LeaseRecord { schema_version: 1; owner_id: string; pid: number; acquired_at: string; last_heartbeat_at: string; expires_at: string; heartbeat_sequence: number; }

class LeaseOwnerAmbiguousError extends RuntimeStateIntegrityError {
  constructor(message = "LEASE_OWNER_AMBIGUOUS") {
    super(message);
    this.name = "LeaseOwnerAmbiguousError";
  }
}

type ProcessProbe = "ALIVE" | "DEAD" | "UNKNOWN";

function processProbe(pid: number): ProcessProbe {
  if (!Number.isSafeInteger(pid) || pid <= 0) return "UNKNOWN";
  try { process.kill(pid, 0); return "ALIVE"; }
  catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ESRCH") return "DEAD";
    return "UNKNOWN";
  }
}

async function readLease(file: string): Promise<LeaseRecord> {
  let value: unknown;
  try { value = parseStrictJson(await readFile(file, "utf8")); } catch (error) { throw new RuntimeStateIntegrityError(`lease is corrupt: ${String(error)}`); }
  if (!value || typeof value !== "object") throw new RuntimeStateIntegrityError("lease is corrupt");
  const lease = value as Record<string, unknown>;
  if (lease.schema_version !== 1 || !validString(lease.owner_id) || !Number.isSafeInteger(lease.pid) || !validTime(lease.acquired_at) || !validTime(lease.last_heartbeat_at) || !validTime(lease.expires_at) || !Number.isSafeInteger(lease.heartbeat_sequence)) throw new RuntimeStateIntegrityError("lease is malformed");
  return lease as unknown as LeaseRecord;
}

async function acquireLease(file: string, durationMs: number): Promise<{ lease: LeaseRecord; release: () => Promise<void>; lost: () => boolean } | null> {
  const ownerId = `${process.pid}-${randomBytes(12).toString("hex")}`;
  for (;;) {
    const now = Date.now();
    const lease: LeaseRecord = { schema_version: 1, owner_id: ownerId, pid: process.pid, acquired_at: new Date(now).toISOString(), last_heartbeat_at: new Date(now).toISOString(), expires_at: new Date(now + durationMs).toISOString(), heartbeat_sequence: 0 };
    try {
      await createExclusiveJson(file, lease);
      let leaseLost = false;
      const heartbeat = setInterval(() => {
        void (async () => {
          try {
            const current = await readLease(file);
            if (current.owner_id !== ownerId) { leaseLost = true; return; }
            const heartbeatAt = Date.now();
            await writeAtomicJson(file, { ...current, last_heartbeat_at: new Date(heartbeatAt).toISOString(), expires_at: new Date(heartbeatAt + durationMs).toISOString(), heartbeat_sequence: current.heartbeat_sequence + 1 });
          } catch { leaseLost = true; }
        })();
      }, Math.max(100, Math.floor(durationMs / 3)));
      const release = async () => {
        clearInterval(heartbeat);
        try { if ((await readLease(file)).owner_id === ownerId) await unlink(file); } catch { /* crash/recovery owns cleanup */ }
      };
      return { lease, release, lost: () => leaseLost };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const current = await readLease(file);
      const expired = Date.parse(current.expires_at) <= Date.now();
      if (!expired) return null;
      const ownerProcess = processProbe(current.pid);
      if (ownerProcess !== "DEAD") throw new LeaseOwnerAmbiguousError();
      await unlink(file);
    }
  }
}

function canTransition(from: RuntimeJobState, to: RuntimeJobState, allowConflict: boolean): boolean {
  if (from === to) return true;
  if (from === "STATE_CONFLICT") return allowConflict && (to === "RECONCILE_REQUIRED" || to === "CLOSED");
  if (from === "CLOSED" || from === "FAILED") return allowConflict && to === "STATE_CONFLICT";
  const allowed: Record<RuntimeJobState, RuntimeJobState[]> = {
    PENDING: ["HANDOFF_READY", "RECONCILE_REQUIRED", "CLOSED", "FAILED", "STATE_CONFLICT"],
    HANDOFF_READY: ["PROCESSING", "RETRY_READY", "RECONCILE_REQUIRED", "CLOSED", "FAILED", "STATE_CONFLICT"],
    PROCESSING: ["RETRY_READY", "RECONCILE_REQUIRED", "CLOSED", "FAILED", "STATE_CONFLICT"],
    RETRY_READY: ["RECONCILE_REQUIRED", "CLOSED", "FAILED", "STATE_CONFLICT"],
    RECONCILE_REQUIRED: ["CLOSED", "FAILED", "STATE_CONFLICT"],
    CLOSED: [],
    FAILED: [],
    STATE_CONFLICT: [],
  };
  return allowed[from].includes(to);
}

export class RuntimeJobStore {
  constructor(readonly directory: string, readonly options: { stateIntegrityKey?: IntegrityKeyInput; leaseDurationMs?: number } = {}) {}
  private key(): IntegrityKeyInput { return stateKey(this.options.stateIntegrityKey); }

  async initialize(): Promise<void> { await ensureDirectory(this.directory); await this.list(); }

  async create(input: Omit<RuntimeJob, "schema_version" | "key_id" | "mac" | "job_id" | "created_at" | "updated_at" | "state"> & { state?: RuntimeJobState }): Promise<RuntimeJob> {
    await ensureDirectory(this.directory);
    const now = new Date().toISOString();
    const unsigned: Omit<RuntimeJob, "key_id" | "mac"> = { ...input, schema_version: 2, job_id: `job-${fileKey(input.incident_id).slice(0, 24)}`, state: input.state ?? "PENDING", created_at: now, updated_at: now };
    const job = signJob(unsigned, this.key());
    const file = path.join(this.directory, `${fileKey(input.incident_id)}.json`);
    try { await createExclusiveJson(file, job); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const existing = await readJob(file, this.key());
      if (existing.incident_id !== input.incident_id || existing.receipt_key !== input.receipt_key || existing.policy_id !== input.policy_id || existing.policy_version !== input.policy_version || existing.deploy_key_id !== input.deploy_key_id || existing.expected_target_title !== input.expected_target_title || canonicalize(existing.create_request) !== canonicalize(input.create_request)) throw new RuntimeStateIntegrityError("runtime job identity conflict");
      return existing;
    }
    return job;
  }

  async get(incidentId: string): Promise<RuntimeJob | null> {
    await ensureDirectory(this.directory);
    const file = path.join(this.directory, `${fileKey(incidentId)}.json`);
    try { return await readJob(file, this.key()); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT" || error instanceof RuntimeStateIntegrityError && String(error.message).includes("ENOENT")) return null; throw error; }
  }

  async update(incidentId: string, patch: Partial<Omit<RuntimeJob, "schema_version" | "key_id" | "mac" | "job_id" | "incident_id" | "created_at">>, options: { allowStateConflict?: boolean } = {}): Promise<RuntimeJob> {
    const file = path.join(this.directory, `${fileKey(incidentId)}.json`);
    const lock = `${file}.state-lock`;
    for (;;) {
      try {
        const handle = await open(lock, "wx", 0o600);
        await handle.close();
        try {
          const current = await readJob(file, this.key());
          const requested = patch.state ?? current.state;
          if (!canTransition(current.state, requested, options.allowStateConflict === true)) throw new RuntimeStateIntegrityError(`local job state transition ${current.state} -> ${requested} is not permitted`);
          const merged = { ...current, ...patch, updated_at: new Date().toISOString() } as RuntimeJob;
          const next = signJob(unsignedJob(merged) as Omit<RuntimeJob, "key_id" | "mac">, this.key());
          await writeAtomicJson(file, next);
          return next;
        } finally { try { await unlink(lock); } catch { /* preserve operation result */ } }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        try { if (Date.now() - (await stat(lock)).mtimeMs > 30_000) await unlink(lock); } catch { /* active writer */ }
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
    }
  }

  async list(): Promise<RuntimeJob[]> {
    await ensureDirectory(this.directory);
    const jobs: RuntimeJob[] = [];
    for (const entry of await readdir(this.directory, { withFileTypes: true })) if (entry.isFile() && entry.name.endsWith(".json")) jobs.push(await readJob(path.join(this.directory, entry.name), this.key()));
    return jobs.sort((a, b) => a.created_at.localeCompare(b.created_at));
  }

  async withLease<T>(incidentId: string, operation: (job: RuntimeJob) => Promise<T>): Promise<T | null> {
    const file = path.join(this.directory, `${fileKey(incidentId)}.json`);
    const lease = await acquireLease(file.replace(/\.json$/i, ".lease"), this.options.leaseDurationMs ?? 30_000);
    if (!lease) return null;
    try {
      const result = await operation(await readJob(file, this.key()));
      if (lease.lost()) throw new RuntimeStateIntegrityError("runtime job lease was lost during operation");
      return result;
    } finally { await lease.release(); }
  }
}
