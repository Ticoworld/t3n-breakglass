import { randomBytes, createHash } from "node:crypto";
import { chmod, link, mkdir, open, readFile, readdir, unlink } from "node:fs/promises";
import path from "node:path";

import {
  buildC2PushPolicyV2,
  pushPolicyContentHash,
  validateC2PushPolicyV2,
  type C2PushPolicyV2,
  type C2PushPolicyV2Input,
} from "../c2/push-policy.js";
import { pushEventBindingIdentity, type PushBindingIdentityInput } from "../c2/push-binding.js";
import type { NormalizedPushEvent } from "../c2/types.js";
import type { PushTransitionResult } from "../c2/push-transition.js";
import {
  POLICY_BINDING_INTEGRITY_DOMAIN,
  POLICY_RETIREMENT_INTEGRITY_DOMAIN,
  type IntegrityKeyInput,
  parseStrictJson,
  signEnvelope,
  verifyEnvelope,
} from "./integrity.js";

const POLICY_SCHEMA_VERSION = 2;
const BINDING_SCHEMA_VERSION = 1;
const RETIREMENT_SCHEMA_VERSION = 2;

export type RegistryPolicyInput = Omit<C2PushPolicyV2Input, "enabled" | "actual_creation_timestamp" | "creation_commit_or_registry_identity" | "provenance">;

export interface PolicyRegistryRecord {
  schema_version: typeof POLICY_SCHEMA_VERSION;
  key_id: string;
  mac: string;
  registry_identity: string;
  activated_at: string;
  policy_sha256: string;
  trusted_evidence_identity: string;
  policy: C2PushPolicyV2;
}

export interface PolicyBindingRecord {
  schema_version: typeof BINDING_SCHEMA_VERSION;
  key_id: string;
  mac: string;
  policy_id: string;
  policy_version: number;
  registry_identity: string;
  policy_content_hash: string;
  dedupe_key: string;
  delivery_id: string;
  event_type: string;
  repository_id: number;
  repository_full_name: string;
  ref: string;
  before: string;
  after: string;
  raw_body_sha256: string;
  event_binding_identity: string;
  incident_id: string;
  bound_at: string;
}

export interface PolicyRetirementRecord {
  schema_version: typeof RETIREMENT_SCHEMA_VERSION;
  key_id: string;
  mac: string;
  registry_identity: string;
  policy_id: string;
  policy_version: number;
  retired: true;
  retired_at: string;
  retirement_reason: string;
  incident_id: string;
}

export class PolicyRegistryIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyRegistryIntegrityError";
  }
}

function policyKey(policyId: string, policyVersion: number): string {
  if (!/^[A-Za-z0-9._-]{1,128}$/.test(policyId) || !Number.isSafeInteger(policyVersion) || policyVersion <= 0) throw new PolicyRegistryIntegrityError("policy identity is not a safe storage identifier");
  return createHash("sha256").update(`${policyId}\n${policyVersion}`, "utf8").digest("hex");
}

async function ensurePrivateDirectory(directory: string): Promise<void> {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  try { await chmod(directory, 0o700); } catch { /* Windows does not expose POSIX modes. */ }
}

async function writeExclusiveJson(file: string, value: unknown): Promise<void> {
  const directory = path.dirname(file);
  await ensurePrivateDirectory(directory);
  const temporary = `${file}.${process.pid}.${Date.now()}.${randomBytes(6).toString("hex")}.tmp`;
  const handle = await open(temporary, "wx", 0o600);
  try { await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, "utf8"); await handle.sync(); }
  finally { await handle.close(); }
  try { await link(temporary, file); }
  catch (error) { try { await unlink(temporary); } catch { /* preserve the original failure */ } throw error; }
  await unlink(temporary);
}

async function jsonFiles(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  return entries.filter((entry) => entry.isFile() && entry.name.endsWith(".json")).map((entry) => path.join(directory, entry.name));
}

function keyInput(input?: IntegrityKeyInput): IntegrityKeyInput {
  const value = input ?? process.env.BREAKGLASS_STATE_INTEGRITY_KEY;
  if (!value) throw new PolicyRegistryIntegrityError("BREAKGLASS_STATE_INTEGRITY_KEY is required for the policy registry");
  return value;
}

function stripIntegrity<T extends Record<string, unknown>>(value: T): Record<string, unknown> {
  const { key_id: _keyId, mac: _mac, ...payload } = value;
  return payload;
}

function signRecord<T extends Record<string, unknown>>(domain: string, record: T, key: IntegrityKeyInput): T & { key_id: string; mac: string } {
  const { key_id: _keyId, mac: _mac, ...payload } = record;
  const envelope = signEnvelope(domain, payload, key);
  return { ...payload, key_id: envelope.key_id, mac: envelope.mac } as T & { key_id: string; mac: string };
}

function assertRecord(record: unknown, file: string, key: IntegrityKeyInput): PolicyRegistryRecord {
  if (!record || typeof record !== "object" || Array.isArray(record)) throw new PolicyRegistryIntegrityError(`policy record is not an object: ${file}`);
  const value = record as Record<string, unknown>;
  if (value.schema_version === 1) throw new PolicyRegistryIntegrityError(`legacy unkeyed policy record is not trusted: ${file}`);
  const policy = value.policy;
  if (!policy || typeof policy !== "object") throw new PolicyRegistryIntegrityError(`policy payload is missing: ${file}`);
  if (value.schema_version !== POLICY_SCHEMA_VERSION || typeof value.registry_identity !== "string" || !value.registry_identity || typeof value.key_id !== "string" || typeof value.mac !== "string") throw new PolicyRegistryIntegrityError(`policy registry envelope is invalid: ${file}`);
  const validation = validateC2PushPolicyV2(policy as C2PushPolicyV2, { requireLiveProvenance: true });
  if (!validation.valid) throw new PolicyRegistryIntegrityError(`policy validation failed for ${file}: ${validation.reasons.join(", ")}`);
  if (typeof value.activated_at !== "string" || !Number.isFinite(Date.parse(value.activated_at))) throw new PolicyRegistryIntegrityError(`policy activation timestamp is invalid: ${file}`);
  if (typeof value.policy_sha256 !== "string" || value.policy_sha256 !== pushPolicyContentHash(policy as C2PushPolicyV2)) throw new PolicyRegistryIntegrityError(`policy content hash mismatch: ${file}`);
  if (typeof value.trusted_evidence_identity !== "string" || value.trusted_evidence_identity.length === 0) throw new PolicyRegistryIntegrityError(`trusted evidence identity is missing: ${file}`);
  const typedPolicy = policy as C2PushPolicyV2;
  if (typedPolicy.creation_commit_or_registry_identity !== value.registry_identity || typedPolicy.provenance.creation_evidence !== value.registry_identity) throw new PolicyRegistryIntegrityError(`policy provenance is not established by this registry: ${file}`);
  try { verifyEnvelope(RECEIPTLESS_POLICY_DOMAIN, { key_id: value.key_id, payload: stripIntegrity(value), mac: value.mac }, key); }
  catch (error) { throw new PolicyRegistryIntegrityError(`policy integrity verification failed for ${file}: ${error instanceof Error ? error.message : String(error)}`); }
  return value as unknown as PolicyRegistryRecord;
}

// Kept separate from receipt integrity to prevent cross-protocol substitution.
const RECEIPTLESS_POLICY_DOMAIN = "breakglass.policy-record.v1";

function assertBinding(record: unknown, file: string, key: IntegrityKeyInput): PolicyBindingRecord {
  if (!record || typeof record !== "object" || Array.isArray(record)) throw new PolicyRegistryIntegrityError(`policy binding is not an object: ${file}`);
  const value = record as Record<string, unknown>;
  if (value.schema_version !== BINDING_SCHEMA_VERSION || typeof value.key_id !== "string" || typeof value.mac !== "string" || typeof value.policy_id !== "string" || !Number.isSafeInteger(value.policy_version) || typeof value.registry_identity !== "string" || typeof value.policy_content_hash !== "string" || typeof value.dedupe_key !== "string" || !/^[0-9a-f]{64}$/i.test(value.dedupe_key) || typeof value.delivery_id !== "string" || typeof value.event_type !== "string" || !Number.isSafeInteger(value.repository_id) || typeof value.repository_full_name !== "string" || typeof value.ref !== "string" || typeof value.before !== "string" || typeof value.after !== "string" || typeof value.raw_body_sha256 !== "string" || !/^[0-9a-f]{64}$/i.test(value.raw_body_sha256) || typeof value.event_binding_identity !== "string" || typeof value.incident_id !== "string" || typeof value.bound_at !== "string" || !Number.isFinite(Date.parse(value.bound_at))) throw new PolicyRegistryIntegrityError(`policy binding is malformed: ${file}`);
  try { verifyEnvelope(POLICY_BINDING_INTEGRITY_DOMAIN, { key_id: value.key_id, payload: stripIntegrity(value), mac: value.mac }, key); }
  catch (error) { throw new PolicyRegistryIntegrityError(`policy binding integrity verification failed for ${file}: ${error instanceof Error ? error.message : String(error)}`); }
  return value as unknown as PolicyBindingRecord;
}

function assertRetirement(record: unknown, file: string, key: IntegrityKeyInput): PolicyRetirementRecord {
  if (!record || typeof record !== "object" || Array.isArray(record)) throw new PolicyRegistryIntegrityError(`retirement record is not an object: ${file}`);
  const value = record as Record<string, unknown>;
  if (value.schema_version === 1) throw new PolicyRegistryIntegrityError(`legacy unkeyed retirement record is not trusted: ${file}`);
  if (value.schema_version !== RETIREMENT_SCHEMA_VERSION || typeof value.key_id !== "string" || typeof value.mac !== "string" || value.retired !== true || typeof value.registry_identity !== "string" || typeof value.policy_id !== "string" || !Number.isSafeInteger(value.policy_version) || typeof value.retired_at !== "string" || !Number.isFinite(Date.parse(value.retired_at)) || typeof value.retirement_reason !== "string" || typeof value.incident_id !== "string") throw new PolicyRegistryIntegrityError(`retirement record is malformed: ${file}`);
  try { verifyEnvelope(POLICY_RETIREMENT_INTEGRITY_DOMAIN, { key_id: value.key_id, payload: stripIntegrity(value), mac: value.mac }, key); }
  catch (error) { throw new PolicyRegistryIntegrityError(`retirement integrity verification failed for ${file}: ${error instanceof Error ? error.message : String(error)}`); }
  return value as unknown as PolicyRetirementRecord;
}

export class PolicyRegistry {
  readonly policyDirectory: string;
  readonly bindingDirectory: string;
  readonly retirementDirectory: string;

  constructor(readonly rootDirectory: string, readonly options: { stateIntegrityKey?: IntegrityKeyInput } = {}) {
    this.policyDirectory = path.join(rootDirectory, "policies");
    this.bindingDirectory = path.join(rootDirectory, "bindings");
    this.retirementDirectory = path.join(rootDirectory, "retirements");
  }

  private key(): IntegrityKeyInput { return keyInput(this.options.stateIntegrityKey); }

  async initialize(): Promise<void> {
    await ensurePrivateDirectory(this.policyDirectory);
    await ensurePrivateDirectory(this.bindingDirectory);
    await ensurePrivateDirectory(this.retirementDirectory);
    await this.records();
    await this.bindings();
    await this.retirements();
  }

  async create(input: RegistryPolicyInput, options: { trustedEvidenceIdentity?: string } = {}): Promise<PolicyRegistryRecord> {
    if (!input || typeof input !== "object") throw new PolicyRegistryIntegrityError("policy input is missing");
    if (!options.trustedEvidenceIdentity) throw new PolicyRegistryIntegrityError("explicit trusted policy evidence identity is required");
    const activatedAt = new Date().toISOString();
    const evidenceIdentity = options.trustedEvidenceIdentity.slice(0, 512);
    const evidenceHash = createHash("sha256").update(evidenceIdentity, "utf8").digest("hex").slice(0, 16);
    const registryIdentity = `file-policy:${input.policy_id}:v${input.policy_version}:${evidenceHash}:${randomBytes(8).toString("hex")}`;
    const policy = buildC2PushPolicyV2({
      ...input,
      enabled: true,
      actual_creation_timestamp: activatedAt,
      creation_commit_or_registry_identity: registryIdentity,
      provenance: { classification: "LIVE_PROVENANCE", creation_evidence: registryIdentity, enabled_before_event_proof: true },
    });
    const record = signRecord(RECEIPTLESS_POLICY_DOMAIN, {
      schema_version: POLICY_SCHEMA_VERSION,
      registry_identity: registryIdentity,
      activated_at: activatedAt,
      policy_sha256: pushPolicyContentHash(policy),
      trusted_evidence_identity: evidenceIdentity,
      policy,
    }, this.key());
    const file = path.join(this.policyDirectory, `${policyKey(policy.policy_id, policy.policy_version)}.json`);
    try { await writeExclusiveJson(file, record); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === "EEXIST") throw new PolicyRegistryIntegrityError(`duplicate policy identity/version refused: ${policy.policy_id}@${policy.policy_version}`); throw error; }
    return record as PolicyRegistryRecord;
  }

  async records(): Promise<PolicyRegistryRecord[]> {
    const key = this.key();
    await ensurePrivateDirectory(this.policyDirectory);
    const records: PolicyRegistryRecord[] = [];
    for (const file of await jsonFiles(this.policyDirectory)) {
      let decoded: unknown;
      try { decoded = parseStrictJson(await readFile(file, "utf8")); } catch (error) { throw new PolicyRegistryIntegrityError(`cannot parse policy record ${file}: ${String(error)}`); }
      records.push(assertRecord(decoded, file, key));
    }
    return records.sort((a, b) => a.policy.policy_id.localeCompare(b.policy.policy_id) || a.policy.policy_version - b.policy.policy_version);
  }

  async bindings(): Promise<PolicyBindingRecord[]> {
    const key = this.key();
    await ensurePrivateDirectory(this.bindingDirectory);
    const records: PolicyBindingRecord[] = [];
    for (const file of await jsonFiles(this.bindingDirectory)) {
      let decoded: unknown;
      try { decoded = parseStrictJson(await readFile(file, "utf8")); } catch (error) { throw new PolicyRegistryIntegrityError(`cannot parse policy binding ${file}: ${String(error)}`); }
      records.push(assertBinding(decoded, file, key));
    }
    return records;
  }

  async retirements(): Promise<PolicyRetirementRecord[]> {
    const key = this.key();
    await ensurePrivateDirectory(this.retirementDirectory);
    const records: PolicyRetirementRecord[] = [];
    for (const file of await jsonFiles(this.retirementDirectory)) {
      let decoded: unknown;
      try { decoded = parseStrictJson(await readFile(file, "utf8")); } catch (error) { throw new PolicyRegistryIntegrityError(`cannot parse retirement record ${file}: ${String(error)}`); }
      records.push(assertRetirement(decoded, file, key));
    }
    return records;
  }

  async activePolicyRecords(at = new Date()): Promise<PolicyRegistryRecord[]> {
    const [records, bindings, retirements] = await Promise.all([this.records(), this.bindings(), this.retirements()]);
    const unavailable = new Set([...bindings.map((record) => `${record.policy_id}@${record.policy_version}`), ...retirements.map((record) => `${record.policy_id}@${record.policy_version}`)]);
    return records.filter((record) => record.policy.enabled && Date.parse(record.activated_at) <= at.getTime() && !unavailable.has(`${record.policy.policy_id}@${record.policy.policy_version}`));
  }

  async activePolicies(at = new Date()): Promise<C2PushPolicyV2[]> {
    return (await this.activePolicyRecords(at)).map((record) => record.policy);
  }

  async findRecord(policyId: string, policyVersion: number): Promise<PolicyRegistryRecord | null> {
    return (await this.records()).find((candidate) => candidate.policy.policy_id === policyId && candidate.policy.policy_version === policyVersion) ?? null;
  }

  async find(policyId: string, policyVersion: number): Promise<C2PushPolicyV2 | null> {
    return (await this.findRecord(policyId, policyVersion))?.policy ?? null;
  }

  async boundPolicyForEvent(event: NormalizedPushEvent, dedupeKey: string): Promise<PolicyRegistryRecord | null> {
    const binding = (await this.bindings()).find((item) => item.dedupe_key === dedupeKey && item.delivery_id === event.delivery_id && item.raw_body_sha256 === event.raw_body_sha256);
    if (!binding) return null;
    const record = await this.findRecord(binding.policy_id, binding.policy_version);
    if (!record || record.registry_identity !== binding.registry_identity || record.policy_sha256 !== binding.policy_content_hash) throw new PolicyRegistryIntegrityError("bound policy metadata does not match the registry");
    return record;
  }

  async boundPolicyRecordsForEvent(event: NormalizedPushEvent): Promise<PolicyRegistryRecord[]> {
    const [bindings, records] = await Promise.all([this.bindings(), this.records()]);
    const byIdentity = new Map(records.map((record) => [`${record.policy.policy_id}@${record.policy.policy_version}`, record]));
    const result: PolicyRegistryRecord[] = [];
    for (const binding of bindings) {
      if (binding.event_type !== event.event_type || binding.repository_id !== event.repository_id || binding.repository_full_name !== event.repository_full_name || binding.ref !== event.ref) continue;
      const record = byIdentity.get(`${binding.policy_id}@${binding.policy_version}`);
      if (!record || record.registry_identity !== binding.registry_identity || record.policy_sha256 !== binding.policy_content_hash) throw new PolicyRegistryIntegrityError("bound policy metadata does not match the registry");
      result.push(record);
    }
    return result;
  }

  async bindVerifiedEvent(input: PushBindingIdentityInput): Promise<{ eventBindingIdentity: string }> {
    if (!input.eventBindingIdentity) throw new PolicyRegistryIntegrityError("verified event binding identity is missing");
    const record = await this.findRecord(input.policy.policy_id, input.policy.policy_version);
    if (!record || record.registry_identity !== input.registryIdentity || record.policy_sha256 !== input.policyContentHash) throw new PolicyRegistryIntegrityError("verified event policy metadata does not match the registry");
    if (pushPolicyContentHash(input.policy) !== record.policy_sha256) throw new PolicyRegistryIntegrityError("verified event policy payload does not match the registry record");
    if (!record.policy.enabled || Date.parse(record.activated_at) > Date.now()) throw new PolicyRegistryIntegrityError("verified event policy is not currently ACTIVE");
    const expectedIdentity = pushEventBindingIdentity(input);
    if (expectedIdentity !== input.eventBindingIdentity) throw new PolicyRegistryIntegrityError("verified event binding identity is invalid");
    const file = path.join(this.bindingDirectory, `${policyKey(input.policy.policy_id, input.policy.policy_version)}.json`);
    const existingFile = await readFile(file, "utf8").catch(() => null);
    if (existingFile !== null) {
      let existing: unknown;
      try { existing = parseStrictJson(existingFile); } catch (error) { throw new PolicyRegistryIntegrityError(`cannot parse existing policy binding: ${String(error)}`); }
      const binding = assertBinding(existing, file, this.key());
      if (binding.event_binding_identity === input.eventBindingIdentity && binding.dedupe_key === input.dedupeKey && binding.incident_id === input.incidentId) return { eventBindingIdentity: binding.event_binding_identity };
      throw new PolicyRegistryIntegrityError("policy is already bound to a different verified event");
    }
    const [retirements, bindings] = await Promise.all([this.retirements(), this.bindings()]);
    const policyIdentity = `${input.policy.policy_id}@${input.policy.policy_version}`;
    if (retirements.some((item) => `${item.policy_id}@${item.policy_version}` === policyIdentity) || bindings.some((item) => `${item.policy_id}@${item.policy_version}` === policyIdentity)) throw new PolicyRegistryIntegrityError("policy is already bound or retired");
    const binding = signRecord(POLICY_BINDING_INTEGRITY_DOMAIN, {
      schema_version: BINDING_SCHEMA_VERSION,
      policy_id: input.policy.policy_id,
      policy_version: input.policy.policy_version,
      registry_identity: input.registryIdentity,
      policy_content_hash: input.policyContentHash,
      dedupe_key: input.dedupeKey,
      delivery_id: input.event.delivery_id,
      event_type: input.event.event_type,
      repository_id: input.event.repository_id,
      repository_full_name: input.event.repository_full_name,
      ref: input.event.ref,
      before: input.event.before,
      after: input.event.after,
      raw_body_sha256: input.event.raw_body_sha256,
      event_binding_identity: input.eventBindingIdentity,
      incident_id: input.incidentId,
      bound_at: new Date().toISOString(),
    }, this.key());
    try { await writeExclusiveJson(file, binding); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const winner = assertBinding(parseStrictJson(await readFile(file, "utf8")), file, this.key());
      if (winner.event_binding_identity === input.eventBindingIdentity && winner.dedupe_key === input.dedupeKey) return { eventBindingIdentity: winner.event_binding_identity };
      throw new PolicyRegistryIntegrityError("policy is already bound to a different verified event");
    }
    return { eventBindingIdentity: input.eventBindingIdentity };
  }

  async retire(policyId: string, policyVersion: number, incidentId: string, reason = "terminal incident closed verified absent"): Promise<PolicyRetirementRecord> {
    const record = await this.findRecord(policyId, policyVersion);
    if (!record) throw new PolicyRegistryIntegrityError(`cannot retire unknown policy ${policyId}@${policyVersion}`);
    const binding = (await this.bindings()).find((item) => item.policy_id === policyId && item.policy_version === policyVersion);
    if (!binding || binding.incident_id !== incidentId) throw new PolicyRegistryIntegrityError("policy retirement incident does not match the durable binding");
    const file = path.join(this.retirementDirectory, `${policyKey(policyId, policyVersion)}.json`);
    const value = signRecord(POLICY_RETIREMENT_INTEGRITY_DOMAIN, {
      schema_version: RETIREMENT_SCHEMA_VERSION,
      registry_identity: record.registry_identity,
      policy_id: policyId,
      policy_version: policyVersion,
      retired: true,
      retired_at: new Date().toISOString(),
      retirement_reason: reason,
      incident_id: incidentId,
    }, this.key());
    try { await writeExclusiveJson(file, value); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const existing = assertRetirement(parseStrictJson(await readFile(file, "utf8")), file, this.key());
      if (existing.registry_identity !== record.registry_identity || existing.policy_id !== policyId || existing.policy_version !== policyVersion || existing.incident_id !== incidentId) throw new PolicyRegistryIntegrityError(`retirement tombstone conflicts with policy ${policyId}@${policyVersion}`);
      return existing;
    }
    return assertRetirement(parseStrictJson(await readFile(file, "utf8")), file, this.key());
  }
}

export function policyRegistryInputFromJson(value: unknown): RegistryPolicyInput {
  if (!value || typeof value !== "object") throw new PolicyRegistryIntegrityError("policy input JSON must be an object");
  const candidate = value as Record<string, unknown>;
  const source = candidate.policy && typeof candidate.policy === "object" ? candidate.policy as Record<string, unknown> : candidate;
  const sanitized = { ...source };
  const forbidden = ["source_provider", "source_event_type", "repository_id", "repository_full_name", "ref", "secret_path", "enabled", "actual_creation_timestamp", "creation_commit_or_registry_identity", "provenance"];
  for (const field of forbidden) delete sanitized[field];
  return sanitized as unknown as RegistryPolicyInput;
}
