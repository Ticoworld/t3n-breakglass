import { createHmac, timingSafeEqual } from "node:crypto";

export const RECEIPT_INTEGRITY_DOMAIN = "breakglass.receipt.v3";
export const POLICY_BINDING_INTEGRITY_DOMAIN = "breakglass.policy-binding.v1";
export const POLICY_RETIREMENT_INTEGRITY_DOMAIN = "breakglass.policy-retirement.v1";
export const JOB_INTEGRITY_DOMAIN = "breakglass.runtime-job.v1";

export interface IntegrityKeyRing {
  current: { id: string; value: Uint8Array };
  verify?: ReadonlyMap<string, Uint8Array>;
}

export type IntegrityKeyInput = string | Uint8Array | IntegrityKeyRing;

export interface IntegrityEnvelope {
  key_id: string;
  payload: unknown;
  mac: string;
}

export class IntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IntegrityError";
  }
}

/**
 * Small deterministic JSON canonicalizer for internal state envelopes. It
 * deliberately rejects values JSON.stringify would silently discard or
 * coerce, so the signed representation cannot have two meanings.
 */
export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0)) throw new IntegrityError("unsupported non-canonical number");
    return JSON.stringify(value);
  }
  if (typeof value !== "object" || value === undefined) throw new IntegrityError("unsupported value in canonical state");
  if (Array.isArray(value)) return `[${value.map((item) => canonicalize(item)).join(",")}]`;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new IntegrityError("unsupported non-plain object in canonical state");
  const object = value as Record<string, unknown>;
  const keys = Object.keys(object).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(object[key])}`).join(",")}}`;
}

/** Parse persisted JSON while rejecting duplicate object keys. JSON.parse by
 * itself keeps only the last duplicate key, which would make two raw state
 * documents represent the same signed object. */
export function parseStrictJson(text: string): unknown {
  const value = JSON.parse(text) as unknown;
  let offset = 0;
  const whitespace = () => { while (/\s/.test(text[offset] ?? "")) offset += 1; };
  const stringEnd = (): number => {
    if (text[offset] !== '"') throw new IntegrityError("invalid JSON string");
    offset += 1;
    while (offset < text.length) {
      const character = text[offset++];
      if (character === "\\") { if (offset >= text.length) throw new IntegrityError("invalid JSON escape"); offset += 1; continue; }
      if (character === '"') return offset;
      if (character < " ") throw new IntegrityError("invalid JSON control character");
    }
    throw new IntegrityError("unterminated JSON string");
  };
  const valueEnd = (): void => {
    whitespace();
    const character = text[offset];
    if (character === "{") {
      offset += 1;
      whitespace();
      const keys = new Set<string>();
      if (text[offset] === "}") { offset += 1; return; }
      for (;;) {
        const start = offset;
        const end = stringEnd();
        const key = JSON.parse(text.slice(start, end)) as string;
        if (keys.has(key)) throw new IntegrityError(`duplicate JSON object key: ${key}`);
        keys.add(key);
        whitespace();
        if (text[offset++] !== ":") throw new IntegrityError("invalid JSON object separator");
        valueEnd();
        whitespace();
        if (text[offset] === "}") { offset += 1; return; }
        if (text[offset++] !== ",") throw new IntegrityError("invalid JSON object delimiter");
        whitespace();
      }
    }
    if (character === "[") {
      offset += 1;
      whitespace();
      if (text[offset] === "]") { offset += 1; return; }
      for (;;) {
        valueEnd();
        whitespace();
        if (text[offset] === "]") { offset += 1; return; }
        if (text[offset++] !== ",") throw new IntegrityError("invalid JSON array delimiter");
        whitespace();
      }
    }
    if (character === '"') { stringEnd(); return; }
    if (text.startsWith("true", offset)) { offset += 4; return; }
    if (text.startsWith("false", offset)) { offset += 5; return; }
    if (text.startsWith("null", offset)) { offset += 4; return; }
    const number = text.slice(offset).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
    if (number) { offset += number[0].length; return; }
    throw new IntegrityError("invalid JSON value");
  };
  valueEnd();
  whitespace();
  if (offset !== text.length) throw new IntegrityError("trailing JSON data");
  return value;
}

function bytes(value: string | Uint8Array): Uint8Array {
  return typeof value === "string" ? Buffer.from(value, "utf8") : Buffer.from(value);
}

export function keyRing(input: IntegrityKeyInput, keyId = "current"): IntegrityKeyRing {
  if (typeof input === "object" && !(input instanceof Uint8Array) && "current" in input) {
    const current = { id: input.current.id, value: bytes(input.current.value) };
    if (!current.id || current.value.length < 32) throw new IntegrityError("state integrity key is too short");
    const verify = new Map<string, Uint8Array>(input.verify ? [...input.verify.entries()].map(([id, value]) => [id, bytes(value)]) : []);
    verify.set(current.id, current.value);
    for (const [id, value] of verify) if (!id || value.length < 32) throw new IntegrityError(`state integrity verify key ${id} is too short`);
    return { current, verify };
  }
  const current = { id: keyId, value: bytes(input as string | Uint8Array) };
  if (!current.id || current.value.length < 32) throw new IntegrityError("state integrity key is too short");
  return { current, verify: new Map([[current.id, current.value]]) };
}

function macInput(domain: string, keyId: string, payload: unknown): Buffer {
  return Buffer.from(`${domain}\n${canonicalize({ key_id: keyId, payload })}`, "utf8");
}

export function signEnvelope(domain: string, payload: unknown, input: IntegrityKeyInput): IntegrityEnvelope {
  const ring = keyRing(input);
  const mac = createHmac("sha256", ring.current.value).update(macInput(domain, ring.current.id, payload)).digest("hex");
  return { key_id: ring.current.id, payload, mac };
}

export function verifyEnvelope<T>(domain: string, value: unknown, input: IntegrityKeyInput): T {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new IntegrityError("integrity envelope is not an object");
  const envelope = value as Partial<IntegrityEnvelope>;
  if (typeof envelope.key_id !== "string" || envelope.key_id.length === 0 || typeof envelope.mac !== "string" || !/^[0-9a-f]{64}$/i.test(envelope.mac) || envelope.payload === undefined) throw new IntegrityError("integrity envelope is incomplete");
  const ring = keyRing(input);
  const key = ring.verify?.get(envelope.key_id);
  if (!key) throw new IntegrityError(`unknown state integrity key id: ${envelope.key_id}`);
  const expected = createHmac("sha256", key).update(macInput(domain, envelope.key_id, envelope.payload)).digest();
  const received = Buffer.from(envelope.mac, "hex");
  if (received.length !== expected.length || !timingSafeEqual(received, expected)) throw new IntegrityError("state integrity MAC verification failed");
  return envelope.payload as T;
}

export function assertIntegrityKey(value: string | Uint8Array, label = "state integrity key"): Uint8Array {
  const result = bytes(value);
  if (result.length < 32) throw new IntegrityError(`${label} must contain at least 32 bytes`);
  return result;
}
