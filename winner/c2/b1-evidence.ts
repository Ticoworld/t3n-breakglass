import { Buffer } from "node:buffer";

export type B1EvidenceObject = Record<string, unknown>;

/**
 * Single serialization boundary shared by the live runner and preflight.
 * Callers provide sanitized facts only; this helper never accepts private
 * material as a separate field.
 */
export function buildB1Evidence(fields: B1EvidenceObject): B1EvidenceObject {
  return {
    classification: "C2_B1_REAL_CAUSAL_SECRET_INTRODUCTION_PASS",
    ...fields,
  };
}

export function serializeB1Evidence(value: B1EvidenceObject): Buffer {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}
