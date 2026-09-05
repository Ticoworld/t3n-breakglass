import type { C2Policy } from "./types.js";

export interface LivePolicyProvenanceCheck {
  live: boolean;
  reasons: string[];
}

/**
 * A policy's payload timestamp is not evidence that a live policy existed.
 * Live use requires independent creation evidence and target fingerprinting.
 */
export function checkLivePolicyProvenance(policy: C2Policy): LivePolicyProvenanceCheck {
  const reasons: string[] = [];
  const provenance = policy.provenance;
  if (provenance.classification !== "LIVE_PROVENANCE") reasons.push("policy is explicitly marked fixture-only");
  if (!/^[0-9a-f]{40}$/i.test(provenance.source_commit_sha)) reasons.push("source commit SHA is missing or malformed");
  if (!provenance.durable_registry_identity) reasons.push("durable registry identity is missing");
  if (!provenance.actual_creation_timestamp || !Number.isFinite(Date.parse(provenance.actual_creation_timestamp))) reasons.push("actual creation timestamp evidence is missing");
  if (!provenance.creation_evidence) reasons.push("creation evidence reference is missing");
  if (provenance.enabled_before_event_proof !== true) reasons.push("enabled-before-event proof is missing");
  if (!policy.target_reference.expected_public_key_fingerprint || !/^SHA256\/[A-Za-z0-9+/]+={0,2}$/.test(policy.target_reference.expected_public_key_fingerprint)) {
    reasons.push("exact target public-key fingerprint is missing or malformed");
  }
  return { live: reasons.length === 0, reasons };
}
