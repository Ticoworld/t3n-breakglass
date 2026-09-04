import { existsSync } from "node:fs";
import { open } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { writeAtomicJson } from "./result-file.js";
import { connectC1Principal, invokeC1, redact, requireValue } from "./t3n.js";
import { CONTRACT_VERSION, contractName } from "./constants.js";

function parseNonnegative(value: string, label: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new Error(`${label} must be a nonnegative safe integer`);
  return parsed;
}

function parseResult(value: unknown): Record<string, unknown> {
  const parsed = typeof value === "string" ? JSON.parse(value) : value;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("claim result was not an object");
  return parsed as Record<string, unknown>;
}

function safeError(error: unknown, secret: string): Record<string, unknown> {
  return { class: error instanceof Error ? error.constructor.name : typeof error, message: redact(error, [secret]) };
}

async function waitFor(file: string): Promise<void> {
  while (!existsSync(file)) await new Promise((resolve) => setTimeout(resolve, 5));
}

async function main(): Promise<void> {
  if (process.env.T3N_API_KEY || process.env.GITHUB_PAT || Object.keys(process.env).some((key) => key.startsWith("GITHUB_"))) throw new Error("R6B contender refuses operator/provider credentials");
  const incidentId = requireValue("C1_R6B_INCIDENT_ID");
  const operatorDid = requireValue("C1_OPERATOR_DID");
  const contender = requireValue("C1_R6B_CONTENDER");
  const expectedClaimVersion = parseNonnegative(requireValue("C1_R6B_EXPECTED_CLAIM_VERSION"), "C1_R6B_EXPECTED_CLAIM_VERSION");
  const barrier = requireValue("C1_R6B_BARRIER_FILE");
  const ready = requireValue("C1_R6B_READY_FILE");
  const resultFile = requireValue("C1_R6B_RESULT_FILE");
  const broker = await connectC1Principal("EFFECT_BROKER_T3N_API_KEY", "EFFECT_BROKER_DID");
  const contenderNonce = randomBytes(16).toString("hex");
  const evidence: Record<string, unknown> = { phase: "R6B state-only claim contender", contender, pid: process.pid, did: broker.did, incident_id: incidentId, expected_claim_version: expectedClaimVersion, contender_nonce: contenderNonce, contract: contractName(operatorDid), version: CONTRACT_VERSION, provider_operations: 0, ready_at_unix_ms: Date.now() };
  await writeAtomicJson(ready, { contender, pid: process.pid, ready_at_unix_ms: evidence.ready_at_unix_ms });
  await waitFor(barrier);
  evidence.started_at_unix_ms = Date.now();
  try {
    const raw = await invokeC1(broker.apiKey, broker.nodeUrl, contractName(operatorDid), "claim-effect", { incident_id: incidentId, expected_claim_version: expectedClaimVersion, contender_nonce: contenderNonce });
    const response = parseResult(raw);
    evidence.response = response;
    evidence.claim_outcome = response.result === "WON" ? "CLAIM_WON" : response.result === "LOST" ? "CLAIM_LOST" : "APPLICATION_RESULT";
    const detail = response.detail && typeof response.detail === "object" && !Array.isArray(response.detail) ? response.detail as Record<string, unknown> : {};
    evidence.claim_id = detail.claim_id ?? null;
    evidence.claim_version = detail.claim_version ?? (response.state === "EFFECT_CLAIMED" ? response.effect_claim_version ?? null : null);
    evidence.token_minted = false;
    evidence.destructive_call_count = 0;
  } catch (error) {
    evidence.claim_outcome = "TRANSPORT_OR_GUEST_ERROR";
    evidence.error = safeError(error, broker.apiKey);
    evidence.token_minted = false;
    evidence.destructive_call_count = 0;
  }
  evidence.finished_at_unix_ms = Date.now();
  await writeAtomicJson(resultFile, evidence);
  process.stdout.write(JSON.stringify(evidence));
}

main().catch(async (error) => {
  const resultFile = process.env.C1_R6B_RESULT_FILE;
  if (resultFile) await writeAtomicJson(resultFile, { phase: "R6B state-only claim contender", contender: process.env.C1_R6B_CONTENDER ?? null, pid: process.pid, incident_id: process.env.C1_R6B_INCIDENT_ID ?? null, claim_outcome: "PROCESS_FAILURE", provider_operations: 0, token_minted: false, destructive_call_count: 0, error: String(error), finished_at_unix_ms: Date.now() });
  console.error(`R6B contender failed: ${String(error)}`);
  process.exitCode = 1;
});
