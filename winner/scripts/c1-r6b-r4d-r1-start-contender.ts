import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { writeAtomicJson } from "./result-file.js";
import { connectC1Principal, invokeC1, redact, requireValue } from "./t3n.js";
import { CONTRACT_VERSION, contractName } from "./constants.js";
import path from "node:path";
import { fileURLToPath } from "node:url";

function parseObject(value: unknown): Record<string, any> {
  const parsed = typeof value === "string" ? JSON.parse(value) : value;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Terminal 3 response was not an object");
  return parsed as Record<string, any>;
}

function safeError(error: unknown, secret: string): Record<string, unknown> {
  return { class: error instanceof Error ? error.constructor.name : typeof error, message: redact(error, [secret]) };
}

async function waitFor(file: string, timeoutMs = 120_000): Promise<Record<string, any>> {
  const deadline = Date.now() + timeoutMs;
  while (!existsSync(file)) {
    if (Date.now() > deadline) throw new Error("start barrier timeout");
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  return parseObject(await import("node:fs/promises").then(({ readFile }) => readFile(file, "utf8")));
}

async function main(): Promise<void> {
  if (process.env.T3N_API_KEY || process.env.GITHUB_PAT || Object.keys(process.env).some((key) => key.startsWith("GITHUB_") && Boolean(process.env[key]))) {
    throw new Error("R4D-R1 start contender refuses operator/provider credentials");
  }

  const incidentId = requireValue("C1_R4D_R1_INCIDENT_ID");
  const claimId = requireValue("C1_R4D_R1_CLAIM_ID");
  const operatorDid = requireValue("C1_OPERATOR_DID");
  const contender = requireValue("C1_R4D_R1_CONTENDER");
  const barrier = requireValue("C1_R4D_R1_BARRIER_FILE");
  const readyFile = requireValue("C1_R4D_R1_READY_FILE");
  const resultFile = requireValue("C1_R4D_R1_RESULT_FILE");

  const broker = await connectC1Principal("EFFECT_BROKER_T3N_API_KEY", "EFFECT_BROKER_DID");
  const startNonce = randomBytes(16).toString("hex");
  const ready = {
    phase: "C1-R6B-R4D-R1 start contender",
    contender,
    pid: process.pid,
    did: broker.did,
    incident_id: incidentId,
    claim_id: claimId,
    start_nonce: startNonce,
    ready_at_unix_ms: Date.now(),
    contract: contractName(operatorDid),
    version: CONTRACT_VERSION,
  };
  await writeAtomicJson(readyFile, ready);

  const barrierDocument = await waitFor(barrier);
  if (barrierDocument.abort === true) throw new Error("parent aborted the start barrier");

  const evidence: Record<string, any> = {
    ...ready,
    started_at_unix_ms: Date.now(),
    function: "begin-effect",
    provider_operations: 0,
    token_minted: false,
    destructive_call_count: 0,
    barrier_released_at_unix_ms: barrierDocument.released_at_unix_ms ?? null,
  };
  try {
    const response = parseObject(await invokeC1(broker.apiKey, broker.nodeUrl, contractName(operatorDid), "begin-effect", {
      incident_id: incidentId,
      claim_id: claimId,
      start_nonce: startNonce,
    }));
    evidence.response = response;
    evidence.raw_result = response.result ?? null;
    evidence.effect_start_id = response.detail?.effect_start_id ?? null;
  } catch (error) {
    evidence.raw_result = "TRANSPORT_OR_GUEST_ERROR";
    evidence.effect_start_id = null;
    evidence.error = safeError(error, broker.apiKey);
  }
  evidence.finished_at_unix_ms = Date.now();
  await writeAtomicJson(resultFile, evidence);
  process.stdout.write(JSON.stringify(evidence));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(async (error) => {
    const resultFile = process.env.C1_R4D_R1_RESULT_FILE;
    if (resultFile) {
      await writeAtomicJson(resultFile, {
        phase: "C1-R6B-R4D-R1 start contender",
        contender: process.env.C1_R4D_R1_CONTENDER ?? null,
        pid: process.pid,
        incident_id: process.env.C1_R4D_R1_INCIDENT_ID ?? null,
        claim_id: process.env.C1_R4D_R1_CLAIM_ID ?? null,
        function: "begin-effect",
        raw_result: "PROCESS_FAILURE",
        provider_operations: 0,
        token_minted: false,
        destructive_call_count: 0,
        error: String(error),
        finished_at_unix_ms: Date.now(),
      });
    }
    console.error(`R4D-R1 start contender failed: ${String(error)}`);
    process.exitCode = 1;
  });
}
