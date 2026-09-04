import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { connectTenant } from "../../scripts/lib.js";
import { invokeC1, invokeC1OperatorSession, redact, requireValue } from "./t3n.js";
import { CONTRACT_VERSION, BROKER_FUNCTIONS, RESERVATION_FUNCTION, contractName } from "./constants.js";
import { parseChildJson } from "./child-protocol.js";

const root = path.resolve(import.meta.dirname, "../..");
const EXPECTED_OPERATOR_DID = "did:t3n:adb9365ee986cc6d0cb4006580782fe6fc7a431f";
const EXPECTED_CONTRACT_ID = 878;
const REGISTRATION_EVIDENCE = path.join(root, "winner", "evidence", "C1-R6B-R4B-REGISTRATION.json");
const EVIDENCE_PATH = path.join(root, "winner", "evidence", "C1-R6B-R4C-LIVE-CLAIM-OWNERSHIP.json");

function envFileValue(contents: string, name: string): string {
  const line = contents.split(/\r?\n/).find((entry) => entry.startsWith(`${name}=`));
  if (!line) throw new Error(`${name} missing from environment file`);
  return line.slice(name.length + 1).trim().replace(/^['"]|['"]$/g, "");
}

async function envValue(file: string, name: string): Promise<string> {
  return envFileValue(await readFile(path.join(root, file), "utf8"), name);
}

function objectResult(raw: unknown): Record<string, unknown> {
  const value = typeof raw === "string" ? JSON.parse(raw) : raw;
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Terminal 3 result was not an object");
  return value as Record<string, unknown>;
}

function childEnv(base: NodeJS.ProcessEnv, additions: Record<string, string>): NodeJS.ProcessEnv {
  const env = { ...base };
  for (const key of Object.keys(env)) {
    if (key === "T3N_API_KEY" || key === "AGENT_T3N_API_KEY" || key === "EFFECT_BROKER_T3N_API_KEY" || key === "GITHUB_PAT" || key.startsWith("GITHUB_")) delete env[key];
  }
  Object.assign(env, additions);
  return env;
}

function runChild(args: string[], env: NodeJS.ProcessEnv): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, args, { cwd: root, env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += String(chunk); });
    child.stderr.on("data", (chunk) => { stderr += String(chunk); });
    child.on("close", (code) => resolve({ stdout, stderr, code: code ?? 1 }));
  });
}

async function waitFor(file: string, timeoutMs = 120_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!existsSync(file)) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${file}`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

async function readJson(file: string): Promise<Record<string, unknown>> {
  return JSON.parse(await readFile(file, "utf8")) as Record<string, unknown>;
}

function requireResponse(raw: unknown, result: string, functionName: string): Record<string, unknown> {
  const response = objectResult(raw);
  if (response.result !== result || response.function !== functionName) throw new Error(`${functionName} did not return ${result}`);
  return response;
}

function requireAuthority(response: Record<string, unknown>, incidentId: string, state: string): Record<string, unknown> {
  if (response.incident_id !== incidentId || response.state !== state || response.effect_attempts !== 0) throw new Error("unexpected live authority state");
  return response;
}

async function main(): Promise<void> {
  if (process.env.GITHUB_PAT) throw new Error("R4C refuses GitHub provider credentials");
  const operatorDid = requireValue("C1_OPERATOR_DID");
  if (operatorDid !== EXPECTED_OPERATOR_DID) throw new Error("unexpected fixed operator DID");
  const remediationDid = await envValue(".env.replacement-agent", "REPLACEMENT_AGENT_DID");
  const remediationKey = await envValue(".env.replacement-agent", "REPLACEMENT_AGENT_T3N_API_KEY");
  const brokerDid = await envValue(".env.effect-broker", "EFFECT_BROKER_DID");
  const brokerKey = await envValue(".env.effect-broker", "EFFECT_BROKER_T3N_API_KEY");
  const contract = contractName(operatorDid);
  const registration = JSON.parse(await readFile(REGISTRATION_EVIDENCE, "utf8")) as { registration?: { name?: string; version?: string; contract_id?: number }; local_artifact?: { sha256?: string; bytes?: number } };
  if (registration.registration?.name !== contract || registration.registration.version !== CONTRACT_VERSION || registration.registration.contract_id !== EXPECTED_CONTRACT_ID || registration.local_artifact?.sha256 !== "ca7032b112b837b06e4334c10bca8820447f6ea1756b74db9bccd3181ad4d5d0" || registration.local_artifact.bytes !== 227011) throw new Error("R4B registration evidence does not identify exact 2.0.4/878");

  const { tenant, tenantDid, nodeUrl, t3n } = await connectTenant();
  if (tenantDid !== EXPECTED_OPERATOR_DID) throw new Error("operator authentication mismatch");
  const listed = (await tenant.contracts.listDetailed()).contracts.find((item) => item.name === contract);
  if (!listed || listed.version !== CONTRACT_VERSION || listed.status !== "active") throw new Error("registered 2.0.4 contract is not active in live inventory");

  const runDir = path.join(os.tmpdir(), `breakglass-c1-r4c-${Date.now()}-${randomBytes(6).toString("hex")}`);
  await mkdir(runDir, { recursive: true });
  const incidentId = `C1-R6B-R4C-${Date.now()}-${randomBytes(8).toString("hex")}`;
  const createResponse = requireResponse(await invokeC1OperatorSession(t3n, contract, "create-incident", { incident_id: incidentId, remediation_agent_did: remediationDid, effect_broker_did: brokerDid, deploy_key_id: 1, ttl_secs: 900 }), "WON", "create-incident");
  requireAuthority(createResponse, incidentId, "ACTIVE");

  const reserveRun = await runChild(["--import", "tsx", path.join(root, "winner", "scripts", "reserve-agent.ts")], childEnv(process.env, { AGENT_T3N_API_KEY: remediationKey, AGENT_DID: remediationDid, C1_OPERATOR_DID: operatorDid, C1_INCIDENT_ID: incidentId }));
  if (reserveRun.code !== 0) throw new Error(`reserve child failed: ${reserveRun.stderr.slice(0, 500)}`);
  const reserveDocument = objectResult(parseChildJson(reserveRun.stdout));
  const reserveResponse = requireResponse(reserveDocument.result, "WON", RESERVATION_FUNCTION);
  if (reserveResponse.state !== "RESERVED" || reserveResponse.effect_attempts !== 0) throw new Error("incident did not reach RESERVED claimable state");

  const barrier = path.join(runDir, "release");
  const childAReady = path.join(runDir, "a.ready");
  const childBReady = path.join(runDir, "b.ready");
  const childAResult = path.join(runDir, "a.result.json");
  const childBResult = path.join(runDir, "b.result.json");
  const common = { C1_R6B_INCIDENT_ID: incidentId, C1_OPERATOR_DID: operatorDid, C1_R6B_EXPECTED_CLAIM_VERSION: "0", C1_R6B_BARRIER_FILE: barrier };
  const base = childEnv(process.env, { EFFECT_BROKER_T3N_API_KEY: brokerKey, EFFECT_BROKER_DID: brokerDid, ...common });
  const aPromise = runChild(["--import", "tsx", path.join(root, "winner", "scripts", "c1-r6b-claim-contender.ts")], { ...base, C1_R6B_CONTENDER: "broker-a", C1_R6B_READY_FILE: childAReady, C1_R6B_RESULT_FILE: childAResult });
  const bPromise = runChild(["--import", "tsx", path.join(root, "winner", "scripts", "c1-r6b-claim-contender.ts")], { ...base, C1_R6B_CONTENDER: "broker-b", C1_R6B_READY_FILE: childBReady, C1_R6B_RESULT_FILE: childBResult });
  await waitFor(childAReady);
  await waitFor(childBReady);
  const readyA = await readJson(childAReady);
  const readyB = await readJson(childBReady);
  const nonceA = String(readyA.contender_nonce ?? "");
  const nonceB = String(readyB.contender_nonce ?? "");
  if (!/^[0-9a-f]{32}$/.test(nonceA) || !/^[0-9a-f]{32}$/.test(nonceB) || nonceA === nonceB) {
    await writeFile(barrier, JSON.stringify({ abort: true, reason: "invalid_or_duplicate_nonce", incident_id: incidentId }));
    await Promise.all([aPromise, bPromise]);
    throw new Error("contender nonce barrier failed");
  }
  await writeFile(barrier, JSON.stringify({ released_at_unix_ms: Date.now(), incident_id: incidentId }));
  await waitFor(childAResult);
  await waitFor(childBResult);
  const [childA, childB] = await Promise.all([aPromise, bPromise]);
  if (childA.code !== 0 || childB.code !== 0) throw new Error(`claim contender failed: ${childA.stderr.slice(0, 500)} ${childB.stderr.slice(0, 500)}`);
  const contenders = [await readJson(childAResult), await readJson(childBResult)];
  if (contenders.some((item) => Number(item.provider_operations ?? 0) !== 0 || item.token_minted === true || Number(item.destructive_call_count ?? 0) !== 0)) throw new Error("claim race reported provider activity");

  const claimIds = contenders.map((item) => typeof item.claim_id === "string" ? item.claim_id : `claim-1-${String(item.contender_nonce ?? "")}`);
  if (new Set(claimIds).size !== 2) throw new Error("contender claim identities are not distinct");
  const confirmations = [] as Array<Record<string, unknown>>;
  for (const claimId of claimIds) confirmations.push(objectResult(await invokeC1(brokerKey, nodeUrl, contract, "confirm-claim", { incident_id: incidentId, claim_id: claimId })));
  const confirmed = confirmations.filter((item) => item.result === "CONFIRMED");
  const notOwner = confirmations.filter((item) => item.result === "NOT_OWNER");
  if (confirmed.length !== 1 || notOwner.length !== 1 || confirmed[0].function !== "confirm-claim" || notOwner[0].function !== "confirm-claim") throw new Error("live confirmation did not produce exactly one owner and one NOT_OWNER");
  const confirmedDetail = confirmed[0].detail;
  if (!confirmedDetail || typeof confirmedDetail !== "object" || Array.isArray(confirmedDetail) || !(confirmedDetail as Record<string, unknown>).action || Object.keys(confirmedDetail as Record<string, unknown>).length < 5) throw new Error("confirmed claim did not return target-bearing detail");
  if (!notOwner[0].detail || typeof notOwner[0].detail !== "object" || Array.isArray(notOwner[0].detail) || Object.keys(notOwner[0].detail as Record<string, unknown>).length !== 0) throw new Error("losing confirmation exposed target detail");

  const winnerIndex = confirmations.findIndex((item) => item.result === "CONFIRMED");
  const loserIndex = confirmations.findIndex((item) => item.result === "NOT_OWNER");
  const stableWinner = objectResult(await invokeC1(brokerKey, nodeUrl, contract, "confirm-claim", { incident_id: incidentId, claim_id: claimIds[winnerIndex] }));
  const stableLoser = objectResult(await invokeC1(brokerKey, nodeUrl, contract, "confirm-claim", { incident_id: incidentId, claim_id: claimIds[loserIndex] }));
  if (stableWinner.result !== "CONFIRMED" || stableLoser.result !== "NOT_OWNER") throw new Error("confirmation stability check failed");

  const staleNonce = randomBytes(16).toString("hex");
  const stale = objectResult(await invokeC1(brokerKey, nodeUrl, contract, "claim-effect", { incident_id: incidentId, expected_claim_version: 0, contender_nonce: staleNonce }));
  if (stale.result !== "LOST" || stale.state !== "EFFECT_CLAIMED" || stale.effect_attempts !== 0) throw new Error("stale contender was not rejected without consuming effect budget");
  const finalReadback = objectResult(await invokeC1OperatorSession(t3n, contract, "get-incident", { incident_id: incidentId }));
  const finalDetail = finalReadback.detail;
  if (finalReadback.result !== "FOUND" || finalReadback.state !== "EFFECT_CLAIMED" || finalReadback.effect_attempts !== 0 || !finalDetail || typeof finalDetail !== "object" || (finalDetail as Record<string, unknown>).effect_claim_version !== 1) throw new Error("post-race authority readback is not claim-only");

  const evidence = {
    phase: "C1-R6B-R4C registered live claim-ownership race",
    status: "PASS_REGISTERED_2_0_4_LIVE_CLAIM_OWNERSHIP_PROVEN",
    evidence_tier: "LIVE_T3N_TESTNET",
    environment: "testnet",
    t3n: { node: nodeUrl, contract, contract_id: EXPECTED_CONTRACT_ID, version: CONTRACT_VERSION, registration_inventory: listed },
    incident: { incident_id: incidentId, synthetic_deploy_key_id: 1, create_response: createResponse, reserve_response: reserveResponse, effect_budget_after_reserve: 0 },
    contenders: { both_ready: true, nonce_barrier: { distinct: true, parent_check_is_harness_hygiene: true }, rows: contenders, proposal_claim_ids: claimIds },
    confirmations: { first: confirmations[0], second: confirmations[1], stable_winner: stableWinner, stable_loser: stableLoser, exactly_one_target_bearing: true, loser_targetless: true },
    stale_contender: { nonce: staleNonce, response: stale, rejected: true },
    final_authority_readback: finalReadback,
    forbidden_operations: { begin_effect: 0, confirm_effect_start: 0, finalize_effect: 0, reconcile_effect: 0, provider_operations: 0, github_api_calls: 0 },
    invocation_identifiers: { create: createResponse, reserve: reserveDocument, contenders: contenders.map((item) => item.response ?? null), confirmations, stale: stale, final_readback: finalReadback },
    configuration_changes: { contract_registration: { version: CONTRACT_VERSION, contract_id: EXPECTED_CONTRACT_ID, unchanged: true }, delegation: { remediation: { functions: [RESERVATION_FUNCTION], version_req: CONTRACT_VERSION }, broker: { functions: [...BROKER_FUNCTIONS], version_req: CONTRACT_VERSION }, purpose: "minimum invocation configuration only" }, map_acl: { existing_private_map: "winner-incidents", writers_and_readers_contract_id: EXPECTED_CONTRACT_ID, purpose: "minimum map access for registered contract" } },
    credentials_in_evidence: false,
  };
  await writeFile(EVIDENCE_PATH, JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify({ status: evidence.status, incident_id: incidentId, contract_id: EXPECTED_CONTRACT_ID, contenders: contenders.map((item) => ({ contender: item.contender, nonce: item.contender_nonce, claim_id: item.claim_id ?? null, result: item.response && (item.response as Record<string, unknown>).result })), confirmations: confirmations.map((item) => ({ result: item.result, detail_keys: item.detail && typeof item.detail === "object" ? Object.keys(item.detail as Record<string, unknown>) : [] })), stale_result: stale.result, effect_attempts: finalReadback.effect_attempts, evidence: "winner/evidence/C1-R6B-R4C-LIVE-CLAIM-OWNERSHIP.json" }, null, 2));
}

main().catch((error) => { console.error(`R4C live claim race failed: ${redact(error, [process.env.T3N_API_KEY ?? "", process.env.AGENT_T3N_API_KEY ?? "", process.env.EFFECT_BROKER_T3N_API_KEY ?? ""])}`); process.exitCode = 1; });
