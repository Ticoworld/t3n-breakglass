import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { connectTenant, redactError } from "../../scripts/lib.js";
import { trustedNodeTimeSeconds } from "../../scripts/product.js";
import { ACTION, CONTRACT_TAIL, CONTRACT_VERSION, GITHUB_OWNER, GITHUB_REPOSITORY, INCIDENT_MAP_TAIL } from "./constants.js";
import { invokeC1, requireValue, redact } from "./t3n.js";

const root = path.resolve(import.meta.dirname, "../..");

function envValue(contents: string, name: string): string { const value = contents.split(/\r?\n/).find((line) => line.startsWith(`${name}=`))?.slice(name.length + 1).trim(); if (!value) throw new Error(`${name} missing from environment file`); return value; }
async function readEnvFile(file: string, name: string): Promise<string> { return envValue(await readFile(path.join(root, file), "utf8"), name); }
function parseJson(stdout: string): any { const lines = stdout.trim().split(/\r?\n/).filter(Boolean); return JSON.parse(lines.at(-1) ?? ""); }
function run(command: string, args: string[], env: NodeJS.ProcessEnv): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => { const child = spawn(command, args, { cwd: root, env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] }); let stdout = ""; let stderr = ""; child.stdout.on("data", (chunk) => { stdout += String(chunk); }); child.stderr.on("data", (chunk) => { stderr += String(chunk); }); child.on("close", (code) => resolve({ stdout, stderr, code: code ?? 1 })); });
}
function childEnv(base: NodeJS.ProcessEnv, additions: Record<string, string>, remove: string[]): NodeJS.ProcessEnv { const env = { ...base }; for (const name of remove) delete env[name]; Object.assign(env, additions); return env; }

async function main() {
  if (process.env.GITHUB_PAT) throw new Error("C1 live runner refuses a GitHub PAT");
  const operatorDid = requireValue("C1_OPERATOR_DID");
  const remediationKey = await readEnvFile(".env.replacement-agent", "REPLACEMENT_AGENT_T3N_API_KEY");
  const remediationDid = await readEnvFile(".env.replacement-agent", "REPLACEMENT_AGENT_DID");
  const brokerKey = await readEnvFile(".env.effect-broker", "EFFECT_BROKER_T3N_API_KEY");
  const brokerDid = await readEnvFile(".env.effect-broker", "EFFECT_BROKER_DID");
  const actualBarrierDir = path.join(os.tmpdir(), `breakglass-c1-${Date.now()}`);
  await mkdir(actualBarrierDir, { recursive: true });
  const barrier = path.join(actualBarrierDir, "release");
  const { tenant, tenantDid, nodeUrl, t3n } = await connectTenant();
  if (tenantDid !== operatorDid) throw new Error("live runner authenticated as unexpected operator");
  const createdAt = await trustedNodeTimeSeconds(nodeUrl);
  const expiresAt = createdAt + 900;
  const incidentId = `C1-${Date.now()}`;
  const registration = JSON.parse(await readFile(path.join(root, "winner", "evidence", "contract-registration.json"), "utf8")) as { contract?: { name?: string } };
  const config = JSON.parse(await readFile(path.join(root, "winner", "evidence", "delegation-configuration.json"), "utf8")) as { remediation_agent_did?: string; effect_broker_did?: string };
  if (config.remediation_agent_did !== remediationDid || config.effect_broker_did !== brokerDid || !registration.contract?.name) throw new Error("live identity/configuration does not match the registered C1 contract");
  const targetChildEnv = childEnv(process.env, {}, ["T3N_API_KEY", "AGENT_T3N_API_KEY", "EFFECT_BROKER_T3N_API_KEY", "GITHUB_PAT"]);
  const targetRun = await run(process.execPath, ["--import", "tsx", path.join(root, "winner", "broker", "prepare-target.ts")], targetChildEnv);
  if (targetRun.code !== 0) throw new Error(`target setup failed: ${redact(targetRun.stderr, [brokerKey])}`);
  const targetSetup = parseJson(targetRun.stdout);
  const target = targetSetup.target as { id: number; title: string; read_only: boolean };
  const authority = { incident_id: incidentId, remediation_agent_did: remediationDid, effect_broker_did: brokerDid, action: ACTION, github_owner: GITHUB_OWNER, github_repo: GITHUB_REPOSITORY, deploy_key_id: target.id, created_at: createdAt, expires_at: expiresAt, max_effects: 1, effect_attempts: 0, status: "ACTIVE", reservation_id: null, reservation_version: 0, effect_claim_id: null, effect_claim_version: 0, final_result_classification: null };
  const encoded = JSON.stringify(authority);
  await tenant.maps.entrySet(INCIDENT_MAP_TAIL, incidentId, encoded);
  const seedReadback = await tenant.maps.entryGet(INCIDENT_MAP_TAIL, incidentId);
  if (seedReadback !== encoded) throw new Error("live authority seed readback mismatch");
  const reserveEnv = childEnv(process.env, { AGENT_T3N_API_KEY: remediationKey, AGENT_DID: remediationDid, C1_OPERATOR_DID: operatorDid, C1_INCIDENT_ID: incidentId }, ["T3N_API_KEY", "GITHUB_PAT", "EFFECT_BROKER_T3N_API_KEY"]);
  const reserveChild = await run(process.execPath, ["--import", "tsx", path.join(root, "winner", "scripts", "reserve-agent.ts")], reserveEnv);
  if (reserveChild.code !== 0) throw new Error(`reserve failed: ${reserveChild.stderr.slice(0, 500)}`);
  const reserveResult = parseJson(reserveChild.stdout);
  const childA = path.join(actualBarrierDir, "broker-a.ready");
  const childB = path.join(actualBarrierDir, "broker-b.ready");
  const common = { C1_BARRIER_FILE: barrier, C1_OPERATOR_DID: operatorDid, C1_INCIDENT_ID: incidentId };
  const brokerBase = childEnv(process.env, { EFFECT_BROKER_T3N_API_KEY: brokerKey, EFFECT_BROKER_DID: brokerDid, ...common }, ["T3N_API_KEY", "AGENT_T3N_API_KEY", "GITHUB_PAT"]);
  const aPromise = run(process.execPath, ["--import", "tsx", path.join(root, "winner", "broker", "run.ts"), incidentId], { ...brokerBase, C1_READY_FILE: childA, C1_CONTENDER_ID: "broker-a" });
  const bPromise = run(process.execPath, ["--import", "tsx", path.join(root, "winner", "broker", "run.ts"), incidentId], { ...brokerBase, C1_READY_FILE: childB, C1_CONTENDER_ID: "broker-b" });
  const deadline = Date.now() + 120_000;
  while ((!existsSync(childA) || !existsSync(childB)) && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 25));
  if (!existsSync(childA) || !existsSync(childB)) throw new Error("broker race children did not reach the common barrier");
  await writeFile(barrier, JSON.stringify({ released_at_unix_ms: Date.now(), incident_id: incidentId }));
  const [a, b] = await Promise.all([aPromise, bPromise]);
  if (a.code !== 0 || b.code !== 0) throw new Error(`broker child failed: ${a.stderr.slice(0, 500)} ${b.stderr.slice(0, 500)}`);
  const brokers = [parseJson(a.stdout), parseJson(b.stdout)];
  const finalAuthority = await tenant.maps.entryGet(INCIDENT_MAP_TAIL, incidentId);
  let activity: unknown;
  try { activity = await t3n.getActivityLog({ contract: CONTRACT_TAIL, limit: 100 }); } catch (error) { activity = { error: redactError(error, [process.env.T3N_API_KEY ?? ""]) }; }
  const replayEnv = childEnv(process.env, { EFFECT_BROKER_T3N_API_KEY: brokerKey, EFFECT_BROKER_DID: brokerDid, C1_OPERATOR_DID: operatorDid, C1_READY_FILE: path.join(actualBarrierDir, "replay.ready"), C1_BARRIER_FILE: path.join(actualBarrierDir, "replay.release"), C1_CONTENDER_ID: "replay" }, ["T3N_API_KEY", "AGENT_T3N_API_KEY", "GITHUB_PAT"]);
  const replayReady = path.join(actualBarrierDir, "replay.ready");
  const replayRelease = path.join(actualBarrierDir, "replay.release");
  const replayPromise = run(process.execPath, ["--import", "tsx", path.join(root, "winner", "broker", "run.ts"), incidentId], replayEnv);
  const replayDeadline = Date.now() + 60_000;
  while (!existsSync(replayReady) && Date.now() < replayDeadline) await new Promise((resolve) => setTimeout(resolve, 25));
  if (!existsSync(replayReady)) throw new Error("replay broker did not reach the common barrier");
  await writeFile(replayRelease, "release");
  const replay = await replayPromise;
  if (replay.code !== 0) throw new Error(`replay broker failed: ${redact(replay.stderr, [brokerKey])}`);
  const replayObservation = parseJson(replay.stdout);
  const totalDelete = brokers.reduce((sum, item) => sum + Number(item.destructive_call_count ?? 0), 0);
  const totalTokens = brokers.filter((item) => item.token_minted === true).length;
  const statuses = brokers.map((item) => item.claim_outcome);
  if (statuses.filter((status) => status === "CLAIM_WON").length !== 1 || statuses.filter((status) => status === "CLAIM_LOST").length !== 1 || totalDelete !== 1 || totalTokens !== 1 || (finalAuthority ? JSON.parse(finalAuthority).status : null) !== "CLOSED" || replayObservation.claim_outcome !== "CLAIM_LOST" || replayObservation.token_minted !== false || Number(replayObservation.destructive_call_count ?? -1) !== 0) throw new Error("C1 kill condition: effect-safe race or replay did not meet the brutal pass criteria");
  const evidence = { experiment: "C1 effect-safe T3N reservation + JIT GitHub remediation", date_utc: new Date().toISOString(), branch: "winner-v2-core", t3n: { environment: "testnet", node: nodeUrl, sdk: "@terminal3/t3n-sdk 5.2.0", contract: registration.contract.name }, principals: { remediation_agent_did: remediationDid, effect_broker_did: brokerDid, operator_did: operatorDid }, incident_id: incidentId, target: { owner: "Ticoworld", repository: "t3n-breakglass-sandbox", deploy_key_id: target.id, title: target.title, read_only: target.read_only, private: true }, initial_authority: authority, reservation: { result: reserveResult, provider_mutations: 0 }, broker_race: { common_barrier: { both_ready: true, released: true }, contenders: brokers, token_minted_total: totalTokens, destructive_delete_total: totalDelete }, github_before_after: { independent_provider_observation: brokers.map((item) => ({ contender: item.contender, before: item.before, delete: item.delete, after: item.after, classification: item.classification })) }, final_t3n_authority: finalAuthority ? JSON.parse(finalAuthority) : null, replay: replayObservation, activity, credential_safety: { pat_used: false, jwt_in_evidence: false, installation_token_in_evidence: false, authorization_header_in_evidence: false, private_key_in_evidence: false, ssh_private_key_in_evidence: false }, classifications: { t3n_contract_claims: "contract-reported", github_state: "independent-provider-GET/list", token_scope: "GitHub-response metadata", activity: "host-stamped activity metadata" }, limitations: ["No real GitHub webhook ingress was used in C1.", "The GitHub App private key remains a standing trust root.", "Provider DELETE is one broker-issued attempt, not a provider-side exactly-once guarantee."] };
  await mkdir(path.join(root, "winner", "evidence"), { recursive: true });
  await writeFile(path.join(root, "winner", "evidence", "C1-live-proof.json"), JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify({ status: "C1_PASS", incident_id: incidentId, deploy_key_id: target.id, broker_race: { statuses, token_minted_total: totalTokens, destructive_delete_total: totalDelete }, evidence: "winner/evidence/C1-live-proof.json" }, null, 2));
}

main().catch((error) => { console.error(`C1 live proof failed: ${redactError(error, [process.env.T3N_API_KEY ?? "", process.env.AGENT_T3N_API_KEY ?? "", process.env.EFFECT_BROKER_T3N_API_KEY ?? "", process.env.GITHUB_PAT ?? ""])}`); process.exitCode = 1; });
