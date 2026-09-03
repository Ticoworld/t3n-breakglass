import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { connectTenant, redactError } from "../../scripts/lib.js";
import { invokeC1OperatorSession } from "./t3n.js";
import { CONTRACT_TAIL, CONTRACT_VERSION, GITHUB_OWNER, GITHUB_REPOSITORY, contractName } from "./constants.js";
import { appConfigFromEnvironment, appJwt, exactKey, listInstallationRepositories, listKeys, mintInstallationToken, revokeInstallationToken, validateInstallation } from "../broker/github-app.js";

const root = path.resolve(import.meta.dirname, "../..");
const OPERATOR_DID = "did:t3n:adb9365ee986cc6d0cb4006580782fe6fc7a431f";
const INCIDENT_ID = "C1-1788441029399";
const TARGET_ID = 162181065;

function isObject(value: unknown): value is Record<string, unknown> { return Boolean(value) && typeof value === "object" && !Array.isArray(value); }
function parsed(value: unknown): Record<string, unknown> { const result = typeof value === "string" ? JSON.parse(value) : value; if (!isObject(result)) throw new Error("response was not an object"); return result; }
function targetMetadata(value: unknown): Record<string, unknown> | null { if (!isObject(value)) return null; return { id: value.id ?? null, title: value.title ?? null, read_only: value.read_only ?? null, private: value.private ?? null }; }
function safeActivity(value: unknown): unknown {
  const rows = Array.isArray(value) ? value : isObject(value) && Array.isArray(value.entries) ? value.entries : [];
  if (!rows.length) return { shape: isObject(value) ? Object.keys(value).sort() : typeof value };
  return rows.map((entry) => {
    if (!isObject(entry)) return null;
    const output: Record<string, unknown> = {};
    for (const key of ["seq_no", "sequence", "hash", "timestamp", "actor", "caller", "on_behalf_of", "org", "organization", "contract", "function", "function_name", "outcome", "result"]) if (entry[key] !== undefined) output[key] = entry[key];
    return output;
  });
}

async function main(): Promise<void> {
  const forbidden = ["GITHUB_PAT", "AGENT_T3N_API_KEY", "EFFECT_BROKER_T3N_API_KEY"].filter((name) => Boolean(process.env[name]));
  if (forbidden.length) throw new Error(`failure inspection refuses fallback credentials: ${forbidden.join(",")}`);
  const targetSetup = parsed(await readFile(path.join(root, "winner", "evidence", "target-setup.json"), "utf8"));
  const recordedTarget = isObject(targetSetup.target) ? targetSetup.target : {};
  if (Number(recordedTarget.id) !== TARGET_ID || recordedTarget.title === undefined || recordedTarget.read_only !== true || recordedTarget.repository !== `${GITHUB_OWNER}/${GITHUB_REPOSITORY}`) throw new Error("target metadata does not match the exact failed-run target");
  const { t3n, tenantDid, nodeUrl } = await connectTenant();
  if (tenantDid !== OPERATOR_DID) throw new Error("operator DID mismatch");
  const contract = contractName(OPERATOR_DID);
  const stateRaw = await invokeC1OperatorSession(t3n, contract, "get-incident", { incident_id: INCIDENT_ID });
  const state = parsed(stateRaw);
  let activity: unknown;
  try { activity = safeActivity(await t3n.getActivityLog({ contract: CONTRACT_TAIL, limit: 200 })); } catch (error) { activity = { read_succeeded: false, error: redactError(error, [process.env.T3N_API_KEY ?? ""]) }; }
  const config = appConfigFromEnvironment(process.env);
  const jwt = await appJwt(config);
  const installation = await validateInstallation(config, jwt);
  if (installation.status !== 200) throw new Error(`inspection installation validation failed HTTP ${installation.status}`);
  const minted = await mintInstallationToken(config, jwt);
  if (!minted.token) throw new Error(`inspection token mint failed HTTP ${minted.response.status}`);
  const token = minted.token;
  let revoked = false;
  let evidence: Record<string, unknown> | undefined;
  try {
    const repositories = await listInstallationRepositories(token);
    const exact = await exactKey(token, config.owner, config.repository, TARGET_ID);
    const list = await listKeys(token, config.owner, config.repository);
    const listRows = Array.isArray(list.body) ? list.body : [];
    const targetRow = listRows.find((row) => isObject(row) && Number(row.id) === TARGET_ID);
    evidence = {
      phase: "C1-R6 failed-run read-only reconciliation",
      status: "C1_FAIL_RECONCILED_NO_RETRY",
      failure_stage: "post-run pass-criteria check / final authority readback",
      failure_reason: "The live runner raised its effect-safe kill condition. Read-only final state was EFFECT_CLAIMED with effect_attempts=0 and no final classification, so C1 did not reach the required CLOSED terminal state.",
      manual_recovery_required: true,
      incident_id: INCIDENT_ID,
      operator_did: tenantDid,
      contract: { name: contract, version: CONTRACT_VERSION },
      target: { owner: GITHUB_OWNER, repository: GITHUB_REPOSITORY, deploy_key_id: TARGET_ID, title: recordedTarget.title, read_only: recordedTarget.read_only, metadata_match: true },
      final_t3n_authority: { response: state, read_only_call: true },
      host_activity: { classification: "HOST_ACTIVITY", entries: activity, limitations: ["Host-stamped metadata only; not a Merkle proof, body commitment, or complete causal receipt."] },
      provider_reconciliation: {
        inspection_token_scope: { repository_selection: minted.metadata.repository_selection ?? null, permissions: minted.metadata.permissions ?? null, expires_at: minted.metadata.expires_at ?? null, repository_list_http_status: repositories.status },
        exact_get: { http_status: exact.status, target: targetMetadata(exact.body) },
        list_get: { http_status: list.status, body_valid: Array.isArray(list.body), target_present: Boolean(targetRow), target: targetMetadata(targetRow) },
        delete_performed_by_inspector: false,
        installation_token_revoked: true,
        broker_delete_acknowledgement: "NOT_RECONSTRUCTIBLE_FROM_DISCARDED_RUN_OUTPUT",
        delete_may_have_been_initiated: true,
        blind_retry_forbidden: true,
        target_cleanup_required: false,
      },
      live_run_counters: { target_created: 1, broker_delete_count_observed: null, broker_effect_token_mint_count_observed: null, replay_effect_token_mint_count_observed: null, provider_mutations_by_inspector: 0, automatic_retries: 0 },
      run_trace: { barrier_directory_observed: true, incident_id_from_barrier: INCIDENT_ID, broker_ready_files_observed: 2, replay_ready_file_observed: true, pass_artifact_written: false },
      counters: { inspection_operator_get_calls: 1, inspection_installation_tokens_minted: 1, inspection_provider_mutations: 0, automatic_retry_count: 0 },
      credential_safety: { pat_used: false, credentials_in_evidence: false, installation_token_in_evidence: false, jwt_in_evidence: false, authorization_header_in_evidence: false, private_key_in_evidence: false, ssh_private_key_in_evidence: false, t3n_api_key_in_evidence: false },
      classification: "C1_FAIL — live pass gate failed; run reconciled read-only and no retry performed",
    };
  } finally {
    const revoke = await revokeInstallationToken(token);
    revoked = revoke.status === 204;
    if (!revoked) throw new Error(`inspection token revoke failed HTTP ${revoke.status}`);
  }
  if (!revoked) throw new Error("inspection token was not revoked");
  if (!evidence) throw new Error("failure evidence was not constructed");
  await writeFile(path.join(root, "winner", "evidence", "C1-R6-LIVE-FAILURE.json"), JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify({ status: evidence.status, incident_id: INCIDENT_ID, final_state: state, provider: evidence.provider_reconciliation, activity: evidence.host_activity }, null, 2));
}

main().catch((error) => { console.error(`C1 failure inspection failed: ${redactError(error, [process.env.T3N_API_KEY ?? ""])}`); process.exitCode = 1; });
