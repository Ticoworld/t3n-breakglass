import { access, constants, stat } from "node:fs/promises";
import path from "node:path";

import { appConfigFromEnvironment } from "../broker/github-app.js";
import { C2_PUSH_REF, C2_PUSH_REPOSITORY, C2_PUSH_SECRET_PATH } from "../c2/push-source.js";
import { CONTRACT_VERSION, contractName } from "../scripts/constants.js";
import { loadDataDirectory, loadStateIntegrityKey, runtimePaths } from "./config.js";
import { PolicyRegistry } from "./policy-registry.js";

type Check = { name: string; ok: boolean; detail: string };

function present(env: NodeJS.ProcessEnv, name: string): Check {
  return { name, ok: Boolean(env[name]), detail: env[name] ? "present" : "missing" };
}

async function directoryCheck(directory: string): Promise<Check> {
  try {
    const value = await stat(directory);
    await access(directory, constants.R_OK | constants.W_OK | constants.X_OK);
    return { name: `storage:${path.basename(directory)}`, ok: value.isDirectory(), detail: value.isDirectory() ? "readable/writable" : "not a directory" };
  } catch { return { name: `storage:${path.basename(directory)}`, ok: true, detail: "not initialized; runtime will create it" }; }
}

async function main(): Promise<void> {
  const checks: Check[] = [];
  const major = Number(process.versions.node.split(".")[0]);
  checks.push({ name: "node", ok: major >= 20, detail: process.versions.node });
  let stateIntegrityKey: ReturnType<typeof loadStateIntegrityKey> | undefined;
  try {
    stateIntegrityKey = loadStateIntegrityKey();
    checks.push({ name: "state_integrity_key", ok: true, detail: process.env.BREAKGLASS_STATE_INTEGRITY_KEY_FILE ? "external key file configured and valid" : "external secret configured and valid" });
  } catch (error) {
    checks.push({ name: "state_integrity_key", ok: false, detail: error instanceof Error ? error.message : String(error) });
  }
  for (const name of ["BREAKGLASS_DATA_DIRECTORY", "C2_WEBHOOK_SECRET", "T3N_API_KEY", "AGENT_T3N_API_KEY", "C1_OPERATOR_DID", "AGENT_DID", "EFFECT_BROKER_DID", "GITHUB_APP_ID", "GITHUB_APP_INSTALLATION_ID", "GITHUB_APP_PRIVATE_KEY_PATH"]) checks.push(present(process.env, name));
  checks.push({ name: "broker_environment", ok: true, detail: process.env.EFFECT_BROKER_T3N_API_KEY ? "broker key present in this environment" : "configure EFFECT_BROKER_T3N_API_KEY in the separate broker environment" });
  checks.push({ name: "github_pat", ok: !process.env.GITHUB_PAT, detail: process.env.GITHUB_PAT ? "forbidden" : "absent" });
  checks.push({ name: "proof_barriers", ok: !process.env.C1_BARRIER_FILE && !process.env.C1_PROPOSALS_COMPLETE_FILE && !process.env.C1_READY_FILE && !process.env.C1_EFFECT_START_READY_FILE && !process.env.C1_PRE_DELETE_RELEASE_FILE, detail: "absent" });
  try {
    const operator = process.env.C1_OPERATOR_DID;
    const remediation = process.env.AGENT_DID;
    const broker = process.env.EFFECT_BROKER_DID;
    const valid = [operator, remediation, broker].every((value) => typeof value === "string" && /^did:t3n:[0-9a-f]{40}$/i.test(value));
    checks.push({ name: "principal_identity", ok: valid && new Set([operator?.toLowerCase(), remediation?.toLowerCase(), broker?.toLowerCase()]).size === 3, detail: valid ? "valid and distinct" : "invalid or not distinct" });
    if (operator) { contractName(operator); checks.push({ name: "contract_identity", ok: true, detail: `${CONTRACT_VERSION} configured` }); }
    else checks.push({ name: "contract_identity", ok: false, detail: "operator DID missing" });
  } catch (error) { checks.push({ name: "contract_identity", ok: false, detail: error instanceof Error ? error.message : String(error) }); }
  try {
    const app = appConfigFromEnvironment(process.env);
    checks.push({ name: "github_app_shape", ok: true, detail: `installation ${app.installationId}; fixed repository ${app.owner}/${app.repository}` });
  } catch (error) { checks.push({ name: "github_app_shape", ok: false, detail: error instanceof Error ? error.message : String(error) }); }
  checks.push({ name: "fixed_source", ok: C2_PUSH_REPOSITORY === "Ticoworld/t3n-breakglass-sandbox" && C2_PUSH_REF === "refs/heads/c2-breakglass-demo" && C2_PUSH_SECRET_PATH === ".breakglass-c2/exposed-deploy-key", detail: `${C2_PUSH_REPOSITORY} ${C2_PUSH_REF} ${C2_PUSH_SECRET_PATH}` });
  try {
    const root = loadDataDirectory();
    const paths = runtimePaths(root);
    for (const directory of [root, paths.policies, paths.retirements, paths.receipts, paths.jobs, paths.results]) checks.push(await directoryCheck(directory));
    if ((await stat(paths.policies).catch(() => null))?.isDirectory() && (await stat(paths.retirements).catch(() => null))?.isDirectory()) {
      const registry = new PolicyRegistry(root, { stateIntegrityKey });
      try {
        const records = await registry.records();
        const retirements = await registry.retirements();
        checks.push({ name: "policy_registry", ok: true, detail: `${records.length} policy record(s), ${retirements.length} retirement(s)` });
      } catch (error) { checks.push({ name: "policy_registry", ok: false, detail: error instanceof Error ? error.message : String(error) }); }
    } else checks.push({ name: "policy_registry", ok: true, detail: "not initialized; no records to validate" });
  } catch (error) { checks.push({ name: "storage_configuration", ok: false, detail: error instanceof Error ? error.message : String(error) }); }
  for (const check of checks) process.stdout.write(`${check.ok ? "OK" : "FAIL"} ${check.name}: ${check.detail}\n`);
  if (checks.some((check) => !check.ok)) process.exitCode = 1;
}

main().catch((error) => { process.stderr.write(`breakglass doctor failed: ${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; });
