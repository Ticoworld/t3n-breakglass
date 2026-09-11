import { listDedupeRecords } from "../c2/dedupe.js";
import { loadDataDirectory, loadStateIntegrityKey, runtimePaths } from "./config.js";
import { RuntimeJobStore } from "./job-store.js";
import { PolicyRegistry } from "./policy-registry.js";

async function main(): Promise<void> {
  const paths = runtimePaths(loadDataDirectory());
  const key = loadStateIntegrityKey();
  const registry = new PolicyRegistry(paths.root, { stateIntegrityKey: key });
  const jobs = new RuntimeJobStore(paths.jobs, { stateIntegrityKey: key });
  await registry.initialize();
  await jobs.initialize();
  const [policies, retirements, receipts, runtimeJobs] = await Promise.all([registry.records(), registry.retirements(), listDedupeRecords(paths.receipts, { stateIntegrityKey: key }), jobs.list()]);
  process.stdout.write(`${JSON.stringify({
    policies: policies.map((record) => ({ policy_id: record.policy.policy_id, policy_version: record.policy.policy_version, activated_at: record.activated_at, registry_identity: record.registry_identity })),
    retirements: retirements.map((record) => ({ policy_id: record.policy_id, policy_version: record.policy_version, retired_at: record.retired_at, incident_id: record.incident_id })),
    receipts: receipts.map((record) => ({ dedupe_key: record.dedupe_key, state: record.state, policy_id: record.policy_id ?? null, policy_version: record.policy_version ?? null, incident_id: record.derived_incident_id ?? null })),
    jobs: runtimeJobs.map((job) => ({ job_id: job.job_id, incident_id: job.incident_id, state: job.state, remote_state: job.remote_state ?? null, claim_id: job.claim_id ?? null, effect_start_id: job.effect_start_id ?? null, provider_classification: job.provider_classification ?? null })),
  }, null, 2)}\n`);
}

main().catch((error) => { process.stderr.write(`breakglass inspect failed: ${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; });
