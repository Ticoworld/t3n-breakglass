import { mkdir, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import { redactError, required } from "./lib.js";
import { ensurePhase2DisposableTarget, verifyGithubAbsent, writePhase2TargetEvidence } from "./github.js";
import { persistPreparedIncident, prepareIncidentAuthority, renderIncidentPreview } from "./incident-create.js";

const execFileAsync = promisify(execFile);
const root = path.resolve(import.meta.dirname, "..");

async function runAgent(incidentId: string) {
  const agentEnv = { ...process.env };
  for (const name of ["GITHUB_PAT", "T3N_API_KEY", "AGENT_T3N_API_KEY", "AGENT_DID", "AGENT_ORGANISATION_DID"]) delete agentEnv[name];
  const result = await execFileAsync("node", [
    "--env-file-if-exists=.env.replacement-agent",
    "node_modules/tsx/dist/cli.mjs",
    "scripts/agent-execute.ts",
    incidentId,
  ], { cwd: root, env: agentEnv, maxBuffer: 1024 * 1024 });
  return JSON.parse(result.stdout.trim()) as Record<string, unknown>;
}

async function main() {
  const owner = required("GITHUB_OWNER");
  const repository = required("GITHUB_REPO");
  const target = await ensurePhase2DisposableTarget(owner, repository);
  await writePhase2TargetEvidence(target);
  console.log(`STEP 1 — deploy key exists\n${target.owner}/${target.repository}#${target.deployKeyId} (read-only=${target.readOnly === true})\n`);

  const runTag = String(Date.now());
  const nonexistentIncident = `INC-PHASE2-DEMO-NO-AUTHORITY-${runTag}`;
  const denied = await runAgent(nonexistentIncident);
  console.log(`STEP 2 — agent tries nonexistent authority\n${JSON.stringify(denied, null, 2)}\n`);
  if (denied.outcome !== "DENIED" || denied.destructive_call_count !== 0) throw new Error("demo denial step failed");

  const incidentId = `INC-PHASE2-DEMO-${runTag}`;
  const prepared = await prepareIncidentAuthority({ incidentId, owner, repository, deployKeyId: target.deployKeyId, ttlSeconds: 300 });
  console.log(`STEP 3 — operator preview\n${renderIncidentPreview(prepared.preview)}\nOperator confirmation: CONFIRMED by demo command\n`);
  const authority = await persistPreparedIncident(prepared);

  const executed = await runAgent(incidentId);
  console.log(`STEP 4 — agent executes with only incident_id\n${JSON.stringify(executed, null, 2)}\n`);
  if (executed.outcome !== "CONSUMED" || executed.destructive_call_count !== 1 || executed.destructive_call_http_status !== 204 || !executed.verification || (executed.verification as Record<string, unknown>).http_status !== 404) {
    throw new Error("demo execution step failed");
  }

  const after = await verifyGithubAbsent(owner, repository, target.deployKeyId);
  console.log(`STEP 5 — independent GitHub verification\n${JSON.stringify(after, null, 2)}\n`);
  if (!after.absent) throw new Error("demo independent verification failed");

  const replay = await runAgent(incidentId);
  console.log(`STEP 6 — replay consumed authority\n${JSON.stringify(replay, null, 2)}\n`);
  if (replay.outcome !== "REPLAY_REFUSED" || replay.destructive_call_count !== 0) throw new Error("demo replay step failed");

  await mkdir(path.join(root, "evidence"), { recursive: true });
  const evidence = {
    phase: "2",
    stage: "live_demo",
    status: "PASS",
    environment: "testnet",
    sdk: "@terminal3/t3n-sdk 5.2.0",
    target: { host: target.host, owner: target.owner, repository: target.repository, deploy_key_id: target.deployKeyId, read_only: target.readOnly, repository_private: target.repositoryPrivate },
    sequence: {
      denied: { incident_id: nonexistentIncident, result: denied },
      authority: { incident_id: incidentId, preview: prepared.preview, persisted: authority },
      executed,
      independent_github_after: after,
      replay,
    },
    secrets_printed: false,
    phase1_evidence_overwritten: false,
  };
  await writeFile(path.join(root, "evidence", "phase2-demo.json"), JSON.stringify(evidence, null, 2) + "\n");
  console.log("DEMO PASS — deny → authorize → DELETE 204 → verify 404 → consume → replay-deny");
  console.log("Evidence: evidence/phase2-demo.json");
}

main().catch((error) => {
  console.error(`demo failed: ${redactError(error, [process.env.GITHUB_PAT ?? "", process.env.T3N_API_KEY ?? ""])}`);
  process.exitCode = 1;
});
