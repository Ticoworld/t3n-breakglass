import { mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { spawn } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { connectTenant } from "../scripts/lib.js";

const root = path.resolve(import.meta.dirname, "..");
const wasmPath = path.join(root, "research", "C-0R-occ-probe", "target", "wasm32-wasip2", "release", "c0r_occ_probe.wasm");
const version = "0.1.0";

function safeError(error: unknown): Record<string, unknown> {
  const apiKey = process.env.T3N_API_KEY ?? "";
  const message = error instanceof Error ? error.message : String(error);
  return { message: apiKey ? message.split(apiKey).join("[REDACTED_T3N_API_KEY]") : message };
}

function runChild(env: NodeJS.ProcessEnv): Promise<{ stdout: string; stderrPresent: boolean; exitCode: number | null }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--import", "tsx", path.join(root, "research", "c0r-occ-child.ts")], {
      cwd: root,
      env,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += String(chunk); });
    child.stderr.on("data", (chunk) => { stderr += String(chunk); });
    child.on("close", (code) => resolve({ stdout, stderrPresent: stderr.length > 0, exitCode: code }));
  });
}

if (process.env.GITHUB_PAT) throw new Error("occ runner refuses GITHUB_PAT");
const startedAt = Date.now();
const tail = `c0r-occ-${startedAt}`;
const targetId = `fresh-target-${startedAt}`;
const barrierDir = await mkdir(path.join(os.tmpdir(), `c0r-occ-${startedAt}`), { recursive: true }).then(() => path.join(os.tmpdir(), `c0r-occ-${startedAt}`));
const barrier = path.join(barrierDir, "release");
const { tenant, tenantDid, t3n } = await connectTenant();
const evidence: Record<string, unknown> = {
  experiment: "R2 current KV/OCC reservation",
  date_utc: new Date().toISOString(),
  sdk_version: "@terminal3/t3n-sdk 5.2.0",
  node_environment: "testnet",
  contract_tail: tail,
  contract_version: version,
  map_tail: "c0r-occ-reservations",
  target_id: targetId,
  common_launch_barrier: { path: "omitted", created_by_runner: true },
  caller_credentials_in_evidence: false,
};

try {
  const registration = await tenant.contracts.register({ tail, version, wasm: new Uint8Array(await readFile(wasmPath)) });
  evidence.registration = registration;
  try {
    await tenant.maps.create({ tail: "c0r-occ-reservations", visibility: "private", writers: { only: [registration.contract_id] }, readers: { only: [registration.contract_id] } });
    evidence.map_acl = "created";
  } catch (error) {
    if (!/already exists/i.test(error instanceof Error ? error.message : String(error))) throw error;
    await tenant.maps.update("c0r-occ-reservations", { writers: { only: [registration.contract_id] }, readers: { only: [registration.contract_id] } });
    evidence.map_acl = "repointed";
  }

  const children = ["contender-a", "contender-b"].map((contenderId) => runChild({
    ...process.env,
    GITHUB_PAT: undefined,
    C0R_BARRIER_FILE: barrier,
    C0R_READY_FILE: path.join(barrierDir, `${contenderId}.ready`),
    C0R_OCC_TAIL: tail,
    C0R_OCC_VERSION: version,
    C0R_TARGET_ID: targetId,
    C0R_CONTENDER_ID: contenderId,
  }));
  const readyPaths = ["contender-a", "contender-b"].map((id) => path.join(barrierDir, `${id}.ready`));
  const deadline = Date.now() + 60_000;
  while (!readyPaths.every(existsSync) && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 25));
  evidence.ready_files_observed = await Promise.all(readyPaths.map(async (readyPath) => ({ path: "omitted", exists: existsSync(readyPath), contents: existsSync(readyPath) ? JSON.parse(await readFile(readyPath, "utf8")) : null })));
  evidence.barrier_released_at_unix_ms = Date.now();
  await writeFile(barrier, JSON.stringify({ released_at_unix_ms: Date.now(), target_id: targetId }));
  const childResults = await Promise.all(children);
  evidence.invocations = childResults.map((child) => {
    let parsed: unknown;
    try { parsed = JSON.parse(child.stdout); } catch { parsed = { non_json_stdout: child.stdout.slice(0, 200) }; }
    return { child: parsed, exit_code: child.exitCode, stderr_present: child.stderrPresent };
  });
  evidence.final_reservation = await tenant.maps.entryGet("c0r-occ-reservations", targetId);
  evidence.repeat_readback = await tenant.maps.entryGet("c0r-occ-reservations", targetId);
  evidence.contract_logs = await tenant.contracts.logs(tail, { limit: 100 });
  try { evidence.activity = await t3n.getActivityLog({ contract: tail, limit: 100 }); } catch (error) { evidence.activity = { error: safeError(error) }; }
} catch (error) {
  evidence.error = safeError(error);
}

await writeFile(path.join(root, "research", "C-0R-occ-result.json"), JSON.stringify(evidence, null, 2) + "\n");
console.log(JSON.stringify(evidence, null, 2));
