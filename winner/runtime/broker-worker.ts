import { spawn } from "node:child_process";
import { chmod, mkdir, readFile, unlink } from "node:fs/promises";
import path from "node:path";

import { verifyProviderTarget, type ProviderVerification } from "../broker/provider-verifier.js";
import { principalTransport, asC1Object } from "./c1-client.js";
import { connectC1Principal } from "../scripts/t3n.js";
import type { RuntimeConfig } from "./config.js";
import { RuntimeJobStore, type RuntimeJob } from "./job-store.js";
import { operationalLog } from "./logger.js";
import { PolicyRegistry } from "./policy-registry.js";

type BrokerPrincipal = Pick<Awaited<ReturnType<typeof connectC1Principal>>, "apiKey" | "nodeUrl" | "did">;

function childResultPath(config: RuntimeConfig, job: RuntimeJob): string {
  return path.join(config.paths.results, `${job.job_id}.json`);
}

async function ensurePrivateResultsDirectory(directory: string): Promise<void> {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  try { await chmod(directory, 0o700); } catch { /* Windows does not expose POSIX modes. */ }
}

function resultObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("broker child result is not an object");
  return value as Record<string, unknown>;
}

export function buildBrokerChildEnvironment(config: RuntimeConfig, job: RuntimeJob, parent: NodeJS.ProcessEnv = process.env, transportModule?: string): NodeJS.ProcessEnv {
  const childEnvironment: NodeJS.ProcessEnv = {};
  for (const name of ["PATH", "SystemRoot", "WINDIR", "ComSpec", "PATHEXT", "TEMP", "TMP", "LANG", "TZ"]) {
    if (parent[name] !== undefined) childEnvironment[name] = parent[name];
  }
  childEnvironment.C1_RUNTIME_MODE = "production";
  childEnvironment.C1_RESULT_FILE = childResultPath(config, job);
  childEnvironment.C1_EXPECTED_CLAIM_VERSION = String(job.claim_version ?? 0);
  childEnvironment.C1_EXPECTED_TARGET_TITLE = job.expected_target_title;
  childEnvironment.C1_OPERATOR_DID = config.operatorDid;
  childEnvironment.EFFECT_BROKER_DID = config.brokerDid;
  childEnvironment.EFFECT_BROKER_T3N_API_KEY = config.brokerApiKey!;
  childEnvironment.GITHUB_APP_ID = config.app.appId;
  childEnvironment.GITHUB_APP_INSTALLATION_ID = config.app.installationId;
  childEnvironment.GITHUB_APP_PRIVATE_KEY_PATH = config.app.privateKeyPath;
  childEnvironment.GITHUB_OWNER = config.app.owner;
  childEnvironment.GITHUB_REPO = config.app.repository;
  if (transportModule) {
    childEnvironment.NODE_ENV = "test";
    childEnvironment.BREAKGLASS_TEST_TRANSPORT_MODULE = transportModule;
    if (parent.BROKER_TEST_STATS_FILE) childEnvironment.BROKER_TEST_STATS_FILE = parent.BROKER_TEST_STATS_FILE;
  }
  if (job.remote_state === "EFFECT_CLAIMED" && job.claim_id && job.claim_version) {
    childEnvironment.C1_EXISTING_CLAIM_ID = job.claim_id;
    childEnvironment.C1_EXISTING_CLAIM_VERSION = String(job.claim_version);
  }
  return childEnvironment;
}

async function runChild(config: RuntimeConfig, job: RuntimeJob, transportModule?: string): Promise<Record<string, unknown>> {
  const resultFile = childResultPath(config, job);
  await ensurePrivateResultsDirectory(config.paths.results);
  // A result from an earlier attempt must never be mistaken for this attempt
  // after a child crash. The durable C1 state, not a stale local result, is
  // the recovery authority.
  try { await unlink(resultFile); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  const childEnvironment = buildBrokerChildEnvironment(config, job, process.env, transportModule);
  const script = path.resolve(import.meta.dirname, "../broker/run.ts");
  await new Promise<void>((resolve, reject) => {
    const child = spawn(process.execPath, ["--import", "tsx", script, job.incident_id], {
      env: childEnvironment,
      stdio: ["ignore", "ignore", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString("utf8").slice(0, 4_096); });
    child.once("error", reject);
    child.once("close", (code) => code === 0 ? resolve() : reject(new Error(`broker child exited ${code}: ${stderr.trim()}`)));
  }).catch(async (error) => {
    try { await readFile(resultFile, "utf8"); }
    catch { throw error; }
  });
  return resultObject(JSON.parse(await readFile(resultFile, "utf8")));
}

export interface BrokerWorkerAdapters {
  runChild?: (config: RuntimeConfig, job: RuntimeJob) => Promise<Record<string, unknown>>;
  connectBrokerPrincipal?: () => Promise<BrokerPrincipal>;
  /** Offline-only transport seam; the broker subprocess and state machine remain real. */
  transportModule?: string;
  verifyProvider?: (config: RuntimeConfig["app"], targetId: number) => Promise<ProviderVerification>;
  reconcile?: (config: RuntimeConfig, job: RuntimeJob, classification: string) => Promise<Record<string, unknown>>;
}

export class BreakGlassBrokerWorker {
  private running = false;
  private timer: NodeJS.Timeout | null = null;
  private brokerPrincipal: BrokerPrincipal | null = null;

  constructor(readonly config: RuntimeConfig, readonly jobs: RuntimeJobStore, readonly registry: PolicyRegistry, readonly adapters: BrokerWorkerAdapters = {}) {}

  async initialize(): Promise<void> {
    await this.jobs.initialize();
    await ensurePrivateResultsDirectory(this.config.paths.results);
    this.brokerPrincipal = await (this.adapters.connectBrokerPrincipal ?? (() => connectC1Principal("EFFECT_BROKER_T3N_API_KEY", "EFFECT_BROKER_DID")))();
  }

  async start(): Promise<void> {
    await this.initialize();
    this.timer = setInterval(() => { void this.tick(); }, this.config.pollMs);
    await this.tick();
    operationalLog("broker_started", { c1_state: "WORKER_READY" });
  }

  async stop(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  async tick(): Promise<void> {
    if (this.running || !this.brokerPrincipal) return;
    this.running = true;
    try {
      for (const job of await this.jobs.list()) {
        try {
          if (job.state === "HANDOFF_READY") await this.processHandoff(job);
          else if (job.state === "RETRY_READY") await this.processHandoff(job);
          else if (job.state === "RECONCILE_REQUIRED") await this.processReconciliation(job);
        } catch (error) {
          // A read-only recovery failure must not terminate the worker or
          // turn an uncertain effect into a retry. Leave the durable state
          // unchanged for the next operator/coordinator reconciliation pass.
          operationalLog("broker_recovery_deferred", { incident_id: job.incident_id, reason: error instanceof Error ? error.message : String(error) });
        }
      }
    } finally { this.running = false; }
  }

  private async processHandoff(job: RuntimeJob): Promise<void> {
    const result = await this.jobs.withLease(job.incident_id, async (leasedJob) => {
      if (leasedJob.state !== "HANDOFF_READY" && leasedJob.state !== "RETRY_READY") return null;
      if (!leasedJob.operator_handoff_id || leasedJob.operator_handoff_id === leasedJob.broker_consumed_handoff_id) return null;
      if (!["RESERVED", "READY_RETRY", "EFFECT_CLAIMED"].includes(leasedJob.remote_state ?? "")) {
        await this.jobs.update(leasedJob.incident_id, { state: "STATE_CONFLICT" }, { allowStateConflict: true });
        operationalLog("broker_state_conflict", { incident_id: leasedJob.incident_id, reason: "operator handoff did not authorize normal broker processing" });
        return null;
      }
      if (leasedJob.remote_state === "EFFECT_CLAIMED" && (!leasedJob.claim_id || !leasedJob.claim_version)) {
        await this.jobs.update(leasedJob.incident_id, { state: "STATE_CONFLICT" }, { allowStateConflict: true });
        operationalLog("broker_state_conflict", { incident_id: leasedJob.incident_id, reason: "operator handoff omitted exact remote claim identity" });
        return null;
      }
      // The operator read is the routing authority. Consume its signed handoff
      // before entering broker control flow; a later retry requires a new
      // operator observation and can never be inferred from local state.
      let handoffJob = await this.jobs.update(leasedJob.incident_id, { broker_consumed_handoff_id: leasedJob.operator_handoff_id });
      const firstAttempt = handoffJob.state === "HANDOFF_READY";
      if (firstAttempt) handoffJob = await this.jobs.update(leasedJob.incident_id, { state: "PROCESSING", last_error: null });
      try {
        const child = await (this.adapters.runChild ?? ((config, job) => runChild(config, job, this.adapters.transportModule)))(this.config, handoffJob);
        const effectStarted = child.effect_start_confirmed === true || child.effect_start_id !== null && typeof child.effect_start_id === "string";
        const c1Closed = child.c1_state === "CLOSED" && child.c1_result === "WON";
        const state = c1Closed ? "CLOSED" : effectStarted ? "RECONCILE_REQUIRED" : "RETRY_READY";
        const updated = await this.jobs.update(handoffJob.incident_id, {
          state,
          claim_id: typeof child.claim_id === "string" ? child.claim_id : handoffJob.claim_id ?? null,
          claim_version: Number.isSafeInteger(child.claim_version) ? Number(child.claim_version) : handoffJob.claim_version ?? null,
          effect_start_id: typeof child.effect_start_id === "string" ? child.effect_start_id : handoffJob.effect_start_id ?? null,
          provider_classification: typeof child.classification === "string" ? child.classification : null,
          last_result_file: childResultPath(this.config, handoffJob),
          last_error: child.effect_error && typeof child.effect_error === "object" ? JSON.stringify(child.effect_error).slice(0, 1_000) : null,
        });
        operationalLog("broker_outcome", { incident_id: leasedJob.incident_id, broker_outcome: child.claim_outcome ?? "UNKNOWN", effect_start_confirmed: effectStarted, provider_classification: child.classification ?? null, reconciliation_state: updated.state, c1_state: child.c1_state ?? null });
        return updated;
      } catch (error) {
        // An absent child result is ambiguous. Leave PROCESSING so the
        // coordinator must read remote C1 state before any retry can occur;
        // this prevents a restart from issuing a second DELETE.
        await this.jobs.update(handoffJob.incident_id, { state: firstAttempt ? "PROCESSING" : "RETRY_READY", last_error: error instanceof Error ? error.message.slice(0, 1_000) : String(error).slice(0, 1_000) });
        operationalLog("broker_deferred", { incident_id: handoffJob.incident_id, reason: error instanceof Error ? error.message : String(error) });
        return null;
      }
    });
    void result;
  }

  private async processReconciliation(job: RuntimeJob): Promise<void> {
    if (!job.claim_id || !job.effect_start_id || !this.brokerPrincipal) return;
    const result = await this.jobs.withLease(job.incident_id, async (leasedJob) => {
      if (leasedJob.state !== "RECONCILE_REQUIRED" || !leasedJob.claim_id || !leasedJob.effect_start_id) return null;
      if (!leasedJob.operator_handoff_id || leasedJob.operator_handoff_id === leasedJob.broker_consumed_handoff_id) return null;
      if (!["EFFECT_STARTED", "RECONCILE_REQUIRED", "FAILED"].includes(leasedJob.remote_state ?? "")) {
        await this.jobs.update(leasedJob.incident_id, { state: "STATE_CONFLICT" }, { allowStateConflict: true });
        operationalLog("broker_state_conflict", { incident_id: leasedJob.incident_id, reason: "operator handoff did not authorize reconciliation" });
        return null;
      }
      const handedOff = await this.jobs.update(leasedJob.incident_id, { broker_consumed_handoff_id: leasedJob.operator_handoff_id });
      const verification = await (this.adapters.verifyProvider ?? verifyProviderTarget)(this.config.app, leasedJob.deploy_key_id);
      const classification = verification.classification === "VERIFIED_ABSENT" ? "VERIFIED_ABSENT" : "VERIFIED_PRESENT";
      const transport = principalTransport({ apiKey: this.brokerPrincipal!.apiKey, nodeUrl: this.brokerPrincipal!.nodeUrl, did: this.brokerPrincipal!.did });
      const raw = await (this.adapters.reconcile ?? (async (config, recoveryJob, resultClassification) => transport.call(config.contractId, "reconcile-effect", {
        incident_id: recoveryJob.incident_id,
        claim_id: recoveryJob.claim_id,
        effect_start_id: recoveryJob.effect_start_id,
        classification: resultClassification,
      })))(this.config, handedOff, classification);
      const response = asC1Object(raw);
      operationalLog("reconciliation", { incident_id: leasedJob.incident_id, provider_classification: verification.classification, reconciliation_state: response.state ?? null });
      return this.jobs.update(leasedJob.incident_id, { state: verification.classification === "VERIFIED_ABSENT" ? "CLOSED" : "RECONCILE_REQUIRED", provider_classification: verification.classification, remote_state: typeof response.state === "string" ? response.state : null });
    });
    void result;
  }
}
