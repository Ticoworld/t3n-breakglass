import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { once } from "node:events";
import { randomBytes } from "node:crypto";

import { DedupeIntegrityError, findDedupeRecord, listDedupeRecords } from "../c2/dedupe.js";
import { normalizeVerifiedPushEvent } from "../c2/push-source.js";
import { PolicyAlreadyBoundError, processPushWebhookWithSourceReader, type PushIngressResult } from "../c2/push-ingress.js";
import type { RawGithubRequest } from "../c2/types.js";
import { operationalLog } from "./logger.js";
import { asC1Object, c1Detail, c1State, type WinnerC1Client } from "./c1-client.js";
import type { RuntimeConfig } from "./config.js";
import { RuntimeJobStore, type RuntimeJob } from "./job-store.js";
import { PolicyRegistry, PolicyRegistryIntegrityError } from "./policy-registry.js";
import type { GithubPushSourceReader } from "../c2/push-source-reader.js";

const MAX_HTTP_HEADER_VALUE = 16_384;

export interface CoordinatorDependencies {
  config: RuntimeConfig;
  registry: PolicyRegistry;
  jobs: RuntimeJobStore;
  c1: WinnerC1Client;
  sourceReader: Pick<GithubPushSourceReader, "readPlan">;
}

export interface CoordinatorResult {
  statusCode: number;
  body: Record<string, unknown>;
}

function headerValue(request: IncomingMessage, name: string): string | undefined {
  const value = request.headers[name];
  if (Array.isArray(value)) return value[0];
  return value;
}

async function readBody(request: IncomingMessage, maxBytes: number): Promise<Buffer> {
  const declaredLength = Number(request.headers["content-length"] ?? "0");
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) throw new Error("HTTP_BODY_TOO_LARGE");
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += bytes.length;
    if (total > maxBytes) throw new Error("HTTP_BODY_TOO_LARGE");
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

function rawRequest(request: IncomingMessage, body: Buffer): RawGithubRequest {
  const headers: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(request.headers)) headers[key] = Array.isArray(value) ? value[0] : value;
  return { headers, body };
}

function respond(response: ServerResponse, statusCode: number, body: Record<string, unknown>): void {
  const encoded = Buffer.from(`${JSON.stringify(body)}\n`, "utf8");
  response.statusCode = statusCode;
  response.setHeader("content-type", "application/json");
  response.setHeader("content-length", encoded.length);
  response.end(encoded);
}

function responseResult(raw: unknown): string | null {
  const value = asC1Object(raw);
  return typeof value.result === "string" ? value.result : null;
}

function isAbsentIncidentReadback(raw: unknown): boolean {
  const value = asC1Object(raw);
  if (value.result !== "DENIED") return false;
  if (value.state === "ABSENT") return true;
  return value.state === null && typeof value.note === "string" && /incident authority does not exist/i.test(value.note);
}

function remoteSnapshot(raw: unknown): { state: string | null; claimId: string | null; claimVersion: number | null; effectStartId: string | null; classification: string | null } {
  const detail = c1Detail(raw);
  const value = asC1Object(raw);
  return {
    state: c1State(raw),
    claimId: typeof detail.effect_claim_id === "string" ? detail.effect_claim_id : typeof detail.claim_id === "string" ? detail.claim_id : null,
    claimVersion: Number.isSafeInteger(detail.effect_claim_version) ? Number(detail.effect_claim_version) : Number.isSafeInteger(detail.claim_version) ? Number(detail.claim_version) : null,
    effectStartId: typeof detail.effect_start_id === "string" ? detail.effect_start_id : null,
    classification: typeof value.final_result_classification === "string" ? value.final_result_classification : typeof detail.final_result_classification === "string" ? detail.final_result_classification : null,
  };
}

function remoteAuthorityMatches(raw: unknown, job: RuntimeJob, config: RuntimeConfig): boolean {
  const value = asC1Object(raw);
  if (value.result !== "FOUND") return false;
  const detail = c1Detail(raw);
  return detail.incident_id === job.incident_id &&
    detail.remediation_agent_did === job.create_request.remediation_agent_did &&
    detail.effect_broker_did === job.create_request.effect_broker_did &&
    detail.action === "revoke_github_deploy_key" &&
    detail.github_owner === config.app.owner &&
    detail.github_repo === config.app.repository &&
    Number(detail.deploy_key_id) === job.create_request.deploy_key_id;
}

function expectedJobInput(result: Extract<PushIngressResult, { classification: "C2_PUSH_SELECTED" }>): Omit<RuntimeJob, "schema_version" | "key_id" | "mac" | "job_id" | "created_at" | "updated_at" | "state"> {
  return {
    incident_id: result.incident_id,
    receipt_key: result.dedupe.key,
    policy_id: result.dedupe.record.policy_id!,
    policy_version: result.dedupe.record.policy_version!,
    deploy_key_id: result.create_request.deploy_key_id,
    expected_target_title: result.dedupe.record.expected_target_title!,
    create_request: result.create_request,
  };
}

function operatorHandoffId(): string {
  return `operator-handoff-${Date.now()}-${randomBytes(16).toString("hex")}`;
}

export class BreakGlassCoordinator {
  private server: Server | null = null;
  private recoveryTimer: NodeJS.Timeout | null = null;
  private recoveryRunning = false;

  constructor(readonly dependencies: CoordinatorDependencies) {}

  async initialize(): Promise<void> {
    await this.dependencies.registry.initialize();
    await this.dependencies.jobs.initialize();
    await this.recoverAcceptedReceipts();
    await this.reconcileJobs();
  }

  async start(): Promise<void> {
    await this.initialize();
    this.server = createServer((request, response) => { void this.handleHttp(request, response); });
    this.server.listen(this.dependencies.config.listenPort, this.dependencies.config.listenHost);
    await once(this.server, "listening");
    this.recoveryTimer = setInterval(() => { void this.recoveryTick(); }, this.dependencies.config.pollMs);
    operationalLog("coordinator_started", { c1_state: "LISTENING" });
  }

  async stop(): Promise<void> {
    if (this.recoveryTimer) clearInterval(this.recoveryTimer);
    this.recoveryTimer = null;
    if (this.server) {
      this.server.close();
      await once(this.server, "close").catch(() => undefined);
      this.server = null;
    }
  }

  async acceptWebhook(request: RawGithubRequest): Promise<CoordinatorResult> {
    // Authenticate and inspect the durable receipt before loading current
    // policy state. Accepted replay is an authority record, not a new policy
    // decision, and therefore remains valid after policy retirement.
    const event = normalizeVerifiedPushEvent(request, this.dependencies.config.webhookSecret!);
    const existing = await findDedupeRecord(this.dependencies.config.paths.receipts, event, { stateIntegrityKey: this.dependencies.config.stateIntegrityKey });
    const records = existing?.state === "ACCEPTED" || existing?.state === "REJECTED"
      ? []
      : await this.dependencies.registry.activePolicyRecords(new Date());
    const bound = existing?.state === "RESERVED" ? await this.dependencies.registry.boundPolicyForEvent(event, existing.dedupe_key) : null;
    const activeSourceMatch = records.some((record) => record.policy.source_provider === event.provider && record.policy.source_event_type === event.event_type && record.policy.repository_id === event.repository_id && record.policy.repository_full_name === event.repository_full_name && record.policy.ref === event.ref);
    const boundSourceRecords = existing ? [] : activeSourceMatch ? [] : await this.dependencies.registry.boundPolicyRecordsForEvent(event);
    const selectedRecords = [...records, ...boundSourceRecords.filter((candidate) => !records.some((record) => record.policy.policy_id === candidate.policy.policy_id && record.policy.policy_version === candidate.policy.policy_version))];
    if (bound && !selectedRecords.some((record) => record.policy.policy_id === bound.policy.policy_id && record.policy.policy_version === bound.policy.policy_version)) selectedRecords.push(bound);
    const metadata = new Map(selectedRecords.map((record) => [`${record.policy.policy_id}@${record.policy.policy_version}`, { registryIdentity: record.registry_identity, policyContentHash: record.policy_sha256 }]));
    const result = await processPushWebhookWithSourceReader(
      request,
      this.dependencies.config.webhookSecret!,
      this.dependencies.config.paths.receipts,
      selectedRecords.map((record) => record.policy),
      this.dependencies.sourceReader,
      {
        stateIntegrityKey: this.dependencies.config.stateIntegrityKey,
        recoverReserved: true,
        reservedRecoveryMs: bound ? 0 : undefined,
        requirePolicyBinding: true,
        policyMetadata: (policy) => metadata.get(`${policy.policy_id}@${policy.policy_version}`),
        bindVerifiedPolicy: async (input) => {
          try { return await this.dependencies.registry.bindVerifiedEvent(input); }
          catch (error) {
            if (error instanceof PolicyRegistryIntegrityError && /already bound|already retired/i.test(error.message)) throw new PolicyAlreadyBoundError(error.message);
            throw error;
          }
        },
      },
    );
    operationalLog(result.classification === "C2_PUSH_SELECTED" ? "delivery_accepted" : "delivery_rejected", {
      delivery_id: result.event.delivery_id,
      dedupe_state: result.dedupe.status,
      policy_id: result.policy?.policy_id,
      policy_version: result.policy?.policy_version,
      replayed: result.classification === "C2_PUSH_SELECTED" ? result.replayed : false,
      source_reads: result.classification === "C2_PUSH_SELECTED" ? result.source_reads : 0,
      reason: result.classification === "C2_PUSH_SELECTED" ? undefined : result.reason,
    });
    if (result.classification !== "C2_PUSH_SELECTED") {
      return { statusCode: result.dedupe.status === "CONFLICT" ? 409 : 202, body: { accepted: false, classification: result.classification, reason: result.reason, dedupe: result.dedupe.status } };
    }

    if (!result.dedupe.record.expected_target_title) throw new DedupeIntegrityError("accepted receipt is missing its frozen target title");
    let job = await this.dependencies.jobs.create(expectedJobInput(result));
    job = await this.ensureIncidentAndReservation(job);
    return {
      statusCode: 202,
      body: {
        accepted: true,
        classification: result.classification,
        replayed: result.replayed,
        incident_id: result.incident_id,
        job_id: job.job_id,
        job_state: job.state,
        c1_state: job.remote_state ?? null,
      },
    };
  }

  private async handleHttp(request: IncomingMessage, response: ServerResponse): Promise<void> {
    try {
      if (request.method === "GET" && request.url === "/healthz") {
        respond(response, 200, { ok: true, service: "breakglass-coordinator", mode: "single-instance" });
        return;
      }
      if (request.method !== "POST" || request.url !== this.dependencies.config.webhookRoute) {
        respond(response, 404, { ok: false, error: "NOT_FOUND" });
        return;
      }
      const body = await readBody(request, this.dependencies.config.maxBodyBytes);
      const signature = headerValue(request, "x-hub-signature-256");
      if (signature && signature.length > MAX_HTTP_HEADER_VALUE) throw new Error("MALFORMED_SIGNATURE");
      const result = await this.acceptWebhook(rawRequest(request, body));
      respond(response, result.statusCode, result.body);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const code = error && typeof error === "object" && "code" in error ? String((error as { code: unknown }).code) : "";
      operationalLog("delivery_rejected", { reason: message });
      const status = message === "HTTP_BODY_TOO_LARGE" ? 413 : code === "MALFORMED_SIGNATURE" ? 400 : code === "MISSING_SIGNATURE" || code === "INVALID_SIGNATURE" || /signature/i.test(message) ? 401 : 500;
      respond(response, status, { accepted: false, error: message });
    }
  }

  private async recoverAcceptedReceipts(): Promise<void> {
    const receipts = await listDedupeRecords(this.dependencies.config.paths.receipts, { stateIntegrityKey: this.dependencies.config.stateIntegrityKey });
    for (const receipt of receipts) {
      if (receipt.state !== "ACCEPTED" || !receipt.create_request || !receipt.policy_id || !receipt.policy_version || !receipt.derived_incident_id) continue;
      if (!receipt.expected_target_title) throw new DedupeIntegrityError(`accepted receipt ${receipt.dedupe_key} has no frozen target title`);
      await this.dependencies.jobs.create({
        incident_id: receipt.derived_incident_id,
        receipt_key: receipt.dedupe_key,
        policy_id: receipt.policy_id,
        policy_version: receipt.policy_version,
        deploy_key_id: receipt.create_request.deploy_key_id,
        expected_target_title: receipt.expected_target_title,
        create_request: receipt.create_request,
      });
    }
  }

  private async ensureIncidentAndReservation(job: RuntimeJob): Promise<RuntimeJob> {
    let remote: unknown;
    try {
      remote = await this.dependencies.c1.getIncident(job.incident_id);
      if (responseResult(remote) !== "FOUND") {
        if (!isAbsentIncidentReadback(remote)) throw new Error("C1 incident readback was unavailable or contradictory");
        const created = await this.dependencies.c1.createIncident(job.create_request);
        if (responseResult(created) !== "WON" && responseResult(created) !== "FOUND") {
          remote = await this.dependencies.c1.getIncident(job.incident_id);
          if (responseResult(remote) !== "FOUND") throw new Error("C1 incident creation was not confirmed");
        } else remote = await this.dependencies.c1.getIncident(job.incident_id);
      }
    } catch (error) {
      // A create transport failure is ambiguous. A readback is the only safe
      // recovery; the exact receipt request remains the sole create input.
      try {
        remote = await this.dependencies.c1.getIncident(job.incident_id);
        if (responseResult(remote) !== "FOUND") throw error;
      } catch { throw error; }
    }

    if (!remoteAuthorityMatches(remote, job, this.dependencies.config)) {
      await this.dependencies.jobs.update(job.incident_id, { state: "STATE_CONFLICT", remote_state: c1State(remote) }, { allowStateConflict: true });
      throw new Error("C1 incident readback authority does not match the frozen accepted request");
    }

    let snapshot = remoteSnapshot(remote);
    operationalLog("incident_observed", { incident_id: job.incident_id, c1_state: snapshot.state });
    if (!snapshot.state || !["ACTIVE", "RESERVED", "READY_RETRY", "EFFECT_CLAIMED", "EFFECT_STARTED", "RECONCILE_REQUIRED", "FAILED", "EXPIRED", "CLOSED"].includes(snapshot.state)) {
      await this.dependencies.jobs.update(job.incident_id, { state: "STATE_CONFLICT", remote_state: snapshot.state }, { allowStateConflict: true });
      throw new Error("C1 incident readback state was unavailable or contradictory");
    }
    const dangerous = snapshot.state === "EFFECT_STARTED" || snapshot.state === "RECONCILE_REQUIRED" || Boolean(snapshot.effectStartId);
    if ((snapshot.state === "EFFECT_CLAIMED" && (!snapshot.claimId || snapshot.claimVersion === null)) || (dangerous && (!snapshot.claimId || !snapshot.effectStartId))) {
      await this.dependencies.jobs.update(job.incident_id, { state: "STATE_CONFLICT", remote_state: snapshot.state }, { allowStateConflict: true });
      throw new Error("C1 incident readback omitted the exact claim/effect identity required for safe routing");
    }
    // A terminal/conflicted local job is never allowed to trigger a new C1
    // mutation while remote state is being reconciled.  Remote state remains
    // authoritative, but local terminal knowledge prevents this coordinator
    // from turning a contradiction into a reservation side effect.
    const localMutationBlocked = job.state === "CLOSED" || job.state === "FAILED" || job.state === "STATE_CONFLICT";
    if (snapshot.state === "ACTIVE" && !localMutationBlocked) {
      const reserved = await this.dependencies.c1.reserveIncident(job.incident_id);
      operationalLog("remediation_reserved", { incident_id: job.incident_id, c1_state: c1State(reserved) });
      if (responseResult(reserved) !== "WON" && c1State(reserved) !== "RESERVED") {
        remote = await this.dependencies.c1.getIncident(job.incident_id);
      } else remote = reserved;
      snapshot = remoteSnapshot(remote);
    }
    const state = snapshot.state;
    const closedVerified = state === "CLOSED" && snapshot.classification === "VERIFIED_ABSENT";
    let nextState: RuntimeJob["state"];
    if (state === "CLOSED") nextState = "CLOSED";
    else if (state === "FAILED" || state === "EXPIRED") nextState = job.state === "CLOSED" || job.state === "STATE_CONFLICT" ? "STATE_CONFLICT" : "FAILED";
    else if (dangerous) nextState = "RECONCILE_REQUIRED";
    else if (state === "ACTIVE") nextState = job.state === "PENDING" ? "PENDING" : job.state === "PROCESSING" ? "RETRY_READY" : job.state;
    else if (job.state === "CLOSED" || job.state === "FAILED" || job.state === "STATE_CONFLICT") nextState = "STATE_CONFLICT";
    else if (job.state === "PROCESSING" || job.state === "RETRY_READY") nextState = "RETRY_READY";
    else nextState = "HANDOFF_READY";
    const brokerEligible = nextState === "HANDOFF_READY" || nextState === "RETRY_READY" || nextState === "RECONCILE_REQUIRED";
    const next = await this.dependencies.jobs.update(job.incident_id, {
      state: nextState,
      remote_state: state,
      claim_id: snapshot.claimId,
      claim_version: snapshot.claimVersion,
      effect_start_id: snapshot.effectStartId,
      provider_classification: snapshot.classification,
      operator_handoff_id: brokerEligible ? operatorHandoffId() : null,
      broker_consumed_handoff_id: null,
    }, { allowStateConflict: nextState === "STATE_CONFLICT" || job.state === "STATE_CONFLICT" });
    operationalLog("incident_handoff", { incident_id: job.incident_id, c1_state: state });
    if (closedVerified) await this.retireClosedPolicy(next);
    return next;
  }

  private async reconcileJobs(): Promise<void> {
    for (const job of await this.dependencies.jobs.list()) {
      try { await this.ensureIncidentAndReservation(job); }
      catch (error) { operationalLog("recovery_deferred", { incident_id: job.incident_id, reason: error instanceof Error ? error.message : String(error) }); }
    }
  }

  private async retireClosedPolicy(job: RuntimeJob): Promise<void> {
    const remote = await this.dependencies.c1.getIncident(job.incident_id);
    const snapshot = remoteSnapshot(remote);
    if (responseResult(remote) !== "FOUND" || snapshot.state !== "CLOSED" || snapshot.classification !== "VERIFIED_ABSENT") throw new Error("policy retirement requires authoritative CLOSED / VERIFIED_ABSENT C1 readback");
    const retirement = await this.dependencies.registry.retire(job.policy_id, job.policy_version, job.incident_id);
    operationalLog("policy_retired", { incident_id: job.incident_id, policy_id: job.policy_id, policy_version: job.policy_version, retired: retirement.retired });
  }

  private async recoveryTick(): Promise<void> {
    if (this.recoveryRunning) return;
    this.recoveryRunning = true;
    try { await this.reconcileJobs(); }
    catch (error) { operationalLog("recovery_failed", { reason: error instanceof Error ? error.message : String(error) }); }
    finally { this.recoveryRunning = false; }
  }
}
