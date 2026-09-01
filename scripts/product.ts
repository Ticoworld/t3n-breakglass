import { readFile } from "node:fs/promises";
import path from "node:path";
import { CONTRACT_FUNCTION, CONTRACT_VERSION } from "./lib.js";

const root = path.resolve(import.meta.dirname, "..");

export type AgentIncidentInput = { incident_id: string };

export type SanitizedExecutionResult = {
  incident_id: string;
  outcome: string;
  previous_status: string | null;
  current_status: string | null;
  target: {
    host: string | null;
    owner: string | null;
    repository: string | null;
    deploy_key_id: number | null;
  };
  verification: {
    attempted: boolean;
    authoritative: boolean;
    http_status: number | null;
    absent: boolean;
  };
  destructive_call_count: number;
  destructive_call_http_status: number | null;
  audit_reference: {
    contract_function: typeof CONTRACT_FUNCTION;
    contract_version: typeof CONTRACT_VERSION;
    incident_id: string;
  };
};

export function validateIncidentId(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)) {
    throw new Error("incident_id must be 1-128 letters, numbers, dots, underscores, colons, or hyphens");
  }
  return value;
}

export function parseAgentInput(input: unknown): AgentIncidentInput {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("agent input must be an object containing only incident_id");
  }
  const keys = Object.keys(input);
  if (keys.length !== 1 || keys[0] !== "incident_id") {
    throw new Error("agent input accepts only incident_id");
  }
  return { incident_id: validateIncidentId((input as Record<string, unknown>).incident_id) };
}

export function parseIncidentIdArgument(args: string[]): string {
  if (args.length !== 1) throw new Error("usage: npm run agent:execute -- <incident_id>");
  return validateIncidentId(args[0]);
}

export function assertIncidentIsUnused(existing: string | null, incidentId: string): void {
  if (existing !== null) throw new Error(`incident ID already exists: ${incidentId}`);
}

export function parsePositiveInteger(value: string, label: string): number {
  if (!/^\d+$/.test(value)) throw new Error(`${label} must be a positive integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) throw new Error(`${label} must be a positive integer`);
  return parsed;
}

export function validateTtlSeconds(value: string): number {
  const ttl = parsePositiveInteger(value, "TTL");
  if (ttl < 30 || ttl > 3600) throw new Error("TTL must be between 30 and 3600 seconds");
  return ttl;
}

export function formatTimestamp(seconds: number): string {
  return new Date(seconds * 1000).toISOString();
}

export async function readPhase1Setup(): Promise<{ contractId: string }> {
  const setup = JSON.parse(await readFile(path.join(root, "evidence", "phase1-setup.json"), "utf8")) as {
    contract?: { name?: string; version?: string; function?: string };
  };
  if (
    setup.contract?.version !== CONTRACT_VERSION ||
    setup.contract.function !== CONTRACT_FUNCTION ||
    typeof setup.contract.name !== "string" ||
    setup.contract.name.length === 0
  ) throw new Error("existing Phase 1 contract evidence does not match the pinned contract");
  return { contractId: setup.contract.name };
}

export async function readReplacementProvisioning(): Promise<{ organizationDid: string; expectedAgentDid?: string }> {
  const provisioning = JSON.parse(await readFile(path.join(root, "evidence", "phase1-replacement-agent-provisioning.json"), "utf8")) as {
    organisation_did?: string;
    replacement_agent_did?: string;
  };
  if (!/^did:t3n:[0-9a-f]{40}$/.test(provisioning.organisation_did ?? "")) {
    throw new Error("replacement-agent provisioning evidence has no valid organization DID");
  }
  return { organizationDid: provisioning.organisation_did, expectedAgentDid: provisioning.replacement_agent_did };
}

export async function trustedNodeTimeSeconds(nodeUrl: string): Promise<number> {
  const response = await fetch(`${nodeUrl}/api/trust-manifest`, { redirect: "error", cache: "no-store" });
  const dateHeader = response.headers.get("date");
  await response.arrayBuffer();
  if (!response.ok) throw new Error(`trusted T3N time source failed with HTTP ${response.status}`);
  const timeMs = dateHeader ? Date.parse(dateHeader) : Number.NaN;
  if (!Number.isFinite(timeMs)) throw new Error("trusted T3N time source did not provide a valid Date header");
  return Math.floor(timeMs / 1000);
}

function nullableString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function nullableNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) ? value : null;
}

export function sanitizeExecutionResult(incidentId: string, raw: unknown): SanitizedExecutionResult {
  const result = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  const state = (result.state && typeof result.state === "object" ? result.state : {}) as Record<string, unknown>;
  const target = (result.target && typeof result.target === "object" ? result.target : {}) as Record<string, unknown>;
  const verification = (result.verification && typeof result.verification === "object" ? result.verification : {}) as Record<string, unknown>;
  const destructiveCall = (result.destructive_call && typeof result.destructive_call === "object" ? result.destructive_call : {}) as Record<string, unknown>;
  return {
    incident_id: incidentId,
    outcome: nullableString(result.status) ?? "UNKNOWN",
    previous_status: nullableString(state.before),
    current_status: nullableString(state.after) ?? nullableString(result.status),
    target: {
      host: nullableString(target.host),
      owner: nullableString(target.owner),
      repository: nullableString(target.repository),
      deploy_key_id: nullableNumber(target.deploy_key_id),
    },
    verification: {
      attempted: verification.attempted === true,
      authoritative: verification.authoritative === true,
      http_status: nullableNumber(verification.http_status),
      absent: verification.absent === true,
    },
    destructive_call_count: typeof destructiveCall.count === "number" && Number.isSafeInteger(destructiveCall.count) ? destructiveCall.count : 0,
    destructive_call_http_status: nullableNumber(destructiveCall.http_status),
    audit_reference: {
      contract_function: CONTRACT_FUNCTION,
      contract_version: CONTRACT_VERSION,
      incident_id: incidentId,
    },
  };
}
