import os from "node:os";
import { readFileSync } from "node:fs";
import path from "node:path";

import { appConfigFromEnvironment, type AppConfig } from "../broker/github-app.js";
import { C2_PUSH_REF, C2_PUSH_REPOSITORY, C2_PUSH_SECRET_PATH } from "../c2/push-source.js";
import { CONTRACT_VERSION, contractName } from "../scripts/constants.js";
import { assertIntegrityKey, type IntegrityKeyRing } from "./integrity.js";

export type RuntimeRole = "coordinator" | "broker";

export interface RuntimePaths {
  root: string;
  receipts: string;
  policies: string;
  retirements: string;
  jobs: string;
  results: string;
}

export interface RuntimeConfig {
  role: RuntimeRole;
  paths: RuntimePaths;
  listenHost: string;
  listenPort: number;
  webhookRoute: string;
  webhookSecret?: string;
  maxBodyBytes: number;
  operatorDid: string;
  remediationDid: string;
  brokerDid: string;
  contractId: string;
  contractVersion: string;
  app: AppConfig;
  stateIntegrityKey: IntegrityKeyRing;
  operatorApiKey?: string;
  remediationApiKey?: string;
  brokerApiKey?: string;
  pollMs: number;
}

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function positiveInteger(env: NodeJS.ProcessEnv, name: string, fallback: number): number {
  const raw = env[name] ?? String(fallback);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive integer`);
  return value;
}

function did(env: NodeJS.ProcessEnv, name: string): string {
  const value = required(env, name);
  if (!/^did:t3n:[0-9a-f]{40}$/i.test(value)) throw new Error(`${name} is not a valid T3N DID`);
  return value;
}

function safeDataRoot(value: string): string {
  if (!path.isAbsolute(value)) throw new Error("BREAKGLASS_DATA_DIRECTORY must be an absolute path");
  const root = path.resolve(value);
  const repositoryRoot = path.resolve(import.meta.dirname, "../..");
  const relativeToRepository = path.relative(repositoryRoot, root);
  if (relativeToRepository === "" || (!relativeToRepository.startsWith(`..${path.sep}`) && relativeToRepository !== "..")) throw new Error("BREAKGLASS_DATA_DIRECTORY must be outside the repository");
  const temporaryRoot = path.resolve(os.tmpdir());
  const relativeToTemp = path.relative(temporaryRoot, root);
  if (relativeToTemp === "" || (!relativeToTemp.startsWith(`..${path.sep}`) && relativeToTemp !== "..")) throw new Error("BREAKGLASS_DATA_DIRECTORY must not use the operating-system temporary directory");
  if (root === path.parse(root).root) throw new Error("BREAKGLASS_DATA_DIRECTORY must not be a filesystem root");
  return root;
}

function secretBytes(env: NodeJS.ProcessEnv, valueName: string, fileName: string): Uint8Array {
  const file = env[fileName];
  const value = file ? readFileSync(safeExternalSecretFile(file, fileName), "utf8").trim() : env[valueName];
  if (!value) throw new Error(`${valueName} or ${fileName} is required`);
  return assertIntegrityKey(value, "BREAKGLASS_STATE_INTEGRITY_KEY");
}

function safeExternalSecretFile(value: string, label: string): string {
  if (!path.isAbsolute(value)) throw new Error(`${label} must be an absolute path`);
  const resolved = path.resolve(value);
  const repositoryRoot = path.resolve(import.meta.dirname, "../..");
  const relativeToRepository = path.relative(repositoryRoot, resolved);
  if (relativeToRepository === "" || (!relativeToRepository.startsWith(`..${path.sep}`) && relativeToRepository !== "..")) throw new Error(`${label} must be outside the repository`);
  if (resolved === path.parse(resolved).root) throw new Error(`${label} must point to a file, not a filesystem root`);
  return resolved;
}

export function loadStateIntegrityKey(env: NodeJS.ProcessEnv = process.env): IntegrityKeyRing {
  const currentId = env.BREAKGLASS_STATE_INTEGRITY_KEY_ID ?? "current";
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(currentId)) throw new Error("BREAKGLASS_STATE_INTEGRITY_KEY_ID is invalid");
  const current = { id: currentId, value: secretBytes(env, "BREAKGLASS_STATE_INTEGRITY_KEY", "BREAKGLASS_STATE_INTEGRITY_KEY_FILE") };
  const verify = new Map<string, Uint8Array>([[current.id, current.value]]);
  const configured = env.BREAKGLASS_STATE_INTEGRITY_VERIFY_KEYS;
  if (configured) {
    for (const entry of configured.split(";").filter(Boolean)) {
      const separator = entry.indexOf("=");
      if (separator <= 0) throw new Error("BREAKGLASS_STATE_INTEGRITY_VERIFY_KEYS must contain key_id=path entries");
      const id = entry.slice(0, separator);
      const file = entry.slice(separator + 1);
      if (!/^[A-Za-z0-9._-]{1,64}$/.test(id)) throw new Error(`state integrity verify key id ${id} is invalid`);
      verify.set(id, assertIntegrityKey(readFileSync(safeExternalSecretFile(file, `state integrity verify key ${id}`), "utf8").trim(), `state integrity verify key ${id}`));
    }
  }
  return { current, verify };
}

export function runtimePaths(root: string): RuntimePaths {
  return {
    root,
    receipts: path.join(root, "receipts"),
    policies: path.join(root, "policies"),
    retirements: path.join(root, "retirements"),
    jobs: path.join(root, "jobs"),
    results: path.join(root, "results"),
  };
}

export function loadDataDirectory(env: NodeJS.ProcessEnv = process.env): string {
  return safeDataRoot(required(env, "BREAKGLASS_DATA_DIRECTORY"));
}

export function loadRuntimeConfig(role: RuntimeRole, env: NodeJS.ProcessEnv = process.env): RuntimeConfig {
  if (env.GITHUB_PAT) throw new Error("BreakGlass runtime refuses GITHUB_PAT");
  if (env.C1_BARRIER_FILE || env.C1_PROPOSALS_COMPLETE_FILE || env.C1_READY_FILE || env.C1_EFFECT_START_READY_FILE || env.C1_PRE_DELETE_RELEASE_FILE) throw new Error("proof barriers are forbidden in production runtime mode");
  if (role === "broker" && (env.T3N_API_KEY || env.AGENT_T3N_API_KEY || env.C2_WEBHOOK_SECRET)) throw new Error("broker environment contains coordinator/remediation credentials");
  if (role === "coordinator" && env.EFFECT_BROKER_T3N_API_KEY) throw new Error("coordinator environment contains broker credentials");
  const operatorDid = did(env, "C1_OPERATOR_DID");
  const remediationDid = did(env, "AGENT_DID");
  const brokerDid = did(env, "EFFECT_BROKER_DID");
  if (new Set([operatorDid.toLowerCase(), remediationDid.toLowerCase(), brokerDid.toLowerCase()]).size !== 3) throw new Error("operator, remediation, and broker DIDs must be distinct");
  const root = loadDataDirectory(env);
  const app = appConfigFromEnvironment(env);
  if (`${app.owner}/${app.repository}` !== C2_PUSH_REPOSITORY) throw new Error("GitHub App target is not the fixed C2 repository");
  const webhookRoute = env.BREAKGLASS_WEBHOOK_ROUTE ?? "/c2-b0/github-push";
  if (!webhookRoute.startsWith("/") || webhookRoute.includes("?")) throw new Error("BREAKGLASS_WEBHOOK_ROUTE must be an exact path");
  const config: RuntimeConfig = {
    role,
    paths: runtimePaths(root),
    listenHost: env.BREAKGLASS_LISTEN_HOST ?? "127.0.0.1",
    listenPort: positiveInteger(env, "BREAKGLASS_LISTEN_PORT", 8787),
    webhookRoute,
    webhookSecret: role === "coordinator" ? required(env, "C2_WEBHOOK_SECRET") : undefined,
    maxBodyBytes: positiveInteger(env, "BREAKGLASS_MAX_BODY_BYTES", 1_048_576),
    operatorDid,
    remediationDid,
    brokerDid,
    contractId: contractName(operatorDid),
    contractVersion: CONTRACT_VERSION,
    app,
    stateIntegrityKey: loadStateIntegrityKey(env),
    operatorApiKey: role === "coordinator" ? required(env, "T3N_API_KEY") : undefined,
    remediationApiKey: role === "coordinator" ? required(env, "AGENT_T3N_API_KEY") : undefined,
    brokerApiKey: role === "broker" ? required(env, "EFFECT_BROKER_T3N_API_KEY") : undefined,
    pollMs: positiveInteger(env, "BREAKGLASS_POLL_MS", 1_000),
  };
  if (config.app.owner !== "Ticoworld" || config.app.repository !== "t3n-breakglass-sandbox" || C2_PUSH_REF !== "refs/heads/c2-breakglass-demo" || C2_PUSH_SECRET_PATH !== ".breakglass-c2/exposed-deploy-key") throw new Error("fixed C2 source binding is inconsistent");
  return config;
}
