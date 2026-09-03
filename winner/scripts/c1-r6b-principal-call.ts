import { readFile } from "node:fs/promises";
import path from "node:path";
import { connectC1Principal, invokeC1, redact } from "./t3n.js";
import { CONTRACT_VERSION, contractName } from "./constants.js";

const root = path.resolve(import.meta.dirname, "../..");
const OPERATOR_DID = "did:t3n:adb9365ee986cc6d0cb4006580782fe6fc7a431f";
const REMEDIATION_DID = "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019";
const BROKER_DID = "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57";

type JsonObject = Record<string, unknown>;

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function envValue(contents: string, name: string): string {
  const line = contents.split(/\r?\n/).find((entry) => entry.startsWith(`${name}=`));
  if (!line) throw new Error(`${name} missing from credential file`);
  const value = line.slice(name.length + 1).trim().replace(/^['"]|['"]$/g, "");
  if (!value) throw new Error(`${name} is empty`);
  return value;
}

function isObject(value: unknown): value is JsonObject {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function sanitize(value: unknown, depth = 0): unknown {
  if (depth > 8) return "[DEPTH_LIMIT]";
  if (typeof value === "string") return value.slice(0, 1000);
  if (typeof value === "number" || typeof value === "boolean" || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, 40).map((entry) => sanitize(entry, depth + 1));
  if (!isObject(value)) return String(value);
  const output: JsonObject = {};
  for (const [key, entry] of Object.entries(value)) output[key] = /api[_-]?key|authorization|bearer|token|jwt|private[_-]?key|pat|secret|credential/i.test(key) ? "[REDACTED]" : sanitize(entry, depth + 1);
  return output;
}

function parseInput(value: string): JsonObject {
  const parsed = JSON.parse(value) as unknown;
  if (!isObject(parsed)) throw new Error("C1_R6B_INPUT must be a JSON object");
  return parsed;
}

async function main(): Promise<void> {
  if (process.env.T3N_API_KEY || process.env.GITHUB_PAT || Object.keys(process.env).some((key) => key.startsWith("GITHUB_"))) throw new Error("R6B principal call refuses operator/provider credentials");
  const role = required("C1_R6B_ROLE");
  const functionName = required("C1_R6B_FUNCTION");
  const input = parseInput(required("C1_R6B_INPUT"));
  const operatorDid = required("C1_OPERATOR_DID");
  if (operatorDid !== OPERATOR_DID) throw new Error("unexpected fixed operator DID");
  const credentialFile = role === "remediation" ? ".env.replacement-agent" : role === "broker" ? ".env.effect-broker" : "";
  const keyName = role === "remediation" ? "REPLACEMENT_AGENT_T3N_API_KEY" : role === "broker" ? "EFFECT_BROKER_T3N_API_KEY" : "";
  const didName = role === "remediation" ? "REPLACEMENT_AGENT_DID" : role === "broker" ? "EFFECT_BROKER_DID" : "";
  const expectedDid = role === "remediation" ? REMEDIATION_DID : role === "broker" ? BROKER_DID : "";
  if (!credentialFile || !keyName || !didName) throw new Error("role must be remediation or broker");
  const credentials = await readFile(path.join(root, credentialFile), "utf8");
  const key = envValue(credentials, keyName);
  const did = envValue(credentials, didName);
  if (did !== expectedDid) throw new Error(`${role} credential metadata does not match the fixed principal`);
  process.env[keyName === "REPLACEMENT_AGENT_T3N_API_KEY" ? "AGENT_T3N_API_KEY" : "EFFECT_BROKER_T3N_API_KEY"] = key;
  process.env[keyName === "REPLACEMENT_AGENT_T3N_API_KEY" ? "AGENT_DID" : "EFFECT_BROKER_DID"] = did;
  const principal = await connectC1Principal(keyName === "REPLACEMENT_AGENT_T3N_API_KEY" ? "AGENT_T3N_API_KEY" : "EFFECT_BROKER_T3N_API_KEY", keyName === "REPLACEMENT_AGENT_T3N_API_KEY" ? "AGENT_DID" : "EFFECT_BROKER_DID");
  const response = await invokeC1(principal.apiKey, principal.nodeUrl, contractName(operatorDid), functionName, input);
  process.stdout.write(JSON.stringify({ role, did: principal.did, function: functionName, contract: contractName(operatorDid), version: CONTRACT_VERSION, request_fields: Object.keys(input).sort(), response: sanitize(response), provider_operations: 0, state_mutation_expected: false, credentials_in_output: false }));
}

main().catch((error) => {
  process.stdout.write(JSON.stringify({ role: process.env.C1_R6B_ROLE ?? null, did: process.env.C1_R6B_EXPECTED_DID ?? null, function: process.env.C1_R6B_FUNCTION ?? null, contract: contractName(OPERATOR_DID), version: CONTRACT_VERSION, request_fields: (() => { try { return Object.keys(parseInput(process.env.C1_R6B_INPUT ?? "{}")); } catch { return []; } })().sort(), application_response: null, provider_operations: 0, state_mutation_expected: false, credentials_in_output: false, error: sanitize(redact(error, [process.env.AGENT_T3N_API_KEY ?? "", process.env.EFFECT_BROKER_T3N_API_KEY ?? ""])) }));
  process.exitCode = 0;
});
