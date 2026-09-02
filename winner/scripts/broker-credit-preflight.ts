import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { connectC1Principal, redact } from "./t3n.js";

const root = path.resolve(import.meta.dirname, "../..");

async function main() {
  if (process.env.GITHUB_PAT || process.env.T3N_API_KEY) throw new Error("broker credit preflight refuses PAT/operator credentials");
  const registration = JSON.parse(await readFile(path.join(root, "winner", "evidence", "contract-registration.json"), "utf8")) as { contract?: { name?: string; version?: string } };
  if (!registration.contract?.name) throw new Error("C1 contract registration evidence is missing");
  const broker = await connectC1Principal("EFFECT_BROKER_T3N_API_KEY", "EFFECT_BROKER_DID");
  const probeIncident = `C1-CREDIT-PREFLIGHT-${Date.now()}`;
  let result: unknown = null;
  let error: Record<string, unknown> | null = null;
  try {
    const response = await fetch(`${broker.nodeUrl}/api/invoke`, { method: "POST", headers: { "Content-Type": "application/json", "X-T3N-Api-Key": broker.apiKey }, body: JSON.stringify({ contract_id: registration.contract.name, contract_version: registration.contract.version ?? "2.0.0", function_name: "claim-effect", input: { incident_id: probeIncident } }), redirect: "error" });
    const raw = await response.text();
    try { result = JSON.parse(raw); } catch { result = redact(raw, [broker.apiKey]); }
    if (!response.ok) error = { message: `server returned HTTP ${response.status}`, http_status: response.status, body: result };
  } catch (caught) { error = { message: redact(caught, [broker.apiKey]), name: caught instanceof Error ? caught.name : "unknown" }; }
  const message = JSON.stringify(error);
  const insufficient = typeof message === "string" && /InsufficientCredit/i.test(message);
  const evidence = { experiment: "C1 dedicated effect broker credit preflight", status: insufficient ? "BLOCKED_ON_BROKER_AGENT_FUNDING" : "SUFFICIENT_OR_POLICY_RESULT", environment: "testnet", sdk: "@terminal3/t3n-sdk 5.2.0", t3n_node: broker.nodeUrl, effect_broker_did: broker.did, contract: registration.contract.name, probe: { incident_id: probeIncident, function: "claim-effect", provider_mutations: 0 }, result, error, insufficient_credit: insufficient, operator_credential_in_process: false, github_pat_in_process: false, credentials_logged: false, funding_action_if_blocked: insufficient ? "Fund the effect broker DID from the Terminal 3 testnet token/credit control plane, then rerun this preflight and C1 configuration." : null };
  const evidencePath = path.join(root, "winner", "evidence", "broker-credit-preflight.json");
  await mkdir(path.dirname(evidencePath), { recursive: true });
  await writeFile(evidencePath, JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify(evidence, null, 2));
  if (insufficient) process.exitCode = 2;
}

main().catch((error) => { console.error(`broker credit preflight failed: ${redact(error, [process.env.EFFECT_BROKER_T3N_API_KEY ?? "", process.env.GITHUB_PAT ?? ""])}`); process.exitCode = 1; });
