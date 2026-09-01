import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  discoverWhoami,
  getNodeUrl,
  setEnvironment,
} from "@terminal3/t3n-sdk";
import { CONTRACT_FUNCTION, CONTRACT_VERSION, redactError, required } from "./lib.js";

const root = path.resolve(import.meta.dirname, "..");
const expectedAgentDid = "did:t3n:06cb1776cc1bc4596b4195112813453e95709500";
const contractId = "z:adb9365ee986cc6d0cb4006580782fe6fc7a431f:breakglass";
const probeIncident = "INC-PHASE1-CREDIT-PREFLIGHT-NO-SUCH";

function parseJson(raw: string): unknown {
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return null;
  }
}

function observedAvailable(raw: string): number | null {
  const match = raw.match(/available\s*[=:]\s*(\d+)/i);
  return match ? Number(match[1]) : null;
}

async function main() {
  if (process.env.GITHUB_PAT || process.env.T3N_API_KEY) {
    throw new Error("agent credit preflight refuses operator/GitHub credentials in its environment");
  }

  const agentApiKey = required("AGENT_T3N_API_KEY");
  const configuredAgentDid = required("AGENT_DID");
  if (configuredAgentDid !== expectedAgentDid) throw new Error("unexpected configured agent DID");

  setEnvironment("testnet");
  const nodeUrl = getNodeUrl();
  const whoami = await discoverWhoami({ baseUrl: nodeUrl, apiKey: agentApiKey });
  if (whoami.did !== expectedAgentDid) throw new Error("agent credential resolved to an unexpected DID");

  const response = await fetch(`${nodeUrl}/api/invoke`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-T3N-Api-Key": agentApiKey,
    },
    body: JSON.stringify({
      contract_id: contractId,
      contract_version: CONTRACT_VERSION,
      function_name: CONTRACT_FUNCTION,
      input: { incident_id: probeIncident },
    }),
    redirect: "error",
  });
  const raw = await response.text();
  const decoded = parseJson(raw);
  const available = observedAvailable(raw);
  const insufficient = response.status === 403 && /InsufficientCredit/i.test(raw);
  if (insufficient) {
    const evidence = {
      phase: "1",
      stage: "agent_credit_preflight",
      status: "BLOCKED_INSUFFICIENT_CREDIT",
      environment: "testnet",
      sdk: "@terminal3/t3n-sdk 5.2.0",
      transport: "keyed whoami + documented stateless POST /api/invoke",
      node_url: nodeUrl,
      agent_did: whoami.did,
      expected_agent_did: expectedAgentDid,
      organisations: whoami.organisations,
      owner: whoami.owner,
      probe: { incident_id: probeIncident, destructive_calls: 0 },
      http_status: response.status,
      available_base_units: available,
      github_destructive_calls: 0,
      github_pat_in_process: false,
      agent_key_logged: false,
    };
    await mkdir(path.join(root, "evidence"), { recursive: true });
    await writeFile(path.join(root, "evidence", "phase1-agent-credit-preflight.json"), JSON.stringify(evidence, null, 2) + "\n");
    console.log(JSON.stringify(evidence, null, 2));
    process.exitCode = 2;
    return;
  }

  if (!response.ok) throw new Error(`agent credit probe failed with HTTP ${response.status}`);
  const evidence = {
    phase: "1",
    stage: "agent_credit_preflight",
    status: "SUFFICIENT_FOR_METERED_INVOKE",
    environment: "testnet",
    sdk: "@terminal3/t3n-sdk 5.2.0",
    transport: "keyed whoami + documented stateless POST /api/invoke",
    node_url: nodeUrl,
    agent_did: whoami.did,
    expected_agent_did: expectedAgentDid,
    organisations: whoami.organisations,
    owner: whoami.owner,
    probe: { incident_id: probeIncident, destructive_calls: 0 },
    http_status: response.status,
    probe_result: decoded,
    available_base_units: available,
    github_destructive_calls: 0,
    github_pat_in_process: false,
    operator_credential_in_process: false,
    agent_key_logged: false,
  };
  await mkdir(path.join(root, "evidence"), { recursive: true });
  await writeFile(path.join(root, "evidence", "phase1-agent-credit-preflight.json"), JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((error) => {
  console.error(`agent credit preflight failed: ${redactError(error, [process.env.AGENT_T3N_API_KEY ?? ""])}`);
  process.exitCode = 1;
});
