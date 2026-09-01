import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { discoverWhoami, getNodeUrl, setEnvironment } from "@terminal3/t3n-sdk";
import { CONTRACT_FUNCTION, CONTRACT_VERSION, redactError, required } from "./lib.js";

const root = path.resolve(import.meta.dirname, "..");
const expectedOrgDid = "did:t3n:3c63f09271c0d9184abbcccbfae28698a8f4a912";
const expectedContractId = "z:adb9365ee986cc6d0cb4006580782fe6fc7a431f:breakglass";
const probeIncident = "INC-PHASE1-REPLACEMENT-NO-SUCH";

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
    throw new Error("replacement credit preflight refuses operator/GitHub credentials in its environment");
  }
  const agentApiKey = required("REPLACEMENT_AGENT_T3N_API_KEY");
  const expectedAgentDid = required("REPLACEMENT_AGENT_DID");
  const provisioning = JSON.parse(await readFile(path.join(root, "evidence", "phase1-replacement-agent-provisioning.json"), "utf8")) as {
    replacement_agent_did?: string;
    organisation_did?: string;
  };
  if (provisioning.replacement_agent_did !== expectedAgentDid || provisioning.organisation_did !== expectedOrgDid) {
    throw new Error("replacement agent environment does not match provisioning evidence");
  }

  setEnvironment("testnet");
  const nodeUrl = getNodeUrl();
  const whoami = await discoverWhoami({ baseUrl: nodeUrl, apiKey: agentApiKey });
  if (whoami.did !== expectedAgentDid || whoami.owner !== expectedOrgDid) {
    throw new Error("replacement agent identity or organization owner check failed");
  }

  const response = await fetch(`${nodeUrl}/api/invoke`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-T3N-Api-Key": agentApiKey,
    },
    body: JSON.stringify({
      contract_id: expectedContractId,
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
  const evidence = {
    phase: "1-repair",
    stage: "replacement_agent_credit_preflight",
    status: insufficient ? "BLOCKED_FUNDING" : "SUFFICIENT_FOR_METERED_INVOKE",
    environment: "testnet",
    sdk: "@terminal3/t3n-sdk 5.2.0",
    transport: "keyed whoami + documented stateless POST /api/invoke",
    t3n_node: nodeUrl,
    agent_did: whoami.did,
    owner: whoami.owner,
    organisations: whoami.organisations,
    probe: { incident_id: probeIncident, expected: "DENIED", destructive_calls: 0 },
    http_status: response.status,
    available_base_units: available,
    error_class: insufficient ? "InsufficientCredit" : null,
    probe_result: insufficient ? null : decoded,
    github_destructive_calls: 0,
    github_pat_in_process: false,
    operator_credential_in_process: false,
    agent_key_logged: false,
  };
  await mkdir(path.join(root, "evidence"), { recursive: true });
  await writeFile(path.join(root, "evidence", "phase1-replacement-agent-credit-preflight.json"), JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify(evidence, null, 2));
  if (insufficient) process.exitCode = 2;
}

main().catch((error) => {
  console.error(`replacement agent credit preflight failed: ${redactError(error, [process.env.REPLACEMENT_AGENT_T3N_API_KEY ?? ""])}`);
  process.exitCode = 1;
});
