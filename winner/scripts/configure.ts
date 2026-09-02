import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { connectTenant, redactError } from "../../scripts/lib.js";
import { BROKER_FUNCTIONS, CONTRACT_VERSION, RESERVATION_FUNCTION, contractName } from "./constants.js";

const root = path.resolve(import.meta.dirname, "../..");
const registrationPath = path.join(root, "winner", "evidence", "contract-registration.json");
const provisioningPath = path.join(root, "winner", "evidence", "broker-provisioning.json");
const evidencePath = path.join(root, "winner", "evidence", "delegation-configuration.json");

function valueFromEnvFile(contents: string, name: string): string | undefined { return contents.split(/\r?\n/).find((line) => line.startsWith(`${name}=`))?.slice(name.length + 1).trim(); }
async function requiredEnvFile(name: string): Promise<string> { const value = valueFromEnvFile(await readFile(path.join(root, ".env.replacement-agent"), "utf8"), name); if (!value) throw new Error(`${name} missing from .env.replacement-agent`); return value; }

async function main() {
  if (process.env.GITHUB_PAT) throw new Error("C1 delegation configuration refuses a GitHub PAT");
  const registration = JSON.parse(await readFile(registrationPath, "utf8")) as { operator_did?: string; contract?: { name?: string; version?: string; contract_id?: number } };
  const provisioning = JSON.parse(await readFile(provisioningPath, "utf8")) as { effect_broker_did?: string };
  const recordedRemediationDid = await requiredEnvFile("REPLACEMENT_AGENT_DID");
  const recordedBrokerDid = provisioning.effect_broker_did;
  if (process.env.REMEDIATION_AGENT_DID && process.env.REMEDIATION_AGENT_DID !== recordedRemediationDid) throw new Error("REMEDIATION_AGENT_DID override differs from recorded C1 principal");
  if (process.env.EFFECT_BROKER_DID && process.env.EFFECT_BROKER_DID !== recordedBrokerDid) throw new Error("EFFECT_BROKER_DID override differs from recorded C1 principal");
  const remediationDid = recordedRemediationDid;
  const brokerDid = recordedBrokerDid;
  if (!brokerDid || !/^did:t3n:[0-9a-f]{40}$/.test(brokerDid)) throw new Error("effect broker DID is missing or invalid");
  if (!/^did:t3n:[0-9a-f]{40}$/.test(remediationDid)) throw new Error("remediation agent DID is missing or invalid");
  if (!registration.operator_did || registration.contract?.version !== CONTRACT_VERSION || !registration.contract.name) throw new Error("registration evidence is incomplete");
  if (new Set([registration.operator_did, remediationDid, brokerDid]).size !== 3) throw new Error("C1 principals must be three distinct DIDs");
  const { t3n, tenantDid, nodeUrl } = await connectTenant();
  if (tenantDid !== registration.operator_did) throw new Error("authenticated operator DID differs from registration evidence");
  const contractId = contractName(tenantDid);
  if (contractId !== registration.contract.name) throw new Error("registration contract name does not match operator tenant");
  await t3n.updateMemberDelegation({ grantee: remediationDid, contract_id: contractId, functions: [RESERVATION_FUNCTION], scopes: [], version_req: CONTRACT_VERSION, allowed_hosts: [] });
  await t3n.updateMemberDelegation({ grantee: brokerDid, contract_id: contractId, functions: [...BROKER_FUNCTIONS], scopes: [], version_req: CONTRACT_VERSION, allowed_hosts: [] });
  const evidence = {
    experiment: "C1 principal separation configuration",
    status: "CONFIGURED",
    environment: "testnet",
    sdk: "@terminal3/t3n-sdk 5.2.0",
    t3n_node: nodeUrl,
    operator_did: tenantDid,
    contract: contractId,
    remediation_agent_did: remediationDid,
    effect_broker_did: brokerDid,
    remediation_grant: { functions: [RESERVATION_FUNCTION], scopes: [], allowed_hosts: [], provider_http: false },
    broker_grant: { functions: [...BROKER_FUNCTIONS], scopes: [], allowed_hosts: [], provider_http: false },
    operator_can_claim: false,
    provider_mutations: 0,
  };
  await mkdir(path.dirname(evidencePath), { recursive: true });
  await writeFile(evidencePath, JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((error) => { console.error(`C1 delegation configuration failed: ${redactError(error, [process.env.T3N_API_KEY ?? "", process.env.GITHUB_PAT ?? ""])}`); process.exitCode = 1; });
