import { readFile } from "node:fs/promises";
import path from "node:path";
import { SessionOrgDataClient } from "@terminal3/t3n-sdk";
import { connectTenant } from "../../scripts/lib.js";
import { BROKER_FUNCTIONS, CONTRACT_VERSION, ORGANISATION_DID, RESERVATION_FUNCTION, contractName } from "./constants.js";

const root = path.resolve(import.meta.dirname, "../..");
const OPERATOR_DID = "did:t3n:adb9365ee986cc6d0cb4006580782fe6fc7a431f";
const REMEDIATION_DID = "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019";
const BROKER_DID = "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57";
const CONTRACT_NAME = contractName(OPERATOR_DID);
const FORBIDDEN_ENV = ["GITHUB_PAT", "GITHUB_APP_ID", "GITHUB_APP_INSTALLATION_ID", "GITHUB_APP_PRIVATE_KEY_PATH", "GITHUB_OWNER", "GITHUB_REPO", "AGENT_T3N_API_KEY", "EFFECT_BROKER_T3N_API_KEY"];

function safeGrant(grant: Record<string, unknown>): Record<string, unknown> {
  return {
    grantee: grant.grantee,
    contract_id: grant.contract_id,
    functions: Array.isArray(grant.functions) ? grant.functions : [],
    scopes: Array.isArray(grant.scopes) ? grant.scopes : [],
    allowed_hosts: grant.allowed_hosts ?? null,
    version_req: grant.version_req ?? null,
  };
}

async function main(): Promise<void> {
  const forbidden = FORBIDDEN_ENV.filter((name) => Boolean(process.env[name]));
  if (forbidden.length) throw new Error(`R6 config check refuses non-operator credentials: ${forbidden.join(",")}`);
  if (!process.env.T3N_API_KEY) throw new Error("T3N_API_KEY is required");
  const registration = JSON.parse(await readFile(path.join(root, "winner", "evidence", "contract-registration.json"), "utf8")) as Record<string, any>;
  if (registration.contract?.name !== CONTRACT_NAME || registration.contract.version !== CONTRACT_VERSION || registration.contract.contract_id !== 876 || registration.map?.private !== true || registration.map.acl_contract_id !== 876) throw new Error("active C1 registration evidence is not 2.0.2/876");
  const { t3n, tenantDid, nodeUrl } = await connectTenant();
  if (tenantDid !== OPERATOR_DID) throw new Error("authenticated operator DID mismatch");
  const orgData = new SessionOrgDataClient(t3n, nodeUrl);
  const admin = await orgData.amIAdmin({ orgDid: ORGANISATION_DID });
  if (!admin) throw new Error("operator is not admin of the expected organization");
  const member = await t3n.getMemberDelegation();
  const read = async (did: string, expected: string[]) => {
    const grants = member.grants.filter((grant) => grant.grantee === did && grant.contract_id === CONTRACT_NAME).map((grant) => safeGrant(grant as unknown as Record<string, unknown>));
    const egressResponse = await orgData.getAgentEgress({ orgDid: ORGANISATION_DID, agentDid: did, contractId: CONTRACT_NAME });
    const egress = egressResponse.egress ? { contract_id: egressResponse.egress.contract_id, functions: [...egressResponse.egress.functions], allowed_hosts: [...egressResponse.egress.allowed_hosts], version_req: egressResponse.egress.version_req ?? null } : null;
    const row = grants.length === 1 ? grants[0] : null;
    const actualFunctions = row && Array.isArray(row.functions) ? row.functions.filter((value): value is string => typeof value === "string") : [];
    const actualHosts = row?.allowed_hosts === null || row?.allowed_hosts === undefined ? [] : row.allowed_hosts;
    const exact = row?.grantee === did && actualFunctions.length === expected.length && [...actualFunctions].sort().join("\n") === [...expected].sort().join("\n") && Array.isArray(row.scopes) && row.scopes.length === 0 && Array.isArray(actualHosts) && actualHosts.length === 0 && row.version_req === CONTRACT_VERSION && egress === null;
    return { did, grants, egress, exact };
  };
  console.log(JSON.stringify({ operator: tenantDid, organization: ORGANISATION_DID, admin, contract: CONTRACT_NAME, version: CONTRACT_VERSION, numeric_contract_id: 876, remediation: await read(REMEDIATION_DID, [RESERVATION_FUNCTION]), broker: await read(BROKER_DID, [...BROKER_FUNCTIONS]), provider_calls: 0, mutations: 0 }, null, 2));
}

main().catch((error) => { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 1; });
