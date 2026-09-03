import { mkdir, readFile, writeFile } from "node:fs/promises";
import { SessionOrgDataClient, type BoundGrant } from "@terminal3/t3n-sdk";
import path from "node:path";
import { connectTenant, redactError } from "../../scripts/lib.js";
import { BROKER_FUNCTIONS, CONTRACT_VERSION, ORGANISATION_DID, RESERVATION_FUNCTION } from "./constants.js";

const root = path.resolve(import.meta.dirname, "../..");
const registrationPath = path.join(root, "winner", "evidence", "contract-registration.json");
const provisioningPath = path.join(root, "winner", "evidence", "broker-provisioning.json");
const replacementEvidencePath = path.join(root, "evidence", "phase1-replacement-agent-provisioning.json");
const evidencePath = path.join(root, "winner", "evidence", "delegation-configuration.json");
const EXPECTED_OPERATOR_DID = "did:t3n:adb9365ee986cc6d0cb4006580782fe6fc7a431f";
const EXPECTED_REMEDIATION_DID = "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019";
const EXPECTED_BROKER_DID = "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57";
const EXPECTED_CONTRACT_NAME = `z:${EXPECTED_OPERATOR_DID.slice("did:t3n:".length)}:breakglass-winner-c1`;

type Target = { role: "remediation_agent" | "effect_broker"; did: string; functions: string[] };

function valueFromEnvFile(contents: string, name: string): string | undefined {
  const line = contents.split(/\r?\n/).find((entry) => entry.startsWith(`${name}=`));
  if (!line) return undefined;
  const value = line.slice(name.length + 1).trim();
  return value.replace(/^['"]|['"]$/g, "");
}

async function requiredEnvFile(file: string, name: string): Promise<string> {
  const value = valueFromEnvFile(await readFile(path.join(root, file), "utf8"), name);
  if (!value) throw new Error(`${name} missing from ${file}`);
  return value;
}

function safeGrant(grant: BoundGrant): Record<string, unknown> {
  return {
    grantee: grant.grantee,
    contract_id: grant.contract_id,
    functions: Array.isArray(grant.functions) ? [...grant.functions] : null,
    scopes: Array.isArray(grant.scopes) ? [...grant.scopes] : null,
    read_scopes: Array.isArray(grant.read_scopes) ? [...grant.read_scopes] : grant.read_scopes ?? null,
    allowed_hosts: Array.isArray(grant.allowed_hosts) ? [...grant.allowed_hosts] : grant.allowed_hosts ?? null,
    version_req: grant.version_req ?? null,
    window: grant.window ?? null,
  };
}

function safeEgress(response: { egress: { contract_id: string; allowed_hosts: string[]; functions: string[]; version_req?: string } | null }): Record<string, unknown> | null {
  if (!response.egress) return null;
  return {
    contract_id: response.egress.contract_id,
    allowed_hosts: [...response.egress.allowed_hosts],
    functions: [...response.egress.functions],
    version_req: response.egress.version_req ?? null,
  };
}

function sameUnorderedStrings(actual: unknown, expected: string[]): boolean {
  if (!Array.isArray(actual) || actual.some((value) => typeof value !== "string") || actual.length !== expected.length) return false;
  const actualSorted = [...actual].sort();
  const expectedSorted = [...expected].sort();
  return actualSorted.every((value, index) => value === expectedSorted[index]);
}

function emptyOrAbsentStrings(actual: unknown): boolean {
  return actual === undefined || (Array.isArray(actual) && actual.length === 0);
}

function documentedDefaultWindow(window: BoundGrant["window"]): boolean {
  if (window === undefined) return true;
  if (!window || typeof window.valid_from_secs !== "number" || typeof window.valid_until_secs !== "number") return false;
  if (!Number.isSafeInteger(window.valid_from_secs) || !Number.isSafeInteger(window.valid_until_secs) || window.valid_until_secs <= window.valid_from_secs) return false;
  return Object.keys(window).every((key) => key === "valid_from_secs" || key === "valid_until_secs");
}

function exactGrant(grant: BoundGrant | undefined, target: Target, contractNameValue: string): boolean {
  if (!grant) return false;
  return grant.grantee === target.did
    && grant.contract_id === contractNameValue
    && sameUnorderedStrings(grant.functions, target.functions)
    && Array.isArray(grant.scopes) && grant.scopes.length === 0
    && emptyOrAbsentStrings(grant.allowed_hosts)
    && emptyOrAbsentStrings(grant.read_scopes)
    && grant.version_req === CONTRACT_VERSION
    && documentedDefaultWindow(grant.window);
}

async function readTargetGrant(t3n: Awaited<ReturnType<typeof connectTenant>>["t3n"], orgData: SessionOrgDataClient, target: Target, contractNameValue: string) {
  const document = await t3n.getMemberDelegation();
  const matches = document.grants.filter((grant) => grant.grantee === target.did && grant.contract_id === contractNameValue);
  const egressResponse = await orgData.getAgentEgress({ orgDid: ORGANISATION_DID, agentDid: target.did, contractId: contractNameValue });
  const memberExact = matches.length === 1 && exactGrant(matches[0], target, contractNameValue);
  const egress = safeEgress(egressResponse);
  return {
    target_did: target.did,
    member_grants_for_exact_pair: matches.map(safeGrant),
    current_grant_classification: matches.length === 0 ? "ABSENT" : memberExact ? "EXACT_TARGET" : "BROADER_OR_DIFFERENT",
    member_grant_exact: memberExact,
    agent_egress: egress,
    agent_egress_read_success: true,
    separate_agent_egress_exact: egress === null,
    exact: memberExact && egress === null,
  };
}

async function main() {
  if (process.env.GITHUB_PAT) throw new Error("C1 delegation configuration refuses a GitHub PAT");

  const registration = JSON.parse(await readFile(registrationPath, "utf8")) as {
    operator_did?: string;
    contract?: { name?: string; version?: string; contract_id?: number; functions?: string[] };
    map?: { private?: boolean; acl_contract_id?: number };
  };
  const provisioning = JSON.parse(await readFile(provisioningPath, "utf8")) as {
    operator_did?: string;
    organisation_did?: string;
    effect_broker_did?: string;
  };
  const replacementEvidence = JSON.parse(await readFile(replacementEvidencePath, "utf8")) as {
    organisation_did?: string;
    replacement_agent_did?: string;
  };
  const recordedRemediationDid = await requiredEnvFile(".env.replacement-agent", "REPLACEMENT_AGENT_DID");
  const recordedRemediationOrg = await requiredEnvFile(".env.replacement-agent", "REPLACEMENT_AGENT_ORGANISATION_DID");
  const recordedBrokerDid = await requiredEnvFile(".env.effect-broker", "EFFECT_BROKER_DID");
  const recordedBrokerOrg = await requiredEnvFile(".env.effect-broker", "EFFECT_BROKER_ORGANISATION_DID");

  if (process.env.C1_OPERATOR_DID && process.env.C1_OPERATOR_DID !== EXPECTED_OPERATOR_DID) throw new Error("C1_OPERATOR_DID override differs from fixed operator");
  if (process.env.REMEDIATION_AGENT_DID && process.env.REMEDIATION_AGENT_DID !== EXPECTED_REMEDIATION_DID) throw new Error("REMEDIATION_AGENT_DID override differs from fixed C1 principal");
  if (process.env.EFFECT_BROKER_DID && process.env.EFFECT_BROKER_DID !== EXPECTED_BROKER_DID) throw new Error("EFFECT_BROKER_DID override differs from fixed C1 principal");
  if (registration.operator_did !== EXPECTED_OPERATOR_DID || provisioning.operator_did !== EXPECTED_OPERATOR_DID) throw new Error("operator evidence does not match fixed operator DID");
  const registeredContract = registration.contract;
  if (!registeredContract || registeredContract.name !== EXPECTED_CONTRACT_NAME || registeredContract.version !== CONTRACT_VERSION || !Number.isSafeInteger(registeredContract.contract_id) || registeredContract.contract_id <= 0 || registration.map?.private !== true || registration.map.acl_contract_id !== registeredContract.contract_id) throw new Error("registration evidence does not match the registered repaired C1 contract");
  const registeredContractId = registeredContract.name;
  const requiredRegisteredFunctions = ["create-incident", "get-incident", RESERVATION_FUNCTION, ...BROKER_FUNCTIONS];
  if (!Array.isArray(registeredContract.functions) || registeredContract.functions.length !== requiredRegisteredFunctions.length || !requiredRegisteredFunctions.every((name) => registeredContract.functions?.includes(name))) throw new Error("registration evidence does not list the complete repaired C1 interface");
  if (provisioning.organisation_did !== ORGANISATION_DID || replacementEvidence.organisation_did !== ORGANISATION_DID || recordedRemediationOrg !== ORGANISATION_DID || recordedBrokerOrg !== ORGANISATION_DID) throw new Error("agent organization evidence does not match the fixed organization");
  if (replacementEvidence.replacement_agent_did !== EXPECTED_REMEDIATION_DID || recordedRemediationDid !== EXPECTED_REMEDIATION_DID) throw new Error("remediation evidence does not match fixed C1 principal");
  if (provisioning.effect_broker_did !== EXPECTED_BROKER_DID || recordedBrokerDid !== EXPECTED_BROKER_DID) throw new Error("broker evidence does not match fixed C1 principal");
  if (new Set([EXPECTED_OPERATOR_DID, EXPECTED_REMEDIATION_DID, EXPECTED_BROKER_DID]).size !== 3) throw new Error("C1 principals must be three distinct DIDs");

  const targets: Target[] = [
    { role: "remediation_agent", did: EXPECTED_REMEDIATION_DID, functions: [RESERVATION_FUNCTION] },
    { role: "effect_broker", did: EXPECTED_BROKER_DID, functions: [...BROKER_FUNCTIONS] },
  ];
  const { t3n, tenantDid, nodeUrl } = await connectTenant();
  if (tenantDid !== EXPECTED_OPERATOR_DID) throw new Error("authenticated operator DID differs from fixed operator");
  const orgData = new SessionOrgDataClient(t3n, nodeUrl);
  const admin = await orgData.amIAdmin({ orgDid: ORGANISATION_DID });
  if (!admin) throw new Error("operator is not admin of the expected organization");

  const preWrite: Record<string, Awaited<ReturnType<typeof readTargetGrant>>> = {};
  for (const target of targets) preWrite[target.role] = await readTargetGrant(t3n, orgData, target, registeredContractId);

  const mutationCounts: Record<string, number> = { remediation_agent: 0, effect_broker: 0 };
  const afterEachUpdate: Record<string, unknown> = {};
  for (const target of targets) {
    if (preWrite[target.role].exact) continue;
    await t3n.updateMemberDelegation({ grantee: target.did, contract_id: registeredContractId, functions: target.functions, scopes: [], version_req: CONTRACT_VERSION, allowed_hosts: [] });
    mutationCounts[target.role] += 1;
    const afterUpdate = await readTargetGrant(t3n, orgData, target, registeredContractId);
    if (!afterUpdate.exact) throw new Error(`${target.role} delegation post-write readback is not exact`);
    afterEachUpdate[target.role] = afterUpdate;
  }

  const postWrite: Record<string, Awaited<ReturnType<typeof readTargetGrant>>> = {};
  for (const target of targets) {
    postWrite[target.role] = await readTargetGrant(t3n, orgData, target, registeredContractId);
    if (!postWrite[target.role].exact) throw new Error(`${target.role} final delegation readback is not exact`);
  }
  const operatorBalance = await t3n.getBalance();
  const status = operatorBalance.available > 0 ? "CONFIGURED_VERIFIED" : "CONFIGURED_BUT_OPERATOR_HEADROOM_EXHAUSTED";
  const evidence = {
    experiment: "C1 principal separation configuration",
    status,
    environment: "testnet",
    sdk: "@terminal3/t3n-sdk 5.2.0",
    t3n_node: nodeUrl,
    operator_did: tenantDid,
    organisation_did: ORGANISATION_DID,
    contract: registeredContractId,
    contract_version: CONTRACT_VERSION,
    contract_id: registeredContract.contract_id,
    operator_admin_read: { exact_call: "SessionOrgDataClient.amIAdmin({ orgDid })", success: true, is_admin: true },
    remediation_agent_did: EXPECTED_REMEDIATION_DID,
    effect_broker_did: EXPECTED_BROKER_DID,
    pre_write_readback: preWrite,
    mutation_count: { remediation_agent: mutationCounts.remediation_agent, effect_broker: mutationCounts.effect_broker, total_updateMemberDelegation: mutationCounts.remediation_agent + mutationCounts.effect_broker },
    after_each_update_readback: afterEachUpdate,
    post_write_readback: postWrite,
    exact_authority: {
      remediation: { functions: [RESERVATION_FUNCTION], scopes: [], allowed_hosts: [], version_req: CONTRACT_VERSION, provider_http: false },
      broker: { functions: [...BROKER_FUNCTIONS], scopes: [], allowed_hosts: [], version_req: CONTRACT_VERSION, provider_http: false },
      function_order_comparison: "order-insensitive; readback values are preserved",
    },
    operator_can_claim: false,
    post_configuration_operator_balance: {
      available_base_units: operatorBalance.available,
      reserved_base_units: operatorBalance.reserved,
      credit_exhausted: operatorBalance.credit_exhausted,
      last_settled_seq_no: operatorBalance.last_settled_seq_no,
      version: operatorBalance.version,
      read_success: true,
    },
    github_api_calls: 0,
    provider_mutations: 0,
    c1_contract_invocations: 0,
    credentials_in_evidence: false,
  };
  await mkdir(path.dirname(evidencePath), { recursive: true });
  await writeFile(evidencePath, JSON.stringify(evidence, null, 2) + "\n");
  console.log(JSON.stringify(evidence, null, 2));
  if (status !== "CONFIGURED_VERIFIED") throw new Error("operator available balance is zero after configuration");
}

main().catch((error) => { console.error(`C1 delegation configuration failed: ${redactError(error, [process.env.T3N_API_KEY ?? "", process.env.GITHUB_PAT ?? ""])}`); process.exitCode = 1; });
