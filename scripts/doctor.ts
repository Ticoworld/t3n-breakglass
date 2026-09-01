import { readFile } from "node:fs/promises";
import path from "node:path";
import { SessionOrgDataClient } from "@terminal3/t3n-sdk";
import { CONTRACT_FUNCTION, CONTRACT_VERSION, INCIDENT_MAP_TAIL, connectTenant, redactError, required } from "./lib.js";
import { inspectGithubTarget } from "./github.js";
import { readPhase1Setup, readReplacementProvisioning } from "./product.js";

const root = path.resolve(import.meta.dirname, "..");

type Check = { status: "PASS" | "WARN" | "FAIL"; detail: Record<string, unknown> };

async function main() {
  const checks: Record<string, Check> = {};
  const sdkPackage = JSON.parse(await readFile(path.join(root, "node_modules", "@terminal3", "t3n-sdk", "package.json"), "utf8")) as { version?: string; name?: string };
  checks.sdk = { status: sdkPackage.name === "@terminal3/t3n-sdk" && sdkPackage.version === "5.2.0" ? "PASS" : "FAIL", detail: { package: sdkPackage.name, version: sdkPackage.version, required: "5.2.0" } };

  const { tenant, tenantDid, nodeUrl, t3n } = await connectTenant();
  checks.trusted_manifest = { status: "PASS", detail: { source: `${nodeUrl}/api/trust-manifest`, verified_by_sdk: true } };
  const me = await tenant.tenant.me() as { tenant?: string; status?: unknown };
  checks.operator_authentication = { status: me.tenant === tenantDid ? "PASS" : "FAIL", detail: { did: tenantDid, tenant_me_succeeded: true } };

  const setup = await readPhase1Setup();
  const contracts = await tenant.contracts.list();
  checks.contract = { status: contracts.includes(setup.contractId) ? "PASS" : "FAIL", detail: { contract: setup.contractId, version: CONTRACT_VERSION, function: CONTRACT_FUNCTION, registered: contracts.includes(setup.contractId) } };
  const mapStatuses = await Promise.all(["secrets", INCIDENT_MAP_TAIL].map(async (tail) => [tail, await tenant.maps.getStatus(tail)] as const));
  checks.required_maps = { status: mapStatuses.every(([, status]) => status !== "absent") ? "PASS" : "WARN", detail: { maps: Object.fromEntries(mapStatuses), destructive: false } };

  const { organizationDid, expectedAgentDid } = await readReplacementProvisioning();
  const orgData = new SessionOrgDataClient(t3n, nodeUrl);
  const admin = await orgData.amIAdmin({ orgDid: organizationDid });
  const roster = await orgData.listAgents({ orgDid: organizationDid, limit: 100 });
  const candidates = roster.agents.filter((agent) => agent.name === "BreakGlass Agent");
  const agentDid = candidates.length === 1 ? candidates[0].did : null;
  const card = agentDid ? await orgData.agentCardGet({ ownerDid: organizationDid, agentDid }) : null;
  const egress = agentDid ? await orgData.getAgentEgress({ orgDid: organizationDid, agentDid, contractId: setup.contractId }) : null;
  const egressValue = (egress as { egress?: { contract_id?: string; allowed_hosts?: string[]; functions?: string[]; version_req?: string } } | null)?.egress;
  const egressExact = Boolean(egressValue
    && egressValue.contract_id === setup.contractId
    && egressValue.allowed_hosts?.length === 1
    && egressValue.allowed_hosts[0] === "api.github.com"
    && egressValue.functions?.length === 1
    && egressValue.functions[0] === CONTRACT_FUNCTION
    && egressValue.version_req === CONTRACT_VERSION);
  checks.replacement_agent = { status: admin && agentDid === expectedAgentDid && Boolean(card?.card) ? "PASS" : "FAIL", detail: { organization_admin: admin, agent_did: agentDid, expected_agent_did: expectedAgentDid, private_card_readable: Boolean(card?.card) } };
  checks.egress = { status: egressExact ? "PASS" : "FAIL", detail: { policy: egressValue ?? null, read_only: true } };

  const patConfigured = typeof process.env.GITHUB_PAT === "string" && process.env.GITHUB_PAT.length > 0;
  const owner = process.env.GITHUB_OWNER;
  const repository = process.env.GITHUB_REPO;
  const keyId = Number(process.env.GITHUB_DEPLOY_KEY_ID ?? "");
  checks.github_credential = { status: patConfigured ? "PASS" : "WARN", detail: { configured: patConfigured, value_emitted: false } };
  if (patConfigured && owner && repository && Number.isSafeInteger(keyId) && keyId > 0) {
    try {
      const target = await inspectGithubTarget(owner, repository, keyId);
      checks.github_target = { status: "PASS", detail: { owner, repository, deploy_key_id: target.deployKeyId, repository_private: target.repositoryPrivate, key_present: true, destructive: false } };
    } catch (error) {
      checks.github_target = { status: "WARN", detail: { owner, repository, configured_key_id: keyId, key_present: false, note: redactError(error, [process.env.GITHUB_PAT ?? ""]) } };
    }
  } else {
    checks.github_target = { status: "WARN", detail: { configured: false, note: "set GITHUB_OWNER, GITHUB_REPO, GITHUB_DEPLOY_KEY_ID for a safe target check" } };
  }

  const failures = Object.values(checks).filter((check) => check.status === "FAIL").length;
  const overall = failures === 0 ? "PASS" : "FAIL";
  console.log(JSON.stringify({ phase: "2", stage: "safe_doctor", overall, node_url: nodeUrl, sdk: "@terminal3/t3n-sdk 5.2.0", checks, destructive_actions: 0, secrets_printed: false }, null, 2));
  if (failures > 0) process.exitCode = 1;
}

main().catch((error) => {
  console.error(`doctor failed: ${redactError(error, [process.env.GITHUB_PAT ?? "", process.env.T3N_API_KEY ?? ""])}`);
  process.exitCode = 1;
});
