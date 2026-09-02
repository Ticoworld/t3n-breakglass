import { spawn } from "node:child_process";
import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  SessionOrgDataClient,
  TenantClient,
  UserUpsertError,
  discoverWhoami,
  getNodeUrl,
  setEnvironment,
} from "@terminal3/t3n-sdk";
import { connectPrincipal, connectTenant, redactError, required } from "../../scripts/lib.js";

const root = path.resolve(import.meta.dirname, "../..");
const evidencePath = path.join(root, "winner", "evidence", "credit-self-admit-probe.json");
const creditEnvPath = path.join(root, ".env.credit-probe-agent");
const agentEnvName = "CREDIT_PROBE_AGENT_T3N_API_KEY";
const agentName = "BreakGlass Credit Probe";
const realBrokerDid = "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57";
const c1ContractId = "z:adb9365ee986cc6d0cb4006580782fe6fc7a431f:breakglass-winner-c1";
const c1ContractVersion = "2.0.0";
const probeIncident = "C1-CREDIT-SELF-ADMIT-NO-SUCH";
const probeFunction = "claim-effect";
const forbiddenAgentEnv = [
  "T3N_API_KEY",
  "T3N_API_KEY_ALT",
  "GITHUB_PAT",
  "AGENT_T3N_API_KEY",
  "REPLACEMENT_AGENT_T3N_API_KEY",
  "EFFECT_BROKER_T3N_API_KEY",
];

type JsonObject = Record<string, unknown>;

function parseJson(raw: string): unknown {
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return null;
  }
}

function safeError(error: unknown, secrets: string[] = []): JsonObject {
  let message = error instanceof Error ? error.message : String(error);
  for (const secret of secrets) {
    if (secret) message = message.split(secret).join("[REDACTED]");
  }
  return {
    name: error instanceof Error ? error.name : "Error",
    message: message.replace(/t3n_key_[A-Za-z0-9_.-]+/g, "[REDACTED_T3N_KEY]"),
  };
}

function observedAvailable(raw: string): number | null {
  const match = raw.match(/available\s*[=:]\s*(\d+)/i);
  return match ? Number(match[1]) : null;
}

function safePreflightResult(value: unknown): unknown {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const input = value as JsonObject;
  const allowed = ["result", "function", "incident_id", "state", "effect_attempts", "provider_http", "note", "error", "code", "request_id"];
  return Object.fromEntries(allowed.filter((key) => key in input).map((key) => [key, input[key]]));
}

function safeSubmitResult(value: { txHash?: string; refusedFields?: string[]; userFound?: boolean; tenantAdmit?: { status: string; grantedCredits?: string; reason?: string; detail?: string } }): JsonObject {
  return {
    tx_hash_present: Boolean(value.txHash),
    user_found: value.userFound ?? null,
    refused_fields: value.refusedFields ?? [],
    tenant_admit: value.tenantAdmit
      ? {
          status: value.tenantAdmit.status,
          granted_credits: value.tenantAdmit.grantedCredits ?? null,
          reason: value.tenantAdmit.reason ?? null,
          detail: value.tenantAdmit.detail ?? null,
        }
      : null,
  };
}

function safeBalance(value: { available: number; reserved: number; last_settled_seq_no: number; version: number; credit_exhausted: boolean }): JsonObject {
  return {
    available_base_units: value.available,
    reserved_base_units: value.reserved,
    last_settled_seq_no: value.last_settled_seq_no,
    version: value.version,
    credit_exhausted: value.credit_exhausted,
  };
}

async function safeTenantMe(t3n: Awaited<ReturnType<typeof connectPrincipal>>["t3n"], nodeUrl: string, did: string): Promise<JsonObject> {
  try {
    const tenant = new TenantClient({ t3n, baseUrl: nodeUrl, tenantDid: did });
    const me = await tenant.tenant.me();
    return {
      observable: true,
      tenant: me.tenant,
      status: me.status,
      label: me.label,
      quotas_present: me.quotas !== null && me.quotas !== undefined,
    };
  } catch (error) {
    return { observable: false, error: safeError(error) };
  }
}

async function meteredPreflight(t3n: Awaited<ReturnType<typeof connectPrincipal>>["t3n"], nodeUrl: string, apiKey: string): Promise<JsonObject> {
  const balance = await t3n.getBalance();
  const response = await fetch(`${nodeUrl}/api/invoke`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-T3N-Api-Key": apiKey },
    body: JSON.stringify({
      contract_id: c1ContractId,
      contract_version: c1ContractVersion,
      function_name: probeFunction,
      input: { incident_id: probeIncident },
    }),
    redirect: "error",
  });
  const raw = await response.text();
  const decoded = parseJson(raw);
  const insufficient = response.status === 403 && /InsufficientCredit/i.test(raw);
  return {
    transport: "keyed whoami + getBalance + documented stateless POST /api/invoke",
    probe: { incident_id: probeIncident, contract_id: c1ContractId, contract_version: c1ContractVersion, function: probeFunction },
    http_status: response.status,
    response_ok: response.ok,
    classification: insufficient ? "InsufficientCredit" : response.ok ? "METERED_INVOCATION_RETURNED" : "BOUNDED_HTTP_FAILURE",
    available_base_units_from_error: observedAvailable(raw),
    balance: safeBalance(balance),
    result: response.ok ? safePreflightResult(decoded) : null,
    error: insufficient ? (typeof decoded === "object" && decoded && "error" in decoded ? (decoded as JsonObject).error : raw.slice(0, 500)) : null,
    github_mutations: 0,
    provider_mutations: 0,
  };
}

async function agentOnlyMain(): Promise<void> {
  const presentForbidden = forbiddenAgentEnv.filter((name) => Boolean(process.env[name]));
  if (presentForbidden.length > 0) throw new Error(`agent-only process received forbidden credential variables: ${presentForbidden.join(",")}`);
  const apiKey = required(agentEnvName);
  setEnvironment("testnet");
  const nodeUrl = getNodeUrl();
  const principal = await connectPrincipal(agentEnvName);
  const whoamiBefore = await discoverWhoami({ baseUrl: nodeUrl, apiKey });
  if (principal.did !== whoamiBefore.did) throw new Error("agent credential DID disagrees with authenticated session DID");
  const tenantBefore = await safeTenantMe(principal.t3n, nodeUrl, whoamiBefore.did);
  const initial = await meteredPreflight(principal.t3n, nodeUrl, apiKey);

  if (initial.classification !== "InsufficientCredit") {
    console.log(JSON.stringify({
      status: "BASELINE_NOT_INSUFFICIENT_STOPPED",
      node_url: nodeUrl,
      identity_before: { did: whoamiBefore.did, owner: whoamiBefore.owner, organisations: whoamiBefore.organisations },
      tenant_before: tenantBefore,
      initial_credit_preflight: initial,
      self_admit_attempted: false,
      github_mutations: 0,
      provider_mutations: 0,
    }));
    return;
  }

  let selfAdmit: JsonObject;
  try {
    const result = await principal.t3n.submitUserInput({ profile: {}, becomeDevTenant: true });
    selfAdmit = { outcome: "returned", safe_result: safeSubmitResult(result) };
  } catch (error) {
    selfAdmit = {
      outcome: "threw",
      error_kind: error instanceof UserUpsertError ? error.kind : "Unknown",
      safe_error: safeError(error, [apiKey]),
    };
  }

  const whoamiAfter = await discoverWhoami({ baseUrl: nodeUrl, apiKey });
  const tenantAfter = await safeTenantMe(principal.t3n, nodeUrl, whoamiAfter.did);
  const post = await meteredPreflight(principal.t3n, nodeUrl, apiKey);
  console.log(JSON.stringify({
    status: "AGENT_PHASE_COMPLETE",
    node_url: nodeUrl,
    identity_before: { did: whoamiBefore.did, owner: whoamiBefore.owner, organisations: whoamiBefore.organisations },
    identity_after: { did: whoamiAfter.did, owner: whoamiAfter.owner, organisations: whoamiAfter.organisations },
    tenant_before: tenantBefore,
    self_admit_attempted: true,
    self_admit: selfAdmit,
    tenant_after: tenantAfter,
    initial_credit_preflight: initial,
    post_admit_credit_preflight: post,
    github_mutations: 0,
    provider_mutations: 0,
  }));
}

function safeEgress(value: unknown): unknown {
  if (!value || typeof value !== "object") return null;
  const egress = (value as JsonObject).egress;
  if (!egress || typeof egress !== "object") return null;
  const row = egress as JsonObject;
  return {
    contract_id: row.contract_id ?? null,
    allowed_hosts: row.allowed_hosts ?? [],
    functions: row.functions ?? [],
    version_req: row.version_req ?? null,
  };
}

async function safeOwnershipSnapshot(orgData: SessionOrgDataClient, orgDid: string, agentDid: string): Promise<JsonObject> {
  const admin = await orgData.amIAdmin({ orgDid });
  const roster = await orgData.listAgents({ orgDid, limit: 100 });
  const agent = roster.agents.find((row) => row.did === agentDid);
  let card: JsonObject;
  try {
    const response = await orgData.agentCardGet({ ownerDid: orgDid, agentDid });
    const rawCard = (response as JsonObject).card;
    const cardBytes = typeof rawCard === "string" ? Buffer.byteLength(rawCard) : rawCard ? Buffer.byteLength(JSON.stringify(rawCard)) : 0;
    card = { read_succeeded: Boolean(rawCard), card_bytes: cardBytes, body_recorded: false };
  } catch (error) {
    card = { read_succeeded: false, card_bytes: 0, body_recorded: false, error: safeError(error) };
  }
  const egressResponse = await orgData.getAgentEgress({ orgDid, agentDid, contractId: c1ContractId });
  return {
    organization_admin: admin,
    roster_contains_agent: Boolean(agent),
    roster_agent: agent ? { did: agent.did, name: agent.name, contract_count: agent.contract_count } : null,
    private_agent_card: card,
    c1_egress: safeEgress(egressResponse),
    github_egress_present: Boolean(safeEgress(egressResponse)),
    sensitive_map_acl_grants_observed: agent?.contract_count ?? null,
  };
}

function jsonLine(raw: string): JsonObject | null {
  const line = raw.trim().split(/\r?\n/).filter(Boolean).at(-1);
  const value = line ? parseJson(line) : null;
  return value && typeof value === "object" && !Array.isArray(value) ? value as JsonObject : null;
}

async function runAgentOnly(): Promise<JsonObject> {
  const childEnv = { ...process.env };
  for (const name of [...forbiddenAgentEnv, agentEnvName]) delete childEnv[name];
  return await new Promise((resolve) => {
    const child = spawn(process.execPath, [
      "--env-file-if-exists=.env.credit-probe-agent",
      "--import",
      "tsx",
      path.join(root, "winner", "scripts", "credit-self-admit-probe.ts"),
      "--agent-only",
    ], { cwd: root, env: childEnv, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
    child.once("error", (error) => resolve({ status: "AGENT_CHILD_ERROR", safe_error: safeError(error) }));
    child.once("close", (code) => {
      const parsed = jsonLine(stdout);
      if (parsed) {
        parsed.child_exit_code = code;
        return resolve(parsed);
      }
      resolve({ status: "AGENT_CHILD_OUTPUT_INVALID", child_exit_code: code, stderr: safeError(stderr, [process.env["T3N_API_KEY"] ?? ""]) });
    });
  });
}

async function pathExists(filePath: string): Promise<boolean> {
  try { await access(filePath); return true; } catch { return false; }
}

function classify(agentPhase: JsonObject, before: JsonObject, after: JsonObject, organisationDid: string, remediationDid: string): string {
  const selfAdmit = agentPhase.self_admit as JsonObject | undefined;
  const selfAdmitReturned = selfAdmit?.outcome === "returned";
  const tenantAdmit = (selfAdmit?.safe_result as JsonObject | undefined)?.tenant_admit as JsonObject | null | undefined;
  const selfAdmitAccepted = selfAdmitReturned && (tenantAdmit?.status === "admitted" || tenantAdmit?.status === "already-admitted");
  const rejected = selfAdmit?.outcome === "threw" && (selfAdmit.error_kind === "EmailNotVerified" || selfAdmit.error_kind === "UserNotFound");
  const post = agentPhase.post_admit_credit_preflight as JsonObject | undefined;
  const postSucceeded = post?.response_ok === true;
  const insufficientAfter = post?.classification === "InsufficientCredit";
  const beforeAgent = before.roster_agent as JsonObject | null;
  const afterAgent = after.roster_agent as JsonObject | null;
  const identityBefore = agentPhase.identity_before as JsonObject | undefined;
  const identityAfter = agentPhase.identity_after as JsonObject | undefined;
  const orgSemanticsPreserved = Boolean(
    identityBefore?.did && identityBefore.did === identityAfter?.did &&
    identityBefore.did !== remediationDid && identityBefore.did !== realBrokerDid &&
    identityAfter?.did !== remediationDid && identityAfter?.did !== realBrokerDid &&
    identityBefore.owner === organisationDid && identityAfter.owner === organisationDid &&
    Array.isArray(identityBefore.organisations) && identityBefore.organisations.includes(organisationDid) &&
    Array.isArray(identityAfter.organisations) && identityAfter.organisations.includes(organisationDid) &&
    before.roster_contains_agent === true && after.roster_contains_agent === true &&
    beforeAgent?.did === afterAgent?.did && beforeAgent?.name === afterAgent?.name &&
    beforeAgent?.contract_count === 0 && afterAgent?.contract_count === 0 &&
    before.c1_egress === null && after.c1_egress === null,
  );
  if (selfAdmitAccepted && insufficientAfter) return "SELF_ADMIT_NO_CREDIT";
  if (rejected) return "SELF_ADMIT_REJECTED";
  if (selfAdmitReturned && tenantAdmit?.status === "refused") return "SELF_ADMIT_REJECTED";
  if (selfAdmitAccepted && postSucceeded && !orgSemanticsPreserved) return "SELF_ADMIT_ROLE_MUTATION";
  if (selfAdmitAccepted && postSucceeded && orgSemanticsPreserved) return "SELF_ADMIT_FUNDED_AGENT";
  if (selfAdmitAccepted && !postSucceeded) return "OTHER_BOUNDED_FAILURE";
  if (selfAdmit?.outcome === "returned" || selfAdmit?.outcome === "threw") return "OTHER_BOUNDED_FAILURE";
  return "OTHER_BOUNDED_FAILURE";
}

async function operatorMain(): Promise<void> {
  if (await pathExists(creditEnvPath) || await pathExists(evidencePath)) {
    throw new Error("credit probe checkpoint already exists; refusing to create another disposable agent");
  }
  const provisioning = JSON.parse(await readFile(path.join(root, "evidence", "phase1-replacement-agent-provisioning.json"), "utf8")) as JsonObject;
  const orgDid = String(provisioning.organisation_did ?? "");
  const operatorDid = String(provisioning.operator_did ?? "");
  const remediationDid = String(provisioning.replacement_agent_did ?? "");
  if (!/^did:t3n:[0-9a-f]{40}$/.test(orgDid) || !/^did:t3n:[0-9a-f]{40}$/.test(operatorDid) || !/^did:t3n:[0-9a-f]{40}$/.test(remediationDid)) {
    throw new Error("existing provisioning evidence has invalid principal metadata");
  }
  const operatorPrincipal = await connectPrincipal("T3N_API_KEY");
  if (operatorPrincipal.did !== operatorDid) throw new Error("authenticated principal is not the recorded operator");
  const operatorBalance = await operatorPrincipal.t3n.getBalance();
  if (operatorBalance.available === 0) {
    const evidence = {
      experiment: "C1 disposable agent self-serve credit admission probe",
      status: "OTHER_BOUNDED_FAILURE",
      bounded_failure: "operator control plane has no usable credit; disposable agent creation did not return a DID or credential",
      environment: "testnet", sdk: "@terminal3/t3n-sdk 5.2.0", t3n_node: operatorPrincipal.nodeUrl,
      source_reference: { basis: "Terminal 3 SDK public reference README and typed submitUserInput documentation", exact_call: "t3n.submitUserInput({ profile: {}, becomeDevTenant: true })", rationale: "testnet self-admit is documented as potentially minting configured welcome credits; effect for an org-owned agent is unverified" },
      operator_control_plane_preflight: {
        did: operatorPrincipal.did,
        balance: safeBalance(operatorBalance),
        required_for_metered_control_plane_call: 10000000000,
        observed_error: "InsufficientCredit (required=10000000000, available=0)",
      },
      disposable_agent: { name: agentName, did: null, organisation_did: orgDid, key_id: null, credential_in_evidence: false, credential_stored_in: null, creation_completed: false, creation_confirmation: "no DID or credential was returned; roster confirmation is also credit-gated" },
      initial_credit_preflight: null,
      self_admit_attempted: false,
      self_admit: null,
      post_admit_credit_preflight: null,
      identity: { before: null, after: null, tenant_before: null, tenant_after: null },
      organization_ownership: { before: null, after: null, observation: "unavailable because the operator roster call is credit-gated" },
      observed_identity_role_changes: null,
      privileges: { contract_count_before: null, c1_egress_before: null, github_egress_before: false, sensitive_map_acl_observed: false },
      safe_for_real_c1_broker: false,
      real_broker_did_touched: false,
      credential_in_evidence: false,
      github_mutation_count: 0,
      provider_mutation_count: 0,
      t3n_control_plane_mutations: { create_agent_completed: 0, self_admit: 0 },
    };
    await mkdir(path.dirname(evidencePath), { recursive: true });
    await writeFile(evidencePath, JSON.stringify(evidence, null, 2) + "\n", { flag: "wx" });
    console.log(JSON.stringify(evidence, null, 2));
    return;
  }
  const { t3n, nodeUrl, tenantDid } = await connectTenant();
  if (tenantDid !== operatorDid) throw new Error("authenticated principal is not the recorded operator");
  const orgData = new SessionOrgDataClient(t3n, nodeUrl);
  if (!(await orgData.amIAdmin({ orgDid }))) throw new Error("operator is not an admin of the existing organization");
  const beforeCreate = await orgData.listAgents({ orgDid, limit: 100 });
  if (beforeCreate.agents.some((row) => row.name === agentName)) throw new Error("agent name already exists; refusing a second disposable agent");

  const created = await t3n.createAgent(orgDid, agentName);
  const agentDid = created.agentDid.value;
  if (!/^did:t3n:[0-9a-f]{40}$/.test(agentDid)) throw new Error("T3N returned an invalid disposable agent DID");
  if ([realBrokerDid, operatorDid, remediationDid].includes(agentDid)) throw new Error("T3N returned a protected existing principal");
  if (!/^t3n_key_[0-9a-f]{16}\.[0-9a-f]+$/.test(created.apiKey)) throw new Error("T3N returned an unexpected agent key format");
  if (!/^[0-9a-f]{16}$/.test(created.keyId)) throw new Error("T3N returned an unexpected key ID format");
  await writeFile(creditEnvPath, [`${agentEnvName}=${created.apiKey}`, `CREDIT_PROBE_AGENT_DID=${agentDid}`, `CREDIT_PROBE_AGENT_ORGANISATION_DID=${orgDid}`, `CREDIT_PROBE_AGENT_KEY_ID=${created.keyId}`, ""].join("\n"), { flag: "wx", mode: 0o600 });

  const ownershipBefore = await safeOwnershipSnapshot(orgData, orgDid, agentDid);
  if (ownershipBefore.roster_contains_agent !== true || (ownershipBefore.roster_agent as JsonObject | null)?.contract_count !== 0 || ownershipBefore.c1_egress !== null) {
    const evidence = {
      experiment: "C1 disposable agent self-serve credit admission probe",
      status: "OTHER_BOUNDED_FAILURE",
      bounded_failure: "new agent did not start with the required zero-privilege shape; self-admit was not attempted",
      environment: "testnet", sdk: "@terminal3/t3n-sdk 5.2.0", t3n_node: nodeUrl,
      source_reference: { basis: "Terminal 3 SDK public reference README and typed submitUserInput documentation", exact_call: "t3n.submitUserInput({ profile: {}, becomeDevTenant: true })", rationale: "testnet self-admit is documented as potentially minting configured welcome credits; effect for an org-owned agent is unverified" },
      disposable_agent: { name: agentName, did: agentDid, organisation_did: orgDid, key_id: created.keyId, credential_in_evidence: false, credential_stored_in: ".env.credit-probe-agent (ignored)" },
      initial_credit_preflight: null, self_admit_attempted: false, self_admit: null, post_admit_credit_preflight: null,
      organization_ownership: { before: ownershipBefore, after: null }, observed_identity_role_changes: null,
      privileges: { contract_count_before: (ownershipBefore.roster_agent as JsonObject | null)?.contract_count ?? null, c1_egress_before: ownershipBefore.c1_egress, github_egress_before: ownershipBefore.github_egress_present },
      credential_in_evidence: false, github_mutation_count: 0, provider_mutation_count: 0, t3n_control_plane_mutations: { create_agent: 1, self_admit: 0 },
    };
    await mkdir(path.dirname(evidencePath), { recursive: true });
    await writeFile(evidencePath, JSON.stringify(evidence, null, 2) + "\n", { flag: "wx" });
    console.log(JSON.stringify(evidence, null, 2));
    return;
  }

  const agentPhase = await runAgentOnly();
  const ownershipAfter = await safeOwnershipSnapshot(orgData, orgDid, agentDid);
  const classification = agentPhase.status === "BASELINE_NOT_INSUFFICIENT_STOPPED"
    ? "OTHER_BOUNDED_FAILURE"
    : classify(agentPhase, ownershipBefore, ownershipAfter, orgDid, remediationDid);
  const identityBefore = agentPhase.identity_before ?? null;
  const identityAfter = agentPhase.identity_after ?? null;
  const evidence = {
    experiment: "C1 disposable agent self-serve credit admission probe",
    status: classification,
    environment: "testnet", sdk: "@terminal3/t3n-sdk 5.2.0", t3n_node: nodeUrl,
    source_reference: { basis: "Terminal 3 SDK public reference README and typed submitUserInput documentation", exact_call: "t3n.submitUserInput({ profile: {}, becomeDevTenant: true })", rationale: "testnet self-admit is documented as potentially minting configured welcome credits; effect for an org-owned agent is unverified" },
    disposable_agent: { name: agentName, did: agentDid, organisation_did: orgDid, key_id: created.keyId, credential_in_evidence: false, credential_stored_in: ".env.credit-probe-agent (ignored)" },
    initial_credit_preflight: agentPhase.initial_credit_preflight ?? null,
    self_admit_attempted: agentPhase.self_admit_attempted === true,
    self_admit: agentPhase.self_admit ?? null,
    post_admit_credit_preflight: agentPhase.post_admit_credit_preflight ?? null,
    identity: { before: identityBefore, after: identityAfter, tenant_before: agentPhase.tenant_before ?? null, tenant_after: agentPhase.tenant_after ?? null },
    organization_ownership: { before: ownershipBefore, after: ownershipAfter },
    observed_identity_role_changes: {
      did_changed: Boolean((identityBefore as JsonObject | null)?.did && (identityAfter as JsonObject | null)?.did && (identityBefore as JsonObject).did !== (identityAfter as JsonObject).did),
      owner_changed: Boolean((identityBefore as JsonObject | null)?.owner !== (identityAfter as JsonObject | null)?.owner),
      organisation_membership_changed: JSON.stringify((identityBefore as JsonObject | null)?.organisations ?? null) !== JSON.stringify((identityAfter as JsonObject | null)?.organisations ?? null),
      roster_membership_preserved: ownershipBefore.roster_contains_agent === true && ownershipAfter.roster_contains_agent === true,
      contract_privileges_before: (ownershipBefore.roster_agent as JsonObject | null)?.contract_count ?? null,
      contract_privileges_after: (ownershipAfter.roster_agent as JsonObject | null)?.contract_count ?? null,
      c1_egress_before: ownershipBefore.c1_egress,
      c1_egress_after: ownershipAfter.c1_egress,
    },
    safe_for_real_c1_broker: classification === "SELF_ADMIT_FUNDED_AGENT",
    real_broker_did_touched: false,
    credential_in_evidence: false,
    github_mutation_count: 0,
    provider_mutation_count: 0,
    t3n_control_plane_mutations: { create_agent: 1, self_admit: agentPhase.self_admit_attempted === true ? 1 : 0 },
  };
  await mkdir(path.dirname(evidencePath), { recursive: true });
  await writeFile(evidencePath, JSON.stringify(evidence, null, 2) + "\n", { flag: "wx" });
  console.log(JSON.stringify(evidence, null, 2));
}

if (process.argv.includes("--agent-only")) {
  agentOnlyMain().catch((error) => {
    console.log(JSON.stringify({ status: "AGENT_PHASE_ERROR", safe_error: safeError(error, [process.env[agentEnvName] ?? ""]) }));
    process.exitCode = 0;
  });
} else {
  operatorMain().catch((error) => {
    console.error(`credit self-admit probe failed: ${redactError(error, [process.env.T3N_API_KEY ?? "", process.env.GITHUB_PAT ?? ""])}`);
    process.exitCode = 1;
  });
}
