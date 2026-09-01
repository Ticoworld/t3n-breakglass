import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  CONTRACT_FUNCTION,
  CONTRACT_TAIL,
  CONTRACT_VERSION,
  INCIDENT_MAP_TAIL,
  connectTenant,
  redactError,
  required,
} from "./lib.js";

const root = path.resolve(import.meta.dirname, "..");
const wasmPath = path.join(root, "contract", "target", "wasm32-wasip2", "release", "breakglass_contract.wasm");
const evidenceDir = path.join(root, "evidence");

type TargetEvidence = {
  owner?: string;
  repository?: string;
  deploy_key?: { id?: number; read_only?: boolean };
  repository_private?: boolean;
  deploy_key_count?: number;
};

async function phase1Target(): Promise<Required<Pick<TargetEvidence, "owner" | "repository">> & { keyId: number }> {
  const target = JSON.parse(await readFile(path.join(evidenceDir, "phase1-github-target.json"), "utf8")) as TargetEvidence;
  const owner = target.owner;
  const repository = target.repository;
  const keyId = Number(target.deploy_key?.id);
  if (
    owner !== "Ticoworld" ||
    repository !== "t3n-breakglass-sandbox" ||
    target.repository_private !== true ||
    target.deploy_key_count !== 1 ||
    target.deploy_key?.read_only !== true ||
    !Number.isSafeInteger(keyId) ||
    keyId <= 0
  ) {
    throw new Error("phase1 GitHub target evidence is not the expected private one-key target");
  }
  return { owner, repository, keyId };
}

async function ensurePrivateContractMap(tenant: Awaited<ReturnType<typeof connectTenant>>["tenant"], tail: string, contractId: number) {
  const acl = { only: [contractId] } as const;
  try {
    await tenant.maps.create({
      tail,
      visibility: "private",
      writers: acl,
      readers: acl,
    });
  } catch (error) {
    if (!String(error).toLowerCase().includes("already exists")) throw error;
  }
  await tenant.maps.update(tail, {
    visibility: "private",
    writers: acl,
    readers: acl,
  });
}

async function main() {
  const githubPat = required("GITHUB_PAT");
  const target = await phase1Target();
  const { t3n, tenant, tenantDid, nodeUrl } = await connectTenant();
  const wasm = new Uint8Array(await readFile(wasmPath));
  const registered = await tenant.contracts.register({
    tail: CONTRACT_TAIL,
    version: CONTRACT_VERSION,
    wasm,
  });

  await ensurePrivateContractMap(tenant, "secrets", registered.contract_id);
  await ensurePrivateContractMap(tenant, INCIDENT_MAP_TAIL, registered.contract_id);

  // This is the only Phase 1 code path that reads GITHUB_PAT. It is sent as
  // the value of a T3N control-plane write and is never printed or returned.
  await tenant.maps.entrySet("secrets", "github_pat", githubPat);

  await mkdir(evidenceDir, { recursive: true });
  const evidence = {
    phase: "1",
    status: "bootstrapped_operator_only",
    environment: "testnet",
    t3n_node: nodeUrl,
    operator_did: tenantDid,
    contract: {
      name: registered.name,
      tail: CONTRACT_TAIL,
      version: CONTRACT_VERSION,
      contract_id: registered.contract_id,
      function: CONTRACT_FUNCTION,
      input_boundary: { allowed_fields: ["incident_id"], target_fields_accepted: false },
    },
    target_precondition: {
      host: "api.github.com",
      owner: target.owner,
      repository: target.repository,
      deploy_key_id: target.keyId,
    },
    storage: {
      incident_authority_map: tenant.canonicalName(INCIDENT_MAP_TAIL),
      incident_map_acl: { readers: [registered.contract_id], writers: [registered.contract_id], private: true },
      secret_map: tenant.canonicalName("secrets"),
      credential_key: "github_pat",
    },
    sealed_credential: { exposed_to_agent: false, exposed_to_invoke_process: false, logged: false },
    egress_policy: { host: "api.github.com", exact: true, agent_grant_pending: true },
    agent_authorization: "pending_separate_agent_did",
  };
  await writeFile(path.join(evidenceDir, "phase1-setup.json"), JSON.stringify(evidence, null, 2) + "\n");

  console.log(JSON.stringify({
    status: evidence.status,
    operator_did: tenantDid,
    contract: registered.name,
    contract_id: registered.contract_id,
    version: CONTRACT_VERSION,
    target: { owner: target.owner, repository: target.repository, deploy_key_id: target.keyId },
    github_pat: "not printed",
    next: "provide a separately funded agent API key/DID, then run authorize-agent",
  }, null, 2));

  // Keep t3n referenced so this script's operator authentication is explicit
  // in the source review; no agent call is made by the bootstrap path.
  void t3n;
}

main().catch((error) => {
  console.error(`bootstrap failed: ${redactError(error, [process.env.GITHUB_PAT ?? "", process.env.T3N_API_KEY ?? ""])}`);
  process.exitCode = 1;
});
