import {
  T3nClient,
  TenantClient,
  createEthAuthInput,
  eth_get_address,
  fetchTrustedManifest,
  getNodeUrl,
  loadWasmComponent,
  metamask_sign,
  setEnvironment,
} from "@terminal3/t3n-sdk";

export const CONTRACT_TAIL = "breakglass";
export const CONTRACT_VERSION = "1.0.0";
export const CONTRACT_FUNCTION = "execute-incident";
export const INCIDENT_MAP_TAIL = "incidents";
export const GITHUB_HOST = "api.github.com";

export function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

export function redactError(error: unknown, secrets: string[] = []): string {
  let message = error instanceof Error ? error.message : String(error);
  for (const secret of secrets) {
    if (secret) message = message.split(secret).join("[REDACTED]");
  }
  return message.replace(/t3n_key_[A-Za-z0-9_-]+/g, "[REDACTED_T3N_KEY]");
}

/**
 * Authenticate exactly one principal.  The API-key environment variable is
 * selected by the caller so the agent path can run without loading the
 * operator bootstrap file or the GitHub PAT.
 */
export async function connectPrincipal(apiKeyEnv: string) {
  const t3nApiKey = required(apiKeyEnv);
  setEnvironment("testnet");
  const nodeUrl = getNodeUrl();
  const wasmComponent = await loadWasmComponent();
  const address = eth_get_address(t3nApiKey);
  const t3n = new T3nClient({
    trustAnchor: await fetchTrustedManifest("testnet"),
    wasmComponent,
    handlers: {
      EthSign: metamask_sign(address, undefined, t3nApiKey),
    },
  });

  await t3n.handshake();
  const did = await t3n.authenticate(createEthAuthInput(address));
  return { t3n, did: did.value, apiKeyEnv, nodeUrl };
}

export async function connectTenant() {
  const principal = await connectPrincipal("T3N_API_KEY");
  const tenant = new TenantClient({
    t3n: principal.t3n,
    baseUrl: principal.nodeUrl,
    tenantDid: principal.did,
  });
  await tenant.tenant.me();
  return { ...principal, tenant, tenantDid: principal.did };
}

export async function connectAgent() {
  return connectPrincipal("AGENT_T3N_API_KEY");
}

export function scriptName(tenantDid: string): string {
  return `z:${tenantDid.slice("did:t3n:".length)}:${CONTRACT_TAIL}`;
}

/** Operator-only delegation.  The agent never receives this client or key. */
export async function authorizeAgent(
  t3n: T3nClient,
  operatorTenantDid: string,
  agentDid: string,
  version: string,
) {
  await t3n.updateMemberDelegation({
    grantee: agentDid,
    contract_id: scriptName(operatorTenantDid),
    functions: [CONTRACT_FUNCTION],
    scopes: [],
    version_req: version,
    allowed_hosts: [GITHUB_HOST],
  });
}
