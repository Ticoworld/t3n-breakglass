import {
  appJwt,
  exactKey,
  listInstallationRepositories,
  listKeys,
  mintReadOnlyInstallationToken,
  repositoryContains,
  repositoryListIsWellFormed,
  repositoryRead,
  revokeInstallationToken,
  type AppConfig,
  type GithubResponse,
} from "./github-app.js";

export type ProviderVerificationClassification = "VERIFIED_ABSENT" | "VERIFIED_PRESENT" | "UNAVAILABLE";

export interface ProviderVerification {
  classification: ProviderVerificationClassification;
  target_id: number;
  token_minted: boolean;
  token_revoked: boolean;
  revoked_token_refused: boolean;
  repository_scope_http_status: number | null;
  exact_get_http_status: number | null;
  list_get_http_status: number | null;
  list_body_valid: boolean;
  list_contains_target: boolean;
}

export interface ProviderVerifierAdapter {
  mint(config: AppConfig): Promise<{ token: string | null; response: GithubResponse }>;
  repositories(token: string): Promise<GithubResponse>;
  exact(token: string, config: AppConfig, targetId: number): Promise<GithubResponse>;
  keys(token: string, config: AppConfig): Promise<GithubResponse>;
  revoke(token: string): Promise<GithubResponse>;
  probe(token: string, config: AppConfig): Promise<GithubResponse>;
}

function defaultAdapter(): ProviderVerifierAdapter {
  return {
    async mint(config) {
      const jwt = await appJwt(config);
      const result = await mintReadOnlyInstallationToken(config, jwt, "verifier");
      return { token: result.token, response: result.response };
    },
    repositories: listInstallationRepositories,
    exact: (token, config, targetId) => exactKey(token, config.owner, config.repository, targetId),
    keys: (token, config) => listKeys(token, config.owner, config.repository),
    revoke: revokeInstallationToken,
    probe: (token, config) => repositoryRead(token, config.owner, config.repository),
  };
}

export async function verifyProviderTarget(
  config: AppConfig,
  targetId: number,
  adapter: ProviderVerifierAdapter = defaultAdapter(),
): Promise<ProviderVerification> {
  if (!Number.isSafeInteger(targetId) || targetId <= 0) throw new Error("provider verifier target ID is invalid");
  const minted = await adapter.mint(config);
  const token = minted.token;
  let tokenRevoked = false;
  let revokedTokenRefused = false;
  let repositoryScopeStatus: number | null = null;
  let exactStatus: number | null = null;
  let listStatus: number | null = null;
  let listValid = false;
  let contains = false;
  let verification: ProviderVerification | undefined;
  try {
    if (!token) throw new Error(`verifier token exchange failed HTTP ${minted.response.status}`);
    const repositories = await adapter.repositories(token);
    repositoryScopeStatus = repositories.status;
    const rows = repositories.body && typeof repositories.body === "object" && !Array.isArray(repositories.body)
      ? (repositories.body as Record<string, unknown>).repositories
      : null;
    const scoped = Array.isArray(rows) && rows.some((row) => row && typeof row === "object" && (row as Record<string, unknown>).full_name === `${config.owner}/${config.repository}` && (row as Record<string, unknown>).private === true);
    if (repositories.status !== 200 || !scoped) throw new Error("verifier token did not prove exact private repository scope");
    const exact = await adapter.exact(token, config, targetId);
    const list = await adapter.keys(token, config);
    exactStatus = exact.status;
    listStatus = list.status;
    listValid = repositoryListIsWellFormed(list.body);
    contains = repositoryContains(list.body, targetId);
    verification = {
      classification: exact.status === 404 && list.status === 200 && listValid && !contains ? "VERIFIED_ABSENT" : "VERIFIED_PRESENT",
      target_id: targetId,
      token_minted: true,
      token_revoked: tokenRevoked,
      revoked_token_refused: revokedTokenRefused,
      repository_scope_http_status: repositoryScopeStatus,
      exact_get_http_status: exactStatus,
      list_get_http_status: listStatus,
      list_body_valid: listValid,
      list_contains_target: contains,
    };
  } finally {
    if (token) {
      const revoked = await adapter.revoke(token);
      if (revoked.status !== 204) throw new Error(`verifier token revocation failed HTTP ${revoked.status}`);
      tokenRevoked = true;
      const probe = await adapter.probe(token, config);
      revokedTokenRefused = probe.status === 401 || probe.status === 403;
      if (!revokedTokenRefused) throw new Error(`revoked verifier token was not refused HTTP ${probe.status}`);
    }
  }
  if (!verification) throw new Error("provider verifier did not produce a verification result");
  verification.token_revoked = tokenRevoked;
  verification.revoked_token_refused = revokedTokenRefused;
  return verification;
}
