export type GithubAppWebhookReadinessClassification =
  | "WEBHOOK_CONFIGURED_AND_REACHABLE"
  | "WEBHOOK_CONFIGURATION_INVALID"
  | "WEBHOOK_ENDPOINT_UNREACHABLE";

export interface GithubAppWebhookReadinessFacts {
  expected_url: string;
  app: {
    http_status: number;
    id: number | null;
    slug: string | null;
    permissions: Record<string, unknown>;
    events: unknown[];
  };
  installation: {
    http_status: number;
    id: number | null;
    repository_selection: string | null;
    permissions: Record<string, unknown>;
  };
  hook: {
    http_status: number;
    url: string | null;
    content_type: string | null;
    insecure_ssl: string | number | null;
    // GitHub may return an opaque/masked secret field. It is deliberately not
    // inspected, copied, compared, logged, or returned by the evaluator.
    secret?: unknown;
    [key: string]: unknown;
  };
  tunnel: {
    ngrok_api_http_status: number | null;
    public_origin: string | null;
    forwarding_address: string | null;
    public_route_probe_http_status: number | null;
  };
  receiver: {
    listening_locally: boolean;
  };
}

export interface GithubAppWebhookReadinessResult {
  valid: boolean;
  classification: GithubAppWebhookReadinessClassification;
  reasons: string[];
  secret_persisted: false;
}

function expectedPermissions(permissions: Record<string, unknown>): boolean {
  return permissions.administration === "write" && permissions.contents === "read" && permissions.metadata === "read";
}

function localForwardingAddress(value: string | null): boolean {
  return value === "http://localhost:8787" || value === "http://127.0.0.1:8787";
}

/**
 * Evaluate only documented/readable GitHub App configuration and endpoint
 * observations. GitHub's hook-config response does not expose an `active`
 * field, so unsupported extra fields are intentionally ignored.
 */
export function evaluateGithubAppWebhookReadiness(facts: GithubAppWebhookReadinessFacts): GithubAppWebhookReadinessResult {
  const configurationReasons: string[] = [];
  const endpointReasons: string[] = [];
  const expectedUrl = facts.expected_url;

  if (facts.app.http_status !== 200 || facts.app.id !== 4793116 || facts.app.slug !== "breakglass-c0r-jit-probe") configurationReasons.push("app identity readback is not exact");
  if (!expectedPermissions(facts.app.permissions) || !facts.app.events.includes("push")) configurationReasons.push("App permissions/events are not exact");
  if (facts.installation.http_status !== 200 || facts.installation.id !== 158227303 || facts.installation.repository_selection !== "selected") configurationReasons.push("installation identity/selection readback is not exact");
  if (!expectedPermissions(facts.installation.permissions)) configurationReasons.push("installation permissions are not exact");
  if (facts.hook.http_status !== 200 || facts.hook.url !== expectedUrl || facts.hook.content_type !== "json" || !(facts.hook.insecure_ssl === "0" || facts.hook.insecure_ssl === 0)) configurationReasons.push("documented hook configuration fields are not exact");

  if (facts.tunnel.ngrok_api_http_status !== 200 || facts.tunnel.public_origin !== new URL(expectedUrl).origin || !localForwardingAddress(facts.tunnel.forwarding_address)) endpointReasons.push("ngrok origin or forwarding address is not exact");
  if (!facts.receiver.listening_locally || facts.tunnel.public_route_probe_http_status !== 404) endpointReasons.push("dedicated receiver is not reachable through the configured public route");

  if (configurationReasons.length > 0) return { valid: false, classification: "WEBHOOK_CONFIGURATION_INVALID", reasons: configurationReasons, secret_persisted: false };
  if (endpointReasons.length > 0) return { valid: false, classification: "WEBHOOK_ENDPOINT_UNREACHABLE", reasons: endpointReasons, secret_persisted: false };
  return { valid: true, classification: "WEBHOOK_CONFIGURED_AND_REACHABLE", reasons: [], secret_persisted: false };
}
