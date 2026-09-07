import assert from "node:assert/strict";
import { test } from "node:test";
import { evaluateGithubAppWebhookReadiness, type GithubAppWebhookReadinessFacts } from "../c2/github-app-webhook-readiness.js";

const EXPECTED_URL = "https://dde7-197-210-70-114.ngrok-free.app/c2-b0/github-push";

function facts(overrides: Partial<GithubAppWebhookReadinessFacts> = {}): GithubAppWebhookReadinessFacts {
  return {
    expected_url: EXPECTED_URL,
    app: { http_status: 200, id: 4793116, slug: "breakglass-c0r-jit-probe", permissions: { administration: "write", contents: "read", metadata: "read" }, events: ["push"] },
    installation: { http_status: 200, id: 158227303, repository_selection: "selected", permissions: { administration: "write", contents: "read", metadata: "read" } },
    hook: { http_status: 200, url: EXPECTED_URL, content_type: "json", insecure_ssl: "0", secret: "********" },
    tunnel: { ngrok_api_http_status: 200, public_origin: "https://dde7-197-210-70-114.ngrok-free.app", forwarding_address: "http://localhost:8787", public_route_probe_http_status: 404 },
    receiver: { listening_locally: true },
    ...overrides,
  };
}

test("documented hook shape passes without an active field and never returns the secret", () => {
  const result = evaluateGithubAppWebhookReadiness(facts());
  assert.equal(result.valid, true);
  assert.equal(result.classification, "WEBHOOK_CONFIGURED_AND_REACHABLE");
  assert.equal(result.secret_persisted, false);
  assert.equal(JSON.stringify(result).includes("********"), false);
  assert.equal(JSON.stringify(result).includes("active"), false);
});

test("unsupported active:false extra field is ignored rather than treated as GitHub state", () => {
  const result = evaluateGithubAppWebhookReadiness(facts({ hook: { ...facts().hook, active: false } }));
  assert.equal(result.valid, true);
  assert.equal(result.classification, "WEBHOOK_CONFIGURED_AND_REACHABLE");
});

test("wrong URL, route, content type, or TLS setting fails configuration", () => {
  for (const hook of [
    { ...facts().hook, url: "https://other.example/c2-b0/github-push" },
    { ...facts().hook, url: "https://dde7-197-210-70-114.ngrok-free.app/wrong" },
    { ...facts().hook, content_type: "form" },
    { ...facts().hook, insecure_ssl: "1" },
  ]) {
    const result = evaluateGithubAppWebhookReadiness(facts({ hook }));
    assert.equal(result.valid, false);
    assert.equal(result.classification, "WEBHOOK_CONFIGURATION_INVALID");
  }
});

test("HTTP and identity/permission/event mismatches fail configuration", () => {
  const cases: GithubAppWebhookReadinessFacts[] = [
    facts({ app: { ...facts().app, http_status: 500 } }),
    facts({ app: { ...facts().app, id: 1 } }),
    facts({ app: { ...facts().app, events: [] } }),
    facts({ installation: { ...facts().installation, http_status: 403 } }),
    facts({ installation: { ...facts().installation, id: 1 } }),
    facts({ installation: { ...facts().installation, repository_selection: "all" } }),
    facts({ hook: { ...facts().hook, http_status: 500 } }),
  ];
  for (const input of cases) {
    const result = evaluateGithubAppWebhookReadiness(input);
    assert.equal(result.valid, false);
    assert.equal(result.classification, "WEBHOOK_CONFIGURATION_INVALID");
  }
});

test("ngrok origin, forwarding, and public receiver failures are endpoint failures", () => {
  const cases: GithubAppWebhookReadinessFacts[] = [
    facts({ tunnel: { ...facts().tunnel, ngrok_api_http_status: 503 } }),
    facts({ tunnel: { ...facts().tunnel, public_origin: "https://other.example" } }),
    facts({ tunnel: { ...facts().tunnel, forwarding_address: "http://localhost:9999" } }),
    facts({ tunnel: { ...facts().tunnel, public_route_probe_http_status: 502 } }),
    facts({ receiver: { listening_locally: false } }),
  ];
  for (const input of cases) {
    const result = evaluateGithubAppWebhookReadiness(input);
    assert.equal(result.valid, false);
    assert.equal(result.classification, "WEBHOOK_ENDPOINT_UNREACHABLE");
  }
});
