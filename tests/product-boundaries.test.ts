import test from "node:test";
import assert from "node:assert/strict";
import {
  assertIncidentIsUnused,
  parseAgentInput,
  sanitizeExecutionResult,
  validateIncidentId,
  validateTtlSeconds,
} from "../scripts/product.js";
import { buildIncidentPreview, renderIncidentPreview } from "../scripts/incident-create.js";
import { breakglassAgentToolDefinition } from "../scripts/agent-tool.js";

test("agent interface accepts only incident_id", () => {
  assert.deepEqual(parseAgentInput({ incident_id: "INC-1043" }), { incident_id: "INC-1043" });
  assert.throws(() => parseAgentInput({ incident_id: "INC-1043", owner: "attacker" }), /only incident_id/);
  assert.throws(() => parseAgentInput({ incident_id: "INC-1043", deploy_key_id: 99 }), /only incident_id/);
});

test("agent surface cannot create authorities", () => {
  const tool = breakglassAgentToolDefinition();
  assert.equal(tool.name, "breakglass_execute_incident");
  assert.equal(tool.inputSchema.additionalProperties, false);
  assert.deepEqual(Object.keys(tool.inputSchema.properties), ["incident_id"]);
  assert.equal((tool.inputSchema.properties as Record<string, unknown>).incident_id !== undefined, true);
});

test("operator preview freezes the exact target and one-use policy", () => {
  const preview = buildIncidentPreview({ incidentId: "INC-1043", owner: "Ticoworld", repository: "t3n-breakglass-sandbox", deployKeyId: 161682082, ttlSeconds: 300 }, "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019", 1_700_000_000, true);
  const rendered = renderIncidentPreview(preview);
  assert.match(rendered, /Target: Ticoworld\/t3n-breakglass-sandbox#161682082/);
  assert.equal(preview.action, "revoke_github_deploy_key");
  assert.equal(preview.max_uses, 1);
  assert.equal(preview.expires_at - preview.created_at, 300);
});

test("invalid TTL and malformed incident IDs are rejected", () => {
  assert.throws(() => validateTtlSeconds("29"), /between 30 and 3600/);
  assert.throws(() => validateTtlSeconds("3601"), /between 30 and 3600/);
  assert.throws(() => validateTtlSeconds("not-a-number"), /positive integer/);
  assert.throws(() => validateIncidentId("INC 1043"), /incident_id/);
  assert.throws(() => validateIncidentId(""), /incident_id/);
});

test("duplicate incident IDs are rejected before authority write", () => {
  assert.doesNotThrow(() => assertIncidentIsUnused(null, "INC-1043"));
  assert.throws(() => assertIncidentIsUnused("{existing authority}", "INC-1043"), /already exists/);
});

test("structured agent output excludes secrets and preserves replay/reconciliation semantics", () => {
  const raw = {
    status: "CONSUMED",
    state: { before: "EXECUTING", after: "CONSUMED" },
    target: { host: "https://api.github.com", owner: "Ticoworld", repository: "t3n-breakglass-sandbox", deploy_key_id: 161682082 },
    verification: { attempted: true, authoritative: true, http_status: 404, absent: true },
    destructive_call: { count: 1, http_status: 204 },
    secret: "sentinel-secret-value",
  };
  const output = sanitizeExecutionResult("INC-1043", raw);
  assert.equal(output.destructive_call_count, 1);
  assert.equal(output.verification.http_status, 404);
  assert.equal(JSON.stringify(output).includes("sentinel-secret-value"), false);

  const replay = sanitizeExecutionResult("INC-1043", { status: "REPLAY_REFUSED", state: { before: "CONSUMED", after: "CONSUMED" }, destructive_call: { count: 0 }, verification: { attempted: false } });
  assert.equal(replay.outcome, "REPLAY_REFUSED");
  assert.equal(replay.destructive_call_count, 0);

  const reconciliation = sanitizeExecutionResult("INC-1043", { status: "RECONCILE_REQUIRED", state: { before: "EXECUTING", after: "RECONCILE_REQUIRED" }, destructive_call: { count: 0 }, verification: { attempted: true, authoritative: true, http_status: 200, absent: false } });
  assert.equal(reconciliation.outcome, "RECONCILE_REQUIRED");
  assert.equal(reconciliation.destructive_call_count, 0);
});
