const ALLOWED_FIELDS = new Set([
  "delivery_id", "dedupe_state", "policy_id", "policy_version", "incident_id", "c1_state",
  "broker_outcome", "effect_start_confirmed", "provider_classification", "reconciliation_state",
  "terminal_state", "retired", "reason", "replayed", "source_reads",
]);

export function operationalLog(event: string, fields: Record<string, unknown> = {}): void {
  const safe: Record<string, unknown> = { event, at: new Date().toISOString() };
  for (const [key, value] of Object.entries(fields)) if (ALLOWED_FIELDS.has(key)) {
    safe[key] = typeof value === "string"
      ? value.replace(/(Authorization\s*:\s*Bearer\s+|Bearer\s+)[A-Za-z0-9._~+\/-]+/gi, "$1[REDACTED]").replace(/(t3n_key_|github_pat_|ghs_|ghp_)[A-Za-z0-9._~+\/-]+/gi, "$1[REDACTED]").replace(/-----BEGIN[\s\S]*?-----END[^-]+-----/g, "[REDACTED_PRIVATE_MATERIAL]")
      : value;
  }
  process.stdout.write(`${JSON.stringify(safe)}\n`);
}
