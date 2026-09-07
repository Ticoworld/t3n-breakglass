/** Structural contract for the one fresh R3 causal vertical. */
export const R3_E2E_SCHEMA = {
  classification: "C2_E2E_R3_FULL_CAUSAL_REMEDIATION_PASS",
  targetTitlePrefix: "breakglass-c2-e2e-r3-",
  policyIdPrefix: "c2-policy:github-push-c2-e2e-r3-",
  repository: "Ticoworld/t3n-breakglass-sandbox",
  repositoryId: 1350596128,
  ref: "refs/heads/c2-breakglass-demo",
  secretPath: ".breakglass-c2/exposed-deploy-key",
  remediationDid: "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019",
  brokerDid: "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57",
  ttlSecs: 900,
} as const;

export type E2ESchema = typeof R3_E2E_SCHEMA;

export function isR3PolicyId(value: unknown): value is string {
  return typeof value === "string" && value.startsWith(R3_E2E_SCHEMA.policyIdPrefix);
}

export function isR3TargetTitle(value: unknown): value is string {
  return typeof value === "string" && value.startsWith(R3_E2E_SCHEMA.targetTitlePrefix);
}
