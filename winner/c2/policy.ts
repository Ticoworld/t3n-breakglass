import type { C2Policy, NormalizedGithubEvent } from "./types.js";
import { checkLivePolicyProvenance } from "./policy-provenance.js";
import {
  C2_ACTION,
  C2_SIGNAL_SECRET_TYPE,
  C2_SOURCE_ACTION,
  C2_SOURCE_EVENT_TYPE,
} from "./types.js";

export const C2_POLICY = {
  policy_id: "github-openssh-private-key-revoke-v1",
  source_provider: "github",
  source_event_type: C2_SOURCE_EVENT_TYPE,
  repository_identity: {
    full_name: "Ticoworld/t3n-breakglass-sandbox",
  },
  signal_match: {
    action: C2_SOURCE_ACTION,
    secret_type: C2_SIGNAL_SECRET_TYPE,
    alert_state: "open",
  },
  action: C2_ACTION,
  target_reference: {
    repository_full_name: "Ticoworld/t3n-breakglass-sandbox",
    deploy_key_id: 162351194,
    expected_title: "breakglass-r4e-disposable-20260904",
    expected_read_only: true,
  },
  remediation_agent_did: "did:t3n:c2cb33e0cb6838dafef6519e5d44a20b56069019",
  effect_broker_did: "did:t3n:71612737505d7fbbd39e03b4d7a89e31d6346a57",
  ttl_secs: 900,
  enabled: true,
  // Deliberately fixed before this C2-A local fixture/event date.
  created_at: "2026-09-01T00:00:00.000Z",
  policy_version: 1,
  provenance: {
    classification: "FIXTURE_DECLARATION_NOT_LIVE_PROVENANCE",
    source_commit_sha: "590abfdcd8efafb0e840be1e5bd37baf70ca9d36",
    durable_registry_identity: null,
    actual_creation_timestamp: null,
    creation_evidence: null,
    enabled_before_event_proof: false,
  },
} satisfies C2Policy;

export type PolicyLookupResult =
  | { kind: "MATCH"; policy: C2Policy }
  | { kind: "NO_MATCH"; reason: string }
  | { kind: "DISABLED"; policy: C2Policy }
  | { kind: "STALE"; policy: C2Policy; reason: string };

export function lookupPreExistingPolicy(
  event: NormalizedGithubEvent,
  policies: readonly C2Policy[] = [C2_POLICY],
): PolicyLookupResult {
  const policy = policies.find((candidate) =>
    candidate.source_provider === event.provider &&
    candidate.source_event_type === event.event_type &&
    candidate.repository_identity.full_name === event.repository_full_name &&
    candidate.signal_match.action === event.action &&
    candidate.signal_match.secret_type === event.secret_type &&
    candidate.signal_match.alert_state === event.alert_state,
  );
  if (!policy) return { kind: "NO_MATCH", reason: "no pre-existing policy matches the authenticated normalized facts" };
  if (!policy.enabled) return { kind: "DISABLED", policy };
  if (Date.parse(event.source_event_time) <= Date.parse(policy.created_at)) {
    return { kind: "STALE", policy, reason: "source event time is not after policy creation time" };
  }
  return { kind: "MATCH", policy };
}

/** Future live ingestion must use this boundary, never the fixture-only lookup. */
export function lookupPreExistingLivePolicy(
  event: NormalizedGithubEvent,
  policies: readonly C2Policy[] = [C2_POLICY],
): PolicyLookupResult {
  const result = lookupPreExistingPolicy(event, policies);
  if (result.kind !== "MATCH") return result;
  const provenance = checkLivePolicyProvenance(result.policy);
  if (!provenance.live) {
    return { kind: "NO_MATCH", reason: `policy lacks independent live provenance: ${provenance.reasons.join(", ")}` };
  }
  return result;
}
