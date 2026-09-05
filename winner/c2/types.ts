export const C2_SOURCE_PROVIDER = "github" as const;
export const C2_SOURCE_EVENT_TYPE = "secret_scanning_alert" as const;
export const C2_SOURCE_ACTION = "created" as const;
export const C2_SIGNAL_SECRET_TYPE = "openssh_private_key" as const;
export const C2_ACTION = "revoke_github_deploy_key" as const;

export type HeaderMap = Record<string, string | undefined>;

export interface RawGithubRequest {
  headers: HeaderMap;
  body: Uint8Array;
}

export interface NormalizedGithubEvent {
  provider: typeof C2_SOURCE_PROVIDER;
  event_type: typeof C2_SOURCE_EVENT_TYPE;
  action: typeof C2_SOURCE_ACTION;
  delivery_id: string;
  repository_id: number;
  repository_full_name: string;
  alert_number: number;
  secret_type: typeof C2_SIGNAL_SECRET_TYPE;
  alert_state: "open";
  source_event_time: string;
  raw_body_sha256: string;
}

export interface TargetReference {
  repository_full_name: "Ticoworld/t3n-breakglass-sandbox";
  deploy_key_id: number;
  expected_title: string;
  expected_read_only: true;
  expected_public_key_fingerprint?: string;
}

export type PolicyProvenanceClassification =
  | "FIXTURE_DECLARATION_NOT_LIVE_PROVENANCE"
  | "LIVE_PROVENANCE";

export interface PolicyProvenance {
  classification: PolicyProvenanceClassification;
  source_commit_sha: string;
  durable_registry_identity: string | null;
  actual_creation_timestamp: string | null;
  creation_evidence: string | null;
  enabled_before_event_proof: boolean;
}

export interface C2Policy {
  policy_id: string;
  source_provider: typeof C2_SOURCE_PROVIDER;
  source_event_type: typeof C2_SOURCE_EVENT_TYPE;
  repository_identity: {
    full_name: "Ticoworld/t3n-breakglass-sandbox";
  };
  signal_match: {
    action: typeof C2_SOURCE_ACTION;
    secret_type: typeof C2_SIGNAL_SECRET_TYPE;
    alert_state: "open";
  };
  action: typeof C2_ACTION;
  target_reference: TargetReference;
  remediation_agent_did: string;
  effect_broker_did: string;
  ttl_secs: number;
  enabled: boolean;
  created_at: string;
  policy_version: number;
  provenance: PolicyProvenance;
}

export interface C1CreateRequest {
  incident_id: string;
  remediation_agent_did: string;
  effect_broker_did: string;
  deploy_key_id: number;
  ttl_secs: number;
}

export type DedupeStatus = "NEW" | "DUPLICATE_SAME" | "CONFLICT";

export interface DedupeRecord {
  dedupe_key: string;
  source_event_id: string;
  event_identity: {
    delivery_id: string;
    event_type: string;
    repository_full_name: string;
  };
  source_event_digest: string;
  normalized_event: NormalizedGithubEvent;
  state: "RESERVED" | "ACCEPTED" | "REJECTED";
  decision?: string;
  reason?: string;
  policy_id?: string;
  policy_version?: number;
  derived_incident_id?: string;
  create_request?: C1CreateRequest;
  updated_at: string;
}

export interface DedupeResult {
  status: DedupeStatus;
  key: string;
  record: DedupeRecord;
}

export interface C2IngressAccepted {
  classification: "C2_SOURCE_SELECTED";
  dedupe: DedupeResult;
  event: NormalizedGithubEvent;
  policy: C2Policy;
  incident_id: string;
  create_request: C1CreateRequest;
}

export interface C2IngressRejected {
  classification:
    | "C2_SOURCE_REJECTED"
    | "C2_NO_MATCHING_POLICY"
    | "C2_POLICY_DISABLED"
    | "C2_POLICY_STALE"
    | "C2_TARGET_NOT_BOUND";
  reason: string;
  dedupe: DedupeResult;
  event: NormalizedGithubEvent;
  policy?: C2Policy;
  incident_id?: string;
}
