use alloc::string::{String, ToString};

use serde::{Deserialize, Serialize};

pub const ACTION_REVOKE_GITHUB_DEPLOY_KEY: &str = "revoke_github_deploy_key";
pub const GITHUB_OWNER: &str = "Ticoworld";
pub const GITHUB_REPOSITORY: &str = "t3n-breakglass-sandbox";
pub const MAP_TAIL: &str = "winner-incidents";
pub const MIN_INCIDENT_TTL_SECS: u64 = 60;
pub const MAX_INCIDENT_TTL_SECS: u64 = 900;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IncidentRequest {
    pub incident_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CreateIncidentRequest {
    pub incident_id: String,
    pub remediation_agent_did: String,
    pub effect_broker_did: String,
    pub deploy_key_id: u64,
    pub ttl_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GetIncidentRequest {
    pub incident_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClaimRequest {
    pub incident_id: String,
    pub expected_claim_version: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClaimIdentityRequest {
    pub incident_id: String,
    pub claim_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FinalizeRequest {
    pub incident_id: String,
    pub claim_id: String,
    pub classification: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    Active,
    Reserved,
    EffectClaimed,
    EffectStarted,
    ReadyRetry,
    Closed,
    Expired,
    ReconcileRequired,
    Failed,
}

impl Status {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Reserved => "RESERVED",
            Self::EffectClaimed => "EFFECT_CLAIMED",
            Self::EffectStarted => "EFFECT_STARTED",
            Self::ReadyRetry => "READY_RETRY",
            Self::Closed => "CLOSED",
            Self::Expired => "EXPIRED",
            Self::ReconcileRequired => "RECONCILE_REQUIRED",
            Self::Failed => "FAILED",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IncidentAuthority {
    pub incident_id: String,
    pub remediation_agent_did: String,
    pub effect_broker_did: String,
    pub action: String,
    pub github_owner: String,
    pub github_repo: String,
    pub deploy_key_id: u64,
    pub created_at: u64,
    pub expires_at: u64,
    pub max_effects: u32,
    pub effect_attempts: u32,
    pub status: Status,
    pub reservation_id: Option<String>,
    pub reservation_version: u64,
    pub effect_claim_id: Option<String>,
    pub effect_claim_version: u64,
    pub final_result_classification: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Won,
    Lost,
    Denied(&'static str),
}

pub fn valid_shape(authority: &IncidentAuthority) -> bool {
    authority.incident_id.trim().len() > 0
        && authority.incident_id.len() <= 128
        && valid_did(&authority.remediation_agent_did)
        && valid_did(&authority.effect_broker_did)
        && authority.action == ACTION_REVOKE_GITHUB_DEPLOY_KEY
        && safe_segment(&authority.github_owner)
        && safe_segment(&authority.github_repo)
        && authority.deploy_key_id > 0
        && authority.created_at < authority.expires_at
        && authority.max_effects == 1
        && authority.effect_attempts <= authority.max_effects
        && match authority.status {
            Status::Active => authority.effect_attempts == 0
                && authority.reservation_id.is_none()
                && authority.effect_claim_id.is_none()
                && authority.final_result_classification.is_none(),
            Status::Reserved | Status::ReadyRetry => authority.effect_attempts == 0
                && authority.reservation_id.is_some()
                && authority.effect_claim_id.is_none()
                && authority.final_result_classification.is_none(),
            Status::EffectClaimed => authority.effect_attempts == 0
                && authority.reservation_id.is_some()
                && authority.effect_claim_id.is_some()
                && authority.final_result_classification.is_none(),
            Status::EffectStarted => authority.effect_attempts == 1
                && authority.reservation_id.is_some()
                && authority.effect_claim_id.is_some()
                && authority.final_result_classification.is_none(),
            Status::Expired => authority.effect_attempts == 0
                && authority.effect_claim_id.is_none()
                && authority.final_result_classification.is_none(),
            Status::Closed => authority.effect_attempts == 1
                && authority.reservation_id.is_some()
                && authority.effect_claim_id.is_some()
                && authority.final_result_classification.as_deref() == Some("VERIFIED_ABSENT"),
            Status::ReconcileRequired => authority.effect_attempts == 1
                && authority.reservation_id.is_some()
                && authority.effect_claim_id.is_some()
                && matches!(authority.final_result_classification.as_deref(), Some("PROVIDER_ACKNOWLEDGED" | "ATTEMPTED_OUTCOME_UNKNOWN" | "VERIFIED_PRESENT")),
            Status::Failed => authority.effect_attempts == 1
                && authority.reservation_id.is_some()
                && authority.effect_claim_id.is_some()
                && authority.final_result_classification.as_deref() == Some("VERIFIED_PRESENT"),
        }
}

pub fn valid_did(value: &str) -> bool {
    value.len() == 48
        && value.starts_with("did:t3n:")
        && value[8..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn caller_matches(expected: &str, caller: Option<&[u8]>) -> bool {
    let Some(caller) = caller else { return false };
    caller.len() == 20
        && valid_did(expected)
        && hex::encode(caller).eq_ignore_ascii_case(&expected[8..])
}

pub fn operator_matches_tenant(calling_user_did: Option<&[u8]>, tenant_did: &[u8]) -> bool {
    matches!(calling_user_did, Some(caller) if caller.len() == 20 && tenant_did.len() == 20 && caller == tenant_did)
}

pub fn valid_incident_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'-' | b'_'))
}

pub fn build_incident_authority(
    request: &CreateIncidentRequest,
    calling_user_did: Option<&[u8]>,
    tenant_did: &[u8],
    now: u64,
) -> Result<IncidentAuthority, &'static str> {
    if !operator_matches_tenant(calling_user_did, tenant_did) {
        return Err("caller is not the current tenant operator")
    }
    if !valid_incident_id(&request.incident_id) {
        return Err("incident_id is invalid")
    }
    if !valid_did(&request.remediation_agent_did) || !valid_did(&request.effect_broker_did) {
        return Err("agent DIDs are invalid")
    }
    if request.remediation_agent_did == request.effect_broker_did {
        return Err("remediation and broker DIDs must differ")
    }
    if caller_matches(&request.remediation_agent_did, Some(tenant_did)) || caller_matches(&request.effect_broker_did, Some(tenant_did)) {
        return Err("operator cannot be an effect principal")
    }
    if request.deploy_key_id == 0 {
        return Err("deploy_key_id must be positive")
    }
    if request.ttl_secs < MIN_INCIDENT_TTL_SECS || request.ttl_secs > MAX_INCIDENT_TTL_SECS {
        return Err("ttl_secs is outside the bounded C1 window")
    }
    let expires_at = now.checked_add(request.ttl_secs).ok_or("ttl_secs overflows cluster time")?;
    let authority = IncidentAuthority {
        incident_id: request.incident_id.clone(),
        remediation_agent_did: request.remediation_agent_did.clone(),
        effect_broker_did: request.effect_broker_did.clone(),
        action: ACTION_REVOKE_GITHUB_DEPLOY_KEY.into(),
        github_owner: GITHUB_OWNER.into(),
        github_repo: GITHUB_REPOSITORY.into(),
        deploy_key_id: request.deploy_key_id,
        created_at: now,
        expires_at,
        max_effects: 1,
        effect_attempts: 0,
        status: Status::Active,
        reservation_id: None,
        reservation_version: 0,
        effect_claim_id: None,
        effect_claim_version: 0,
        final_result_classification: None,
    };
    if !valid_shape(&authority) {
        return Err("constructed incident authority is invalid")
    }
    Ok(authority)
}

pub fn valid_time(authority: &IncidentAuthority, now: u64) -> bool {
    now >= authority.created_at && now < authority.expires_at
}

pub fn reserve(authority: &mut IncidentAuthority, caller: Option<&[u8]>, now: u64) -> Decision {
    if !valid_shape(authority) { return Decision::Denied("invalid authority shape") }
    if !caller_matches(&authority.remediation_agent_did, caller) { return Decision::Denied("caller is not the remediation agent") }
    if !valid_time(authority, now) {
        if matches!(authority.status, Status::Active | Status::Reserved | Status::ReadyRetry) {
            authority.status = Status::Expired;
        }
        return Decision::Denied("incident expired according to cluster time")
    }
    if authority.max_effects != 1 || authority.effect_attempts != 0 { return Decision::Denied("effect budget is not exactly one") }
    match authority.status {
        Status::Active => {
            authority.reservation_version = authority.reservation_version.saturating_add(1);
            authority.reservation_id = Some(format!("reservation-{}-{}", authority.incident_id, authority.reservation_version));
            authority.status = Status::Reserved;
            Decision::Won
        }
        Status::Reserved | Status::ReadyRetry => Decision::Lost,
        Status::EffectClaimed | Status::EffectStarted | Status::Closed | Status::ReconcileRequired | Status::Failed | Status::Expired => Decision::Lost,
    }
}

pub fn claim(authority: &mut IncidentAuthority, caller: Option<&[u8]>, now: u64, expected_claim_version: u64) -> Decision {
    if !valid_shape(authority) { return Decision::Denied("invalid authority shape") }
    if !caller_matches(&authority.effect_broker_did, caller) { return Decision::Denied("caller is not the effect broker") }
    if !valid_time(authority, now) {
        if matches!(authority.status, Status::Active | Status::Reserved | Status::ReadyRetry) {
            authority.status = Status::Expired;
        }
        return Decision::Denied("incident expired according to cluster time")
    }
    if authority.max_effects != 1 || authority.effect_attempts != 0 { return Decision::Lost }
    if authority.effect_claim_version != expected_claim_version { return Decision::Lost }
    match authority.status {
        Status::Reserved | Status::ReadyRetry => {
            let Some(next_version) = authority.effect_claim_version.checked_add(1) else { return Decision::Denied("claim generation exhausted") };
            authority.effect_claim_version = next_version;
            authority.effect_claim_id = Some(format!("claim-{}-{}", authority.incident_id, authority.effect_claim_version));
            authority.status = Status::EffectClaimed;
            Decision::Won
        }
        Status::EffectClaimed | Status::EffectStarted | Status::Closed | Status::ReconcileRequired | Status::Failed | Status::Active | Status::Expired => Decision::Lost,
    }
}

pub fn release_not_attempted(authority: &mut IncidentAuthority, caller: Option<&[u8]>, claim_id: &str, now: u64) -> Decision {
    if !valid_shape(authority) { return Decision::Denied("invalid authority shape") }
    if !caller_matches(&authority.effect_broker_did, caller) { return Decision::Denied("caller is not the effect broker") }
    if authority.status != Status::EffectClaimed || authority.effect_attempts != 0 || authority.effect_claim_id.as_deref() != Some(claim_id) {
        return Decision::Denied("claim is not releasable")
    }
    if !valid_time(authority, now) { return Decision::Denied("incident expired according to cluster time") }
    authority.effect_claim_id = None;
    authority.status = Status::ReadyRetry;
    Decision::Won
}

pub fn begin_effect(authority: &mut IncidentAuthority, caller: Option<&[u8]>, claim_id: &str, now: u64) -> Decision {
    if !valid_shape(authority) { return Decision::Denied("invalid authority shape") }
    if !caller_matches(&authority.effect_broker_did, caller) { return Decision::Denied("caller is not the effect broker") }
    if authority.status != Status::EffectClaimed || authority.effect_attempts != 0 || authority.effect_claim_id.as_deref() != Some(claim_id) {
        return Decision::Denied("claim identity or state does not match")
    }
    if !valid_time(authority, now) { return Decision::Denied("incident expired according to cluster time") }
    authority.effect_attempts = 1;
    authority.status = Status::EffectStarted;
    Decision::Won
}

pub fn finalize(authority: &mut IncidentAuthority, caller: Option<&[u8]>, claim_id: &str, classification: &str) -> Decision {
    if !valid_shape(authority) { return Decision::Denied("invalid authority shape") }
    if !caller_matches(&authority.effect_broker_did, caller) { return Decision::Denied("caller is not the effect broker") }
    if authority.status != Status::EffectStarted || authority.effect_claim_id.as_deref() != Some(claim_id) || authority.effect_attempts != 1 {
        return Decision::Denied("claim identity or state does not match")
    }
    match classification {
        "VERIFIED_ABSENT" => {
            authority.final_result_classification = Some(classification.to_string());
            authority.status = Status::Closed;
            Decision::Won
        }
        "PROVIDER_ACKNOWLEDGED" | "ATTEMPTED_OUTCOME_UNKNOWN" | "VERIFIED_PRESENT" => {
            authority.final_result_classification = Some(classification.to_string());
            authority.status = if classification == "VERIFIED_PRESENT" { Status::Failed } else { Status::ReconcileRequired };
            Decision::Won
        }
        _ => Decision::Denied("classification cannot finalize this effect"),
    }
}

pub fn reconcile(authority: &mut IncidentAuthority, caller: Option<&[u8]>, claim_id: &str, classification: &str) -> Decision {
    if !valid_shape(authority) { return Decision::Denied("invalid authority shape") }
    if !caller_matches(&authority.effect_broker_did, caller) { return Decision::Denied("caller is not the effect broker") }
    if !matches!(authority.status, Status::EffectStarted | Status::ReconcileRequired | Status::Failed) {
        return Decision::Denied("authority is not awaiting reconciliation")
    }
    if authority.effect_claim_id.as_deref() != Some(claim_id) || authority.effect_attempts != 1 {
        return Decision::Denied("reconciliation identity or state does not match")
    }
    match classification {
        "VERIFIED_ABSENT" => {
            authority.final_result_classification = Some(classification.to_string());
            authority.status = Status::Closed;
            Decision::Won
        }
        "VERIFIED_PRESENT" | "ATTEMPTED_OUTCOME_UNKNOWN" => {
            authority.final_result_classification = Some(classification.to_string());
            authority.status = Status::ReconcileRequired;
            Decision::Won
        }
        _ => Decision::Denied("classification cannot reconcile this effect"),
    }
}

fn safe_segment(value: &str) -> bool {
    !value.is_empty() && value.len() <= 100 && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-' || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    const AGENT: &str = "did:t3n:00112233445566778899aabbccddeeff00112233";
    const BROKER: &str = "did:t3n:ffeeddccbbaa99887766554433221100ffeeddcc";
    const OPERATOR_BYTES: [u8; 20] = [0xaa; 20];
    const AGENT_BYTES: [u8; 20] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33];
    const BROKER_BYTES: [u8; 20] = [0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc];

    fn authority() -> IncidentAuthority {
        IncidentAuthority {
            incident_id: "INC-TEST".into(), remediation_agent_did: AGENT.into(), effect_broker_did: BROKER.into(),
            action: ACTION_REVOKE_GITHUB_DEPLOY_KEY.into(), github_owner: "Ticoworld".into(), github_repo: "sandbox".into(), deploy_key_id: 7,
            created_at: 100, expires_at: 200, max_effects: 1, effect_attempts: 0, status: Status::Active,
            reservation_id: None, reservation_version: 0, effect_claim_id: None, effect_claim_version: 0, final_result_classification: None,
        }
    }

    fn create_request() -> CreateIncidentRequest {
        CreateIncidentRequest {
            incident_id: "INC-CREATE-1".into(),
            remediation_agent_did: AGENT.into(),
            effect_broker_did: BROKER.into(),
            deploy_key_id: 7,
            ttl_secs: 900,
        }
    }

    #[test]
    fn create_builds_contract_owned_authority_from_cluster_time() {
        let request = create_request();
        let authority = build_incident_authority(&request, Some(&OPERATOR_BYTES), &OPERATOR_BYTES, 1_000).unwrap();
        assert_eq!(authority.created_at, 1_000);
        assert_eq!(authority.expires_at, 1_900);
        assert_eq!(authority.action, ACTION_REVOKE_GITHUB_DEPLOY_KEY);
        assert_eq!(authority.github_owner, GITHUB_OWNER);
        assert_eq!(authority.github_repo, GITHUB_REPOSITORY);
        assert_eq!(authority.max_effects, 1);
        assert_eq!(authority.effect_attempts, 0);
        assert_eq!(authority.status, Status::Active);
        assert!(valid_shape(&authority));
    }

    #[test]
    fn create_requires_exact_runtime_operator_identity() {
        let request = create_request();
        assert_eq!(build_incident_authority(&request, None, &OPERATOR_BYTES, 1_000), Err("caller is not the current tenant operator"));
        assert_eq!(build_incident_authority(&request, Some(&AGENT_BYTES), &OPERATOR_BYTES, 1_000), Err("caller is not the current tenant operator"));
        assert!(operator_matches_tenant(Some(&OPERATOR_BYTES), &OPERATOR_BYTES));
        assert!(!operator_matches_tenant(None, &OPERATOR_BYTES));
        assert!(!operator_matches_tenant(Some(&[0xaau8; 19]), &OPERATOR_BYTES));
    }

    #[test]
    fn create_rejects_unbounded_or_overflowing_ttl() {
        let mut request = create_request();
        request.ttl_secs = 0;
        assert_eq!(build_incident_authority(&request, Some(&OPERATOR_BYTES), &OPERATOR_BYTES, 1_000), Err("ttl_secs is outside the bounded C1 window"));
        request.ttl_secs = MIN_INCIDENT_TTL_SECS - 1;
        assert_eq!(build_incident_authority(&request, Some(&OPERATOR_BYTES), &OPERATOR_BYTES, 1_000), Err("ttl_secs is outside the bounded C1 window"));
        request.ttl_secs = MAX_INCIDENT_TTL_SECS + 1;
        assert_eq!(build_incident_authority(&request, Some(&OPERATOR_BYTES), &OPERATOR_BYTES, 1_000), Err("ttl_secs is outside the bounded C1 window"));
        request.ttl_secs = MIN_INCIDENT_TTL_SECS;
        assert_eq!(build_incident_authority(&request, Some(&OPERATOR_BYTES), &OPERATOR_BYTES, u64::MAX), Err("ttl_secs overflows cluster time"));
    }

    #[test]
    fn create_rejects_duplicate_effect_principals_and_operator_reuse() {
        let mut request = create_request();
        request.effect_broker_did = request.remediation_agent_did.clone();
        assert_eq!(build_incident_authority(&request, Some(&OPERATOR_BYTES), &OPERATOR_BYTES, 1_000), Err("remediation and broker DIDs must differ"));
        request.effect_broker_did = "did:t3n:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
        assert_eq!(build_incident_authority(&request, Some(&OPERATOR_BYTES), &OPERATOR_BYTES, 1_000), Err("operator cannot be an effect principal"));
    }

    #[test]
    fn create_and_get_requests_reject_unknown_fields() {
        assert!(serde_json::from_str::<CreateIncidentRequest>(r#"{"incident_id":"x","remediation_agent_did":"did:t3n:00112233445566778899aabbccddeeff00112233","effect_broker_did":"did:t3n:ffeeddccbbaa99887766554433221100ffeeddcc","deploy_key_id":7,"ttl_secs":900,"github_repo":"evil"}"#).is_err());
        assert!(serde_json::from_str::<GetIncidentRequest>(r#"{"incident_id":"x","deploy_key_id":7}"#).is_err());
        assert!(!valid_incident_id("INC with spaces"));
        assert!(!valid_incident_id(""));
        assert!(valid_incident_id("INC-CREATE-1"));
    }

    #[test] fn wrong_remediation_did_is_denied() { let mut a = authority(); assert_eq!(reserve(&mut a, Some(&BROKER_BYTES), 120), Decision::Denied("caller is not the remediation agent")); }
    #[test] fn reserve_race_second_observes_reserved() { let mut a = authority(); assert_eq!(reserve(&mut a, Some(&AGENT_BYTES), 120), Decision::Won); assert_eq!(reserve(&mut a, Some(&AGENT_BYTES), 120), Decision::Lost); }
    #[test] fn wrong_broker_cannot_claim() { let mut a = authority(); reserve(&mut a, Some(&AGENT_BYTES), 120); assert_eq!(claim(&mut a, Some(&AGENT_BYTES), 120, 0), Decision::Denied("caller is not the effect broker")); }
    #[test] fn claim_is_one_winner() { let mut a = authority(); reserve(&mut a, Some(&AGENT_BYTES), 120); assert_eq!(claim(&mut a, Some(&BROKER_BYTES), 120, 0), Decision::Won); assert_eq!(claim(&mut a, Some(&BROKER_BYTES), 120, 0), Decision::Lost); }
    #[test] fn begin_effect_consumes_budget_before_provider_phase() { let mut a = authority(); reserve(&mut a, Some(&AGENT_BYTES), 120); assert_eq!(claim(&mut a, Some(&BROKER_BYTES), 120, 0), Decision::Won); let id = a.effect_claim_id.clone().unwrap(); assert_eq!(begin_effect(&mut a, Some(&BROKER_BYTES), &id, 120), Decision::Won); assert_eq!(a.status, Status::EffectStarted); assert_eq!(a.effect_attempts, 1); assert_eq!(release_not_attempted(&mut a, Some(&BROKER_BYTES), &id, 120), Decision::Denied("claim is not releasable")); assert_eq!(begin_effect(&mut a, Some(&BROKER_BYTES), &id, 120), Decision::Denied("claim identity or state does not match")); }
    #[test] fn normal_effect_path_closes_without_finalize_budget_increment() { let mut a = authority(); assert_eq!(reserve(&mut a, Some(&AGENT_BYTES), 120), Decision::Won); assert_eq!(claim(&mut a, Some(&BROKER_BYTES), 120, 0), Decision::Won); let id = a.effect_claim_id.clone().unwrap(); assert_eq!(begin_effect(&mut a, Some(&BROKER_BYTES), &id, 120), Decision::Won); assert_eq!(finalize(&mut a, Some(&BROKER_BYTES), &id, "VERIFIED_ABSENT"), Decision::Won); assert_eq!(a.status, Status::Closed); assert_eq!(a.effect_attempts, 1); assert!(valid_shape(&a)); }
    #[test] fn effect_started_recovery_never_restores_budget() { let mut a = authority(); reserve(&mut a, Some(&AGENT_BYTES), 120); claim(&mut a, Some(&BROKER_BYTES), 120, 0); let id = a.effect_claim_id.clone().unwrap(); begin_effect(&mut a, Some(&BROKER_BYTES), &id, 120); assert_eq!(reconcile(&mut a, Some(&BROKER_BYTES), &id, "VERIFIED_ABSENT"), Decision::Won); assert_eq!(a.status, Status::Closed); assert_eq!(a.effect_attempts, 1); assert_eq!(claim(&mut a, Some(&BROKER_BYTES), 120, 1), Decision::Lost); }
    #[test] fn effect_started_present_stays_in_reconciliation_without_budget_reset() { let mut a = authority(); reserve(&mut a, Some(&AGENT_BYTES), 120); claim(&mut a, Some(&BROKER_BYTES), 120, 0); let id = a.effect_claim_id.clone().unwrap(); begin_effect(&mut a, Some(&BROKER_BYTES), &id, 120); assert_eq!(reconcile(&mut a, Some(&BROKER_BYTES), &id, "VERIFIED_PRESENT"), Decision::Won); assert_eq!(a.status, Status::ReconcileRequired); assert_eq!(a.effect_attempts, 1); assert_ne!(claim(&mut a, Some(&BROKER_BYTES), 120, 1), Decision::Won); }
    #[test] fn stale_claim_generation_loses_after_not_attempted_release() { let mut a = authority(); reserve(&mut a, Some(&AGENT_BYTES), 120); assert_eq!(claim(&mut a, Some(&BROKER_BYTES), 120, 0), Decision::Won); let id = a.effect_claim_id.clone().unwrap(); assert_eq!(release_not_attempted(&mut a, Some(&BROKER_BYTES), &id, 120), Decision::Won); assert_eq!(a.effect_claim_version, 1); assert_eq!(claim(&mut a, Some(&BROKER_BYTES), 120, 0), Decision::Lost); assert_eq!(claim(&mut a, Some(&BROKER_BYTES), 120, 1), Decision::Won); }
    #[test] fn expiry_denies_and_marks_expired() { let mut a = authority(); assert_eq!(reserve(&mut a, Some(&AGENT_BYTES), 200), Decision::Denied("incident expired according to cluster time")); assert_eq!(a.status, Status::Expired); }
    #[test] fn release_does_not_consume_budget() { let mut a = authority(); reserve(&mut a, Some(&AGENT_BYTES), 120); claim(&mut a, Some(&BROKER_BYTES), 120, 0); let id = a.effect_claim_id.clone().unwrap(); assert_eq!(release_not_attempted(&mut a, Some(&BROKER_BYTES), &id, 120), Decision::Won); assert_eq!(a.status, Status::ReadyRetry); assert_eq!(a.effect_attempts, 0); assert_eq!(claim(&mut a, Some(&BROKER_BYTES), 120, 0), Decision::Lost); assert_eq!(claim(&mut a, Some(&BROKER_BYTES), 120, 1), Decision::Won); }
    #[test] fn wrong_claim_and_wrong_did_are_denied() { let mut a = authority(); reserve(&mut a, Some(&AGENT_BYTES), 120); claim(&mut a, Some(&BROKER_BYTES), 120, 0); let id = a.effect_claim_id.clone().unwrap(); assert_eq!(finalize(&mut a, Some(&AGENT_BYTES), "bad", "VERIFIED_ABSENT"), Decision::Denied("caller is not the effect broker")); assert_eq!(finalize(&mut a, Some(&BROKER_BYTES), &id, "VERIFIED_ABSENT"), Decision::Denied("claim identity or state does not match")); }
    #[test] fn only_verified_absence_closes() { let mut a = authority(); reserve(&mut a, Some(&AGENT_BYTES), 120); claim(&mut a, Some(&BROKER_BYTES), 120, 0); let id = a.effect_claim_id.clone().unwrap(); assert_eq!(begin_effect(&mut a, Some(&BROKER_BYTES), &id, 120), Decision::Won); assert_eq!(finalize(&mut a, Some(&BROKER_BYTES), &id, "PROVIDER_ACKNOWLEDGED"), Decision::Won); assert_eq!(a.status, Status::ReconcileRequired); assert_eq!(a.effect_attempts, 1); }
    #[test] fn reconciliation_never_reopens_effect_budget() { let mut a = authority(); reserve(&mut a, Some(&AGENT_BYTES), 120); claim(&mut a, Some(&BROKER_BYTES), 120, 0); let id = a.effect_claim_id.clone().unwrap(); begin_effect(&mut a, Some(&BROKER_BYTES), &id, 120); assert_eq!(reconcile(&mut a, Some(&BROKER_BYTES), &id, "VERIFIED_ABSENT"), Decision::Won); assert_eq!(a.status, Status::Closed); assert_eq!(a.effect_attempts, 1); assert_eq!(reconcile(&mut a, Some(&BROKER_BYTES), &id, "VERIFIED_ABSENT"), Decision::Denied("authority is not awaiting reconciliation")); }
    #[test] fn release_after_expiry_does_not_reopen_retry() { let mut a = authority(); reserve(&mut a, Some(&AGENT_BYTES), 120); claim(&mut a, Some(&BROKER_BYTES), 120, 0); let id = a.effect_claim_id.clone().unwrap(); assert_eq!(release_not_attempted(&mut a, Some(&BROKER_BYTES), &id, 200), Decision::Denied("incident expired according to cluster time")); assert_eq!(a.status, Status::EffectClaimed); }
    #[test] fn malformed_terminal_state_is_rejected() { let mut a = authority(); a.status = Status::Closed; a.effect_attempts = 0; assert!(!valid_shape(&a)); }
    #[test] fn expired_claim_marks_unclaimed_state_expired() { let mut a = authority(); reserve(&mut a, Some(&AGENT_BYTES), 120); assert_eq!(claim(&mut a, Some(&BROKER_BYTES), 200, 0), Decision::Denied("incident expired according to cluster time")); assert_eq!(a.status, Status::Expired); }
    #[test] fn reserve_after_effect_claim_expiry_does_not_corrupt_claim() { let mut a = authority(); reserve(&mut a, Some(&AGENT_BYTES), 120); claim(&mut a, Some(&BROKER_BYTES), 120, 0); let claim_id = a.effect_claim_id.clone(); assert_eq!(reserve(&mut a, Some(&AGENT_BYTES), 200), Decision::Denied("incident expired according to cluster time")); assert_eq!(a.status, Status::EffectClaimed); assert_eq!(a.effect_claim_id, claim_id); }
    #[test] fn malformed_or_extra_input_is_rejected_by_serde() { assert!(serde_json::from_str::<IncidentRequest>(r#"{"incident_id":"x","github_repo":"evil"}"#).is_err()); }

    #[test]
    fn generated_operation_sequences_preserve_single_effect_invariant() {
        fn next(seed: &mut u64) -> u64 {
            *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *seed
        }

        for sequence in 0..4000 {
            let mut seed = sequence as u64 + 1;
            let mut a = authority();
            let mut claim_wins = 0u32;
            let mut release_wins = 0u32;
            for _step in 0..80 {
                let operation = next(&mut seed) % 8;
                let caller_bytes = match next(&mut seed) % 5 {
                    0 => Some(&AGENT_BYTES[..]),
                    1 => Some(&BROKER_BYTES[..]),
                    _ => Some(&[0xabu8; 20][..]),
                };
                let now = if next(&mut seed) % 9 == 0 { 200 } else { 120 };
                let decision = match operation {
                    0 => reserve(&mut a, caller_bytes, now),
                    1 => {
                        let decision = claim(&mut a, caller_bytes, now, 0);
                        if decision == Decision::Won { claim_wins += 1; }
                        decision
                    }
                    2 => {
                        let id = a.effect_claim_id.clone().unwrap_or_else(|| "wrong-claim".into());
                        let decision = release_not_attempted(&mut a, caller_bytes, &id, now);
                        if decision == Decision::Won { release_wins += 1; }
                        decision
                    }
                    3 => {
                        let id = a.effect_claim_id.clone().unwrap_or_else(|| "wrong-claim".into());
                        finalize(&mut a, caller_bytes, &id, if next(&mut seed) % 2 == 0 { "VERIFIED_ABSENT" } else { "ATTEMPTED_OUTCOME_UNKNOWN" })
                    }
                    4 => {
                        let id = a.effect_claim_id.clone().unwrap_or_else(|| "wrong-claim".into());
                        reconcile(&mut a, caller_bytes, &id, if next(&mut seed) % 2 == 0 { "VERIFIED_ABSENT" } else { "VERIFIED_PRESENT" })
                    }
                    6 => {
                        let id = a.effect_claim_id.clone().unwrap_or_else(|| "wrong-claim".into());
                        begin_effect(&mut a, caller_bytes, &id, now)
                    }
                    _ => claim(&mut a, caller_bytes, now, 0),
                };
                let _ = decision;
                assert!(valid_shape(&a), "sequence {sequence} produced invalid reachable shape: {a:?}");
                assert!(a.effect_attempts <= 1);
                assert!(claim_wins <= release_wins + 1, "sequence {sequence} authorized a second claim without release");
                if a.effect_attempts == 1 {
                    assert_ne!(claim(&mut a, Some(&BROKER_BYTES), 120, 0), Decision::Won);
                    assert!(valid_shape(&a));
                }
            }
        }
    }
}
