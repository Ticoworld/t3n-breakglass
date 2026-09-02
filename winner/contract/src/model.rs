use alloc::string::{String, ToString};

use serde::{Deserialize, Serialize};

pub const ACTION_REVOKE_GITHUB_DEPLOY_KEY: &str = "revoke_github_deploy_key";
pub const MAP_TAIL: &str = "winner-incidents";

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IncidentRequest {
    pub incident_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClaimRequest {
    pub incident_id: String,
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
            Status::Active => authority.reservation_id.is_none() && authority.effect_claim_id.is_none(),
            Status::Reserved => authority.reservation_id.is_some() && authority.effect_claim_id.is_none(),
            Status::ReadyRetry => authority.reservation_id.is_some() && authority.effect_claim_id.is_none(),
            Status::EffectClaimed => authority.reservation_id.is_some() && authority.effect_claim_id.is_some(),
            Status::Closed | Status::Expired | Status::ReconcileRequired | Status::Failed => true,
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

pub fn valid_time(authority: &IncidentAuthority, now: u64) -> bool {
    now >= authority.created_at && now < authority.expires_at
}

pub fn reserve(authority: &mut IncidentAuthority, caller: Option<&[u8]>, now: u64) -> Decision {
    if !valid_shape(authority) { return Decision::Denied("invalid authority shape") }
    if !caller_matches(&authority.remediation_agent_did, caller) { return Decision::Denied("caller is not the remediation agent") }
    if !valid_time(authority, now) {
        authority.status = Status::Expired;
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
        Status::EffectClaimed | Status::Closed | Status::ReconcileRequired | Status::Failed | Status::Expired => Decision::Lost,
    }
}

pub fn claim(authority: &mut IncidentAuthority, caller: Option<&[u8]>, now: u64) -> Decision {
    if !valid_shape(authority) { return Decision::Denied("invalid authority shape") }
    if !caller_matches(&authority.effect_broker_did, caller) { return Decision::Denied("caller is not the effect broker") }
    if !valid_time(authority, now) { return Decision::Denied("incident expired according to cluster time") }
    if authority.max_effects != 1 || authority.effect_attempts != 0 { return Decision::Lost }
    match authority.status {
        Status::Reserved | Status::ReadyRetry => {
            authority.effect_claim_version = authority.effect_claim_version.saturating_add(1);
            authority.effect_claim_id = Some(format!("claim-{}-{}", authority.incident_id, authority.effect_claim_version));
            authority.status = Status::EffectClaimed;
            Decision::Won
        }
        Status::EffectClaimed | Status::Closed | Status::ReconcileRequired | Status::Failed | Status::Active | Status::Expired => Decision::Lost,
    }
}

pub fn release_not_attempted(authority: &mut IncidentAuthority, caller: Option<&[u8]>, claim_id: &str) -> Decision {
    if !valid_shape(authority) { return Decision::Denied("invalid authority shape") }
    if !caller_matches(&authority.effect_broker_did, caller) { return Decision::Denied("caller is not the effect broker") }
    if authority.status != Status::EffectClaimed || authority.effect_attempts != 0 || authority.effect_claim_id.as_deref() != Some(claim_id) {
        return Decision::Denied("claim is not releasable")
    }
    authority.effect_claim_id = None;
    authority.status = Status::ReadyRetry;
    Decision::Won
}

pub fn finalize(authority: &mut IncidentAuthority, caller: Option<&[u8]>, claim_id: &str, classification: &str) -> Decision {
    if !valid_shape(authority) { return Decision::Denied("invalid authority shape") }
    if !caller_matches(&authority.effect_broker_did, caller) { return Decision::Denied("caller is not the effect broker") }
    if authority.status != Status::EffectClaimed || authority.effect_claim_id.as_deref() != Some(claim_id) || authority.effect_attempts != 0 {
        return Decision::Denied("claim identity or state does not match")
    }
    match classification {
        "VERIFIED_ABSENT" => {
            authority.effect_attempts = 1;
            authority.final_result_classification = Some(classification.to_string());
            authority.status = Status::Closed;
            Decision::Won
        }
        "PROVIDER_ACKNOWLEDGED" | "ATTEMPTED_OUTCOME_UNKNOWN" | "VERIFIED_PRESENT" => {
            authority.effect_attempts = 1;
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

    #[test] fn wrong_remediation_did_is_denied() { let mut a = authority(); assert_eq!(reserve(&mut a, Some(&BROKER_BYTES), 120), Decision::Denied("caller is not the remediation agent")); }
    #[test] fn reserve_race_second_observes_reserved() { let mut a = authority(); assert_eq!(reserve(&mut a, Some(&AGENT_BYTES), 120), Decision::Won); assert_eq!(reserve(&mut a, Some(&AGENT_BYTES), 120), Decision::Lost); }
    #[test] fn wrong_broker_cannot_claim() { let mut a = authority(); reserve(&mut a, Some(&AGENT_BYTES), 120); assert_eq!(claim(&mut a, Some(&AGENT_BYTES), 120), Decision::Denied("caller is not the effect broker")); }
    #[test] fn claim_is_one_winner() { let mut a = authority(); reserve(&mut a, Some(&AGENT_BYTES), 120); assert_eq!(claim(&mut a, Some(&BROKER_BYTES), 120), Decision::Won); assert_eq!(claim(&mut a, Some(&BROKER_BYTES), 120), Decision::Lost); }
    #[test] fn expiry_denies_and_marks_expired() { let mut a = authority(); assert_eq!(reserve(&mut a, Some(&AGENT_BYTES), 200), Decision::Denied("incident expired according to cluster time")); assert_eq!(a.status, Status::Expired); }
    #[test] fn release_does_not_consume_budget() { let mut a = authority(); reserve(&mut a, Some(&AGENT_BYTES), 120); claim(&mut a, Some(&BROKER_BYTES), 120); let id = a.effect_claim_id.clone().unwrap(); assert_eq!(release_not_attempted(&mut a, Some(&BROKER_BYTES), &id), Decision::Won); assert_eq!(a.status, Status::ReadyRetry); assert_eq!(a.effect_attempts, 0); assert_eq!(claim(&mut a, Some(&BROKER_BYTES), 120), Decision::Won); }
    #[test] fn wrong_claim_and_wrong_did_are_denied() { let mut a = authority(); reserve(&mut a, Some(&AGENT_BYTES), 120); claim(&mut a, Some(&BROKER_BYTES), 120); assert_eq!(finalize(&mut a, Some(&AGENT_BYTES), "bad", "VERIFIED_ABSENT"), Decision::Denied("caller is not the effect broker")); assert_eq!(finalize(&mut a, Some(&BROKER_BYTES), "bad", "VERIFIED_ABSENT"), Decision::Denied("claim identity or state does not match")); }
    #[test] fn only_verified_absence_closes() { let mut a = authority(); reserve(&mut a, Some(&AGENT_BYTES), 120); claim(&mut a, Some(&BROKER_BYTES), 120); let id = a.effect_claim_id.clone().unwrap(); assert_eq!(finalize(&mut a, Some(&BROKER_BYTES), &id, "PROVIDER_ACKNOWLEDGED"), Decision::Won); assert_eq!(a.status, Status::ReconcileRequired); assert_eq!(a.effect_attempts, 1); }
    #[test] fn reconciliation_never_reopens_effect_budget() { let mut a = authority(); reserve(&mut a, Some(&AGENT_BYTES), 120); claim(&mut a, Some(&BROKER_BYTES), 120); let id = a.effect_claim_id.clone().unwrap(); finalize(&mut a, Some(&BROKER_BYTES), &id, "ATTEMPTED_OUTCOME_UNKNOWN"); assert_eq!(reconcile(&mut a, Some(&BROKER_BYTES), &id, "VERIFIED_ABSENT"), Decision::Won); assert_eq!(a.status, Status::Closed); assert_eq!(a.effect_attempts, 1); }
    #[test] fn malformed_or_extra_input_is_rejected_by_serde() { assert!(serde_json::from_str::<IncidentRequest>(r#"{"incident_id":"x","github_repo":"evil"}"#).is_err()); }
}
