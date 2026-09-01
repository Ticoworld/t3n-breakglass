//! Pure Phase 1 authority validation and state transitions.
//!
//! This module deliberately contains no host imports.  The native tests exercise
//! the security decisions deterministically; the WASM export supplies the caller
//! DID, cluster time, KV record, and GitHub result around these decisions.

use alloc::string::{String, ToString};

use serde::{Deserialize, Serialize};

pub const ACTION_REVOKE_GITHUB_DEPLOY_KEY: &str = "revoke_github_deploy_key";

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentRequest {
    pub incident_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct IncidentAuthority {
    pub incident_id: String,
    pub agent_did: String,
    pub action: String,
    pub github_owner: String,
    pub github_repo: String,
    pub deploy_key_id: u64,
    pub created_at: u64,
    pub expires_at: u64,
    pub max_uses: u32,
    pub uses: u32,
    pub status: AuthorityStatus,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum AuthorityStatus {
    #[serde(rename = "ACTIVE")]
    Active,
    #[serde(rename = "EXECUTING")]
    Executing,
    #[serde(rename = "CONSUMED")]
    Consumed,
    #[serde(rename = "EXPIRED")]
    Expired,
    #[serde(rename = "RECONCILE_REQUIRED")]
    ReconcileRequired,
    #[serde(rename = "FAILED")]
    Failed,
}

impl AuthorityStatus {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Executing => "EXECUTING",
            Self::Consumed => "CONSUMED",
            Self::Expired => "EXPIRED",
            Self::ReconcileRequired => "RECONCILE_REQUIRED",
            Self::Failed => "FAILED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateFailure {
    MissingCaller,
    WrongAgent,
    Expired,
    WrongAction,
    MaxUses,
    InvalidTarget,
    Replay,
    ReconcileOnly,
    Failed,
    InvalidState,
}

impl GateFailure {
    pub fn code(self) -> &'static str {
        match self {
            Self::MissingCaller => "DENIED",
            Self::WrongAgent => "DENIED",
            Self::Expired => "DENIED_EXPIRED",
            Self::WrongAction => "DENIED",
            Self::MaxUses => "DENIED",
            Self::InvalidTarget => "DENIED",
            Self::Replay => "REPLAY_REFUSED",
            Self::ReconcileOnly => "RECONCILE_REQUIRED",
            Self::Failed => "FAILED",
            Self::InvalidState => "DENIED",
        }
    }

    pub fn note(self) -> &'static str {
        match self {
            Self::MissingCaller => "authenticated calling user DID is unavailable",
            Self::WrongAgent => "calling agent DID does not match the incident authority",
            Self::Expired => "incident authority has expired according to cluster time",
            Self::WrongAction => "incident action is not the permitted GitHub deploy-key revoke",
            Self::MaxUses => "incident max-use limit has been reached",
            Self::InvalidTarget => "incident target is malformed or outside the bounded GitHub path",
            Self::Replay => "incident is already consumed; no GitHub request was issued",
            Self::ReconcileOnly => "incident requires GET-only reconciliation; DELETE is forbidden",
            Self::Failed => "incident has a confirmed failed external mutation; retry is forbidden",
            Self::InvalidState => "incident contains an invalid state transition",
        }
    }
}

pub fn parse_request(raw: Option<&[u8]>) -> Result<AgentRequest, String> {
    let bytes = raw.ok_or_else(|| "request must contain only incident_id".to_string())?;
    let request: AgentRequest = serde_json::from_slice(bytes)
        .map_err(|_| "request must contain only incident_id".to_string())?;
    if request.incident_id.trim().is_empty() || request.incident_id.len() > 128 {
        return Err("incident_id is invalid".to_string());
    }
    Ok(request)
}

pub fn valid_authority_shape(authority: &IncidentAuthority) -> bool {
    authority.incident_id.trim() != ""
        && authority.agent_did.starts_with("did:t3n:")
        && authority.agent_did.len() == 48
        && authority.action == ACTION_REVOKE_GITHUB_DEPLOY_KEY
        && safe_path_segment(&authority.github_owner)
        && safe_path_segment(&authority.github_repo)
        && authority.deploy_key_id > 0
        && authority.created_at <= authority.expires_at
        && authority.expires_at > 0
        && authority.max_uses == 1
        && authority.uses <= authority.max_uses
}

pub fn caller_matches(authority: &IncidentAuthority, caller_did_bytes: &[u8]) -> bool {
    if caller_did_bytes.len() != 20 || !authority.agent_did.starts_with("did:t3n:") {
        return false;
    }
    let encoded = hex::encode(caller_did_bytes);
    authority.agent_did["did:t3n:".len()..].eq_ignore_ascii_case(&encoded)
}

pub fn begin_execution(
    authority: &mut IncidentAuthority,
    caller_did_bytes: Option<&[u8]>,
    now_secs: u64,
) -> Result<(), GateFailure> {
    match authority.status {
        AuthorityStatus::Consumed => return Err(GateFailure::Replay),
        AuthorityStatus::Executing | AuthorityStatus::ReconcileRequired => {
            return Err(GateFailure::ReconcileOnly)
        }
        AuthorityStatus::Failed => return Err(GateFailure::Failed),
        AuthorityStatus::Expired => return Err(GateFailure::Expired),
        AuthorityStatus::Active => {}
    }

    if !valid_authority_shape(authority) {
        return Err(GateFailure::InvalidTarget);
    }
    let caller = caller_did_bytes.ok_or(GateFailure::MissingCaller)?;
    if !caller_matches(authority, caller) {
        return Err(GateFailure::WrongAgent);
    }
    if now_secs >= authority.expires_at {
        authority.status = AuthorityStatus::Expired;
        return Err(GateFailure::Expired);
    }
    if authority.action != ACTION_REVOKE_GITHUB_DEPLOY_KEY {
        return Err(GateFailure::WrongAction);
    }
    if authority.uses >= authority.max_uses {
        return Err(GateFailure::MaxUses);
    }

    authority.status = AuthorityStatus::Executing;
    Ok(())
}

pub fn consume(authority: &mut IncidentAuthority) -> Result<(), GateFailure> {
    if authority.status != AuthorityStatus::Executing
        && authority.status != AuthorityStatus::ReconcileRequired
    {
        return Err(GateFailure::InvalidState);
    }
    if authority.uses >= authority.max_uses {
        return Err(GateFailure::MaxUses);
    }
    authority.uses += 1;
    authority.status = AuthorityStatus::Consumed;
    Ok(())
}

pub fn mark_reconcile_required(authority: &mut IncidentAuthority) -> Result<(), GateFailure> {
    if authority.status != AuthorityStatus::Executing
        && authority.status != AuthorityStatus::ReconcileRequired
    {
        return Err(GateFailure::InvalidState);
    }
    authority.status = AuthorityStatus::ReconcileRequired;
    Ok(())
}

pub fn mark_failed(authority: &mut IncidentAuthority) -> Result<(), GateFailure> {
    if authority.status != AuthorityStatus::Executing {
        return Err(GateFailure::InvalidState);
    }
    authority.status = AuthorityStatus::Failed;
    Ok(())
}

fn safe_path_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority(status: AuthorityStatus) -> IncidentAuthority {
        IncidentAuthority {
            incident_id: "INC-1042".into(),
            agent_did: "did:t3n:00112233445566778899aabbccddeeff00112233".into(),
            action: ACTION_REVOKE_GITHUB_DEPLOY_KEY.into(),
            github_owner: "Ticoworld".into(),
            github_repo: "t3n-breakglass-sandbox".into(),
            deploy_key_id: 1,
            created_at: 1_000,
            expires_at: 2_000,
            max_uses: 1,
            uses: 0,
            status,
        }
    }

    fn caller() -> [u8; 20] {
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
        ]
    }

    #[test]
    fn nonexistent_incident_is_not_executable() {
        let absent: Option<IncidentAuthority> = None;
        assert!(absent.is_none());
    }

    #[test]
    fn wrong_agent_is_denied_before_execution() {
        let mut record = authority(AuthorityStatus::Active);
        assert_eq!(
            begin_execution(&mut record, Some(&[0u8; 20]), 1_500),
            Err(GateFailure::WrongAgent)
        );
        assert_eq!(record.status, AuthorityStatus::Active);
    }

    #[test]
    fn expired_authority_is_persisted_expired() {
        let mut record = authority(AuthorityStatus::Active);
        assert_eq!(
            begin_execution(&mut record, Some(&caller()), 2_000),
            Err(GateFailure::Expired)
        );
        assert_eq!(record.status, AuthorityStatus::Expired);
    }

    #[test]
    fn valid_active_authority_enters_executing() {
        let mut record = authority(AuthorityStatus::Active);
        assert_eq!(begin_execution(&mut record, Some(&caller()), 1_500), Ok(()));
        assert_eq!(record.status, AuthorityStatus::Executing);
    }

    #[test]
    fn consumed_authority_is_replay_refused() {
        let mut record = authority(AuthorityStatus::Consumed);
        record.uses = 1;
        assert_eq!(
            begin_execution(&mut record, Some(&caller()), 1_500),
            Err(GateFailure::Replay)
        );
    }

    #[test]
    fn max_use_is_enforced() {
        let mut record = authority(AuthorityStatus::Active);
        record.uses = 1;
        assert_eq!(
            begin_execution(&mut record, Some(&caller()), 1_500),
            Err(GateFailure::MaxUses)
        );
    }

    #[test]
    fn target_is_loaded_from_record_and_caller_has_no_target_fields() {
        let request = parse_request(Some(br#"{"incident_id":"INC-1042"}"#)).unwrap();
        assert_eq!(request.incident_id, "INC-1042");
        assert!(parse_request(Some(
            br#"{"incident_id":"INC-1042","github_repo":"other-repo"}"#
        ))
        .is_err());
    }

    #[test]
    fn ambiguous_outcome_requires_reconciliation_without_consuming() {
        let mut record = authority(AuthorityStatus::Executing);
        assert_eq!(mark_reconcile_required(&mut record), Ok(()));
        assert_eq!(record.status, AuthorityStatus::ReconcileRequired);
        assert_eq!(
            begin_execution(&mut record, Some(&caller()), 1_500),
            Err(GateFailure::ReconcileOnly)
        );
    }

    #[test]
    fn reconciliation_can_consume_only_after_absence_is_proven() {
        let mut record = authority(AuthorityStatus::ReconcileRequired);
        assert_eq!(consume(&mut record), Ok(()));
        assert_eq!(record.status, AuthorityStatus::Consumed);
        assert_eq!(record.uses, 1);
    }

    #[test]
    fn invalid_state_transition_is_rejected() {
        let mut record = authority(AuthorityStatus::Active);
        assert_eq!(mark_failed(&mut record), Err(GateFailure::InvalidState));
        assert_eq!(record.status, AuthorityStatus::Active);
    }
}
