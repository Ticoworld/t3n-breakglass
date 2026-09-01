//! BreakGlass Phase 1: incident-bound, one-use GitHub deploy-key authority.
//!
//! The operator creates the incident record in a private T3N KV map.  The agent
//! request contains only the incident id.  This component reads the record,
//! binds it to the authenticated calling DID and cluster time, commits
//! ACTIVE -> EXECUTING before the external call, and never retries DELETE after
//! an ambiguous result.  Reconciliation is GET-only.
#![warn(clippy::style, missing_debug_implementations)]
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

extern crate alloc;

mod authority;
mod target;

pub const CONTRACT_VERSION: &str = "1.0.0";

wit_bindgen::generate!({
    world: "breakglass",
    path: "wit",
    additional_derives: [serde::Deserialize, serde::Serialize],
    generate_all,
});

struct Component;

#[cfg(target_arch = "wasm32")]
impl exports::z::breakglass::contracts::Guest for Component {
    fn execute_incident(
        req: exports::z::breakglass::contracts::GenericInput,
    ) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
        execute(req.input.as_deref())
    }
}

#[cfg(target_arch = "wasm32")]
export!(Component);

#[cfg(target_arch = "wasm32")]
fn execute(raw_input: Option<&[u8]>) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
    use crate::authority::{begin_execution, parse_request, AuthorityStatus, GateFailure, IncidentAuthority};
    use crate::host::{interfaces::kv_store, tenant::tenant_context};

    let request = match parse_request(raw_input) {
        Ok(request) => request,
        Err(note) => return deny_json(None, "DENIED", "", "", note),
    };

    let tenant_hex = hex::encode(tenant_context::tenant_did());
    let incidents_map = alloc::format!("z:{tenant_hex}:{}", target::INCIDENT_MAP_TAIL);
    let raw_authority = kv_store::get(&incidents_map, request.incident_id.as_bytes())
        .map_err(|_| "incident authority read failed".to_string())?;
    let Some(raw_authority) = raw_authority else {
        return deny_json(
            Some(&request.incident_id),
            "DENIED",
            "",
            "",
            "incident authority does not exist",
        );
    };

    let mut authority: IncidentAuthority = match serde_json::from_slice(&raw_authority) {
        Ok(authority) => authority,
        Err(_) => {
            return deny_json(
                Some(&request.incident_id),
                "DENIED",
                "",
                "",
                "incident authority is malformed",
            )
        }
    };
    if authority.incident_id != request.incident_id {
        return deny_json(
            Some(&request.incident_id),
            "DENIED",
            "",
            "",
            "incident authority key does not match its record id",
        );
    }

    let state_before = authority.status.label();
    if authority.status == AuthorityStatus::Executing
        || authority.status == AuthorityStatus::ReconcileRequired
    {
        return reconcile(&mut authority, &incidents_map, state_before);
    }

    let caller = tenant_context::calling_user_did();
    let now_secs = tenant_context::cluster_timestamp_secs();
    if let Err(failure) = begin_execution(&mut authority, caller.as_deref(), now_secs) {
        if failure == GateFailure::Expired {
            put_authority(&incidents_map, &authority)?;
        }
        return proof_json(
            &authority,
            state_before,
            failure.code(),
            None,
            false,
            None,
            false,
            None,
            failure == GateFailure::Replay,
            failure.note(),
        );
    }

    // The exact host is a contract policy constant.  The agent delegation must
    // independently carry the same single-host egress grant.
    if target::API_BASE != "https://api.github.com" {
        return Err("egress policy is not pinned to api.github.com".to_string());
    }
    let pat = match sealed_pat(&tenant_hex) {
        Ok(pat) => pat,
        Err(note) => return deny_json(Some(&authority.incident_id), "DENIED", authority.github_owner.as_str(), authority.github_repo.as_str(), note),
    };

    put_authority(&incidents_map, &authority)?;
    let headers = github_headers(&pat);
    let url = github_url(&authority);

    let before_status = match github_get(&url, &headers) {
        Ok(status) => status,
        Err(()) => {
            return proof_json(
                &authority,
                "EXECUTING",
                "PRECHECK_FAILED",
                None,
                false,
                None,
                false,
                None,
                false,
                "authoritative before-GET failed; DELETE was not attempted",
            )
        }
    };
    if before_status != 200 {
        return proof_json(
            &authority,
            "EXECUTING",
            "PRECHECK_FAILED",
            Some(before_status),
            false,
            None,
            false,
            None,
            false,
            "target key was not confirmed present; DELETE was not attempted",
        );
    }

    let delete_result = github_delete(&url, &headers);
    match delete_result {
        Err(()) => {
            // No retry is possible from this branch.  One GET may prove that
            // the ambiguous request did take effect.
            match github_get(&url, &headers) {
                Ok(404) => {
                    crate::authority::consume(&mut authority)
                        .map_err(|_| "invalid consume transition".to_string())?;
                    put_authority(&incidents_map, &authority)?;
                    proof_json(
                        &authority,
                        "EXECUTING",
                        "CONSUMED",
                        Some(before_status),
                        true,
                        None,
                        true,
                        Some(404),
                        false,
                        "DELETE outcome was ambiguous; authoritative GET proved the key absent",
                    )
                }
                Ok(status) => {
                    crate::authority::mark_reconcile_required(&mut authority)
                        .map_err(|_| "invalid reconciliation transition".to_string())?;
                    put_authority(&incidents_map, &authority)?;
                    proof_json(
                        &authority,
                        "EXECUTING",
                        "RECONCILE_REQUIRED",
                        Some(before_status),
                        true,
                        None,
                        true,
                        Some(status),
                        false,
                        "DELETE outcome was ambiguous; no destructive retry is allowed",
                    )
                }
                Err(()) => {
                    crate::authority::mark_reconcile_required(&mut authority)
                        .map_err(|_| "invalid reconciliation transition".to_string())?;
                    put_authority(&incidents_map, &authority)?;
                    proof_json(
                        &authority,
                        "EXECUTING",
                        "RECONCILE_REQUIRED",
                        Some(before_status),
                        true,
                        None,
                        true,
                        None,
                        false,
                        "DELETE and authoritative verification were ambiguous; no retry is allowed",
                    )
                }
            }
        }
        Ok(delete_status) => match github_get(&url, &headers) {
            Ok(404) => {
                crate::authority::consume(&mut authority)
                    .map_err(|_| "invalid consume transition".to_string())?;
                put_authority(&incidents_map, &authority)?;
                proof_json(
                    &authority,
                    "EXECUTING",
                    "CONSUMED",
                    Some(before_status),
                    true,
                    Some(delete_status),
                    true,
                    Some(404),
                    false,
                    "authoritative GET proved the key absent after the attempted DELETE",
                )
            }
            Ok(200) if delete_status != 204 => {
                crate::authority::mark_failed(&mut authority)
                    .map_err(|_| "invalid failure transition".to_string())?;
                put_authority(&incidents_map, &authority)?;
                proof_json(
                    &authority,
                    "EXECUTING",
                    "FAILED",
                    Some(before_status),
                    true,
                    Some(delete_status),
                    true,
                    Some(200),
                    false,
                    "confirmed failed DELETE; authoritative GET proves the key remains",
                )
            }
            Ok(status) => {
                crate::authority::mark_reconcile_required(&mut authority)
                    .map_err(|_| "invalid reconciliation transition".to_string())?;
                put_authority(&incidents_map, &authority)?;
                proof_json(
                    &authority,
                    "EXECUTING",
                    "RECONCILE_REQUIRED",
                    Some(before_status),
                    true,
                    Some(delete_status),
                    true,
                    Some(status),
                    false,
                    "DELETE/verification outcome is inconsistent; no retry is allowed",
                )
            }
            Err(()) => {
                crate::authority::mark_reconcile_required(&mut authority)
                    .map_err(|_| "invalid reconciliation transition".to_string())?;
                put_authority(&incidents_map, &authority)?;
                proof_json(
                    &authority,
                    "EXECUTING",
                    "RECONCILE_REQUIRED",
                    Some(before_status),
                    true,
                    Some(delete_status),
                    true,
                    None,
                    false,
                    "verification was ambiguous; authoritative reconciliation is required",
                )
            }
        },
    }
}

#[cfg(target_arch = "wasm32")]
fn reconcile(
    authority: &mut authority::IncidentAuthority,
    incidents_map: &str,
    state_before: &str,
) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
    let tenant_hex = hex::encode(crate::host::tenant::tenant_context::tenant_did());
    let pat = sealed_pat(&tenant_hex)?;
    let headers = github_headers(&pat);
    let url = github_url(authority);

    match github_get(&url, &headers) {
        Ok(404) => {
            authority::consume(authority)
                .map_err(|_| "invalid reconciliation consume transition".to_string())?;
            put_authority(incidents_map, authority)?;
            proof_json(
                authority,
                state_before,
                "CONSUMED",
                None,
                false,
                None,
                true,
                Some(404),
                false,
                "authoritative reconciliation proved the key absent; no DELETE was issued",
            )
        }
        Ok(status) => {
            authority::mark_reconcile_required(authority)
                .map_err(|_| "invalid reconciliation transition".to_string())?;
            put_authority(incidents_map, authority)?;
            proof_json(
                authority,
                state_before,
                "RECONCILE_REQUIRED",
                None,
                false,
                None,
                true,
                Some(status),
                false,
                "authoritative reconciliation did not prove absence; no DELETE was issued",
            )
        }
        Err(()) => {
            authority::mark_reconcile_required(authority)
                .map_err(|_| "invalid reconciliation transition".to_string())?;
            put_authority(incidents_map, authority)?;
            proof_json(
                authority,
                state_before,
                "RECONCILE_REQUIRED",
                None,
                false,
                None,
                true,
                None,
                false,
                "authoritative reconciliation was ambiguous; no DELETE was issued",
            )
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn put_authority(
    incidents_map: &str,
    authority: &authority::IncidentAuthority,
) -> Result<(), alloc::string::String> {
    use crate::host::interfaces::kv_store;
    let value = serde_json::to_vec(authority)
        .map_err(|_| "incident authority serialization failed".to_string())?;
    kv_store::put(incidents_map, authority.incident_id.as_bytes(), &value)
        .map_err(|_| "incident authority write failed".to_string())
}

#[cfg(target_arch = "wasm32")]
fn sealed_pat(tenant_hex: &str) -> Result<alloc::string::String, alloc::string::String> {
    use crate::host::interfaces::kv_store;
    let map = alloc::format!("z:{tenant_hex}:{}", target::SECRET_MAP_TAIL);
    let value = kv_store::get(&map, target::GITHUB_PAT_KEY)
        .map_err(|_| "sealed credential read failed".to_string())?
        .ok_or("sealed GitHub credential is not provisioned")?;
    if value.is_empty() {
        return Err("sealed GitHub credential is empty".to_string());
    }
    alloc::string::String::from_utf8(value)
        .map_err(|_| "sealed GitHub credential is not valid UTF-8".to_string())
}

#[cfg(target_arch = "wasm32")]
fn github_url(authority: &authority::IncidentAuthority) -> alloc::string::String {
    alloc::format!(
        "{}/repos/{}/{}/keys/{}",
        target::API_BASE,
        authority.github_owner,
        authority.github_repo,
        authority.deploy_key_id
    )
}

#[cfg(target_arch = "wasm32")]
fn github_get(
    url: &str,
    headers: &alloc::vec::Vec<(alloc::string::String, alloc::string::String)>,
) -> Result<u16, ()> {
    use crate::host::interfaces::http;
    http::call(&http::Request {
        method: http::Verb::Get,
        url: url.to_string(),
        headers: Some(headers.clone()),
        payload: None,
    })
    .map(|response| response.code)
    .map_err(|_| ())
}

#[cfg(target_arch = "wasm32")]
fn github_delete(
    url: &str,
    headers: &alloc::vec::Vec<(alloc::string::String, alloc::string::String)>,
) -> Result<u16, ()> {
    use crate::host::interfaces::http;
    http::call(&http::Request {
        method: http::Verb::Delete,
        url: url.to_string(),
        headers: Some(headers.clone()),
        payload: None,
    })
    .map(|response| response.code)
    .map_err(|_| ())
}

#[cfg(target_arch = "wasm32")]
fn github_headers(pat: &str) -> alloc::vec::Vec<(alloc::string::String, alloc::string::String)> {
    alloc::vec![
        ("Authorization".to_string(), alloc::format!("Bearer {pat}")),
        (
            "Accept".to_string(),
            "application/vnd.github+json".to_string()
        ),
        ("X-GitHub-Api-Version".to_string(), "2026-03-10".to_string()),
        ("User-Agent".to_string(), "breakglass-phase1".to_string()),
    ]
}

#[cfg(target_arch = "wasm32")]
fn deny_json(
    incident_id: Option<&str>,
    outcome: &str,
    owner: &str,
    repository: &str,
    note: impl AsRef<str>,
) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
    use serde_json::json;
    let result = json!({
        "status": outcome,
        "incident_id": incident_id,
        "target": {"host": target::API_BASE, "owner": owner, "repository": repository},
        "destructive_call": {"attempted": false, "method": "NONE", "http_status": null, "count": 0},
        "verification": {"attempted": false, "authoritative": false, "http_status": null, "absent": false},
        "replay_guard": {"replay_refused": outcome == "REPLAY_REFUSED", "destructive_call_count": 0},
        "note": note.as_ref(),
    });
    let _ = crate::host::interfaces::logging::info("BreakGlass denial recorded; credential omitted");
    serde_json::to_vec(&result).map_err(|_| "proof serialization failed".to_string())
}

#[cfg(target_arch = "wasm32")]
fn proof_json(
    authority: &authority::IncidentAuthority,
    state_before: &str,
    outcome: &str,
    before_status: Option<u16>,
    delete_attempted: bool,
    delete_status: Option<u16>,
    verification_attempted: bool,
    verification_status: Option<u16>,
    replay_refused: bool,
    note: &str,
) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
    use serde_json::json;
    let result = json!({
        "status": outcome,
        "incident_id": authority.incident_id,
        "authority": {
            "agent_did": authority.agent_did,
            "action": authority.action,
            "created_at": authority.created_at,
            "expires_at": authority.expires_at,
            "max_uses": authority.max_uses,
            "uses": authority.uses,
            "status": authority.status.label(),
        },
        "target": {
            "host": target::API_BASE,
            "owner": authority.github_owner,
            "repository": authority.github_repo,
            "deploy_key_id": authority.deploy_key_id
        },
        "before": {"http_status": before_status, "exists": before_status == Some(200)},
        "destructive_call": {
            "attempted": delete_attempted,
            "method": if delete_attempted { "DELETE" } else { "NONE" },
            "http_status": delete_status,
            "count": if delete_attempted { 1 } else { 0 }
        },
        "verification": {
            "attempted": verification_attempted,
            "authoritative": verification_attempted,
            "http_status": verification_status,
            "absent": verification_status == Some(404)
        },
        "state": {"before": state_before, "after": authority.status.label()},
        "replay_guard": {
            "replay_refused": replay_refused,
            "destructive_call_count": if delete_attempted { 1 } else { 0 }
        },
        "egress": {"host": target::API_BASE, "exact": true},
        "note": note
    });
    let _ = crate::host::interfaces::logging::info("BreakGlass Phase 1 result recorded; credential omitted");
    serde_json::to_vec(&result).map_err(|_| "proof serialization failed".to_string())
}

#[cfg(test)]
mod tests {
    use super::CONTRACT_VERSION;

    #[test]
    fn contract_version_is_phase1_semver() {
        assert_eq!(CONTRACT_VERSION, "1.0.0");
    }
}
