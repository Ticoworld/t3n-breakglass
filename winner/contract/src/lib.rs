#![warn(clippy::style, missing_debug_implementations)]
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

extern crate alloc;

mod model;

pub const CONTRACT_VERSION: &str = "2.0.4";

wit_bindgen::generate!({
    world: "breakglass-winner",
    path: "wit",
    additional_derives: [serde::Deserialize, serde::Serialize],
    generate_all,
});

struct Component;

#[cfg(target_arch = "wasm32")]
impl exports::z::breakglass_winner::contracts::Guest for Component {
    fn create_incident(req: exports::z::breakglass_winner::contracts::GenericInput) -> Result<alloc::vec::Vec<u8>, alloc::string::String> { create_incident(req.input.as_deref()) }
    fn get_incident(req: exports::z::breakglass_winner::contracts::GenericInput) -> Result<alloc::vec::Vec<u8>, alloc::string::String> { get_incident(req.input.as_deref()) }
    fn reserve_incident(req: exports::z::breakglass_winner::contracts::GenericInput) -> Result<alloc::vec::Vec<u8>, alloc::string::String> { dispatch("reserve-incident", req.input.as_deref()) }
    fn claim_effect(req: exports::z::breakglass_winner::contracts::GenericInput) -> Result<alloc::vec::Vec<u8>, alloc::string::String> { dispatch("claim-effect", req.input.as_deref()) }
    fn confirm_claim(req: exports::z::breakglass_winner::contracts::GenericInput) -> Result<alloc::vec::Vec<u8>, alloc::string::String> { dispatch("confirm-claim", req.input.as_deref()) }
    fn release_not_attempted(req: exports::z::breakglass_winner::contracts::GenericInput) -> Result<alloc::vec::Vec<u8>, alloc::string::String> { dispatch("release-not-attempted", req.input.as_deref()) }
    fn begin_effect(req: exports::z::breakglass_winner::contracts::GenericInput) -> Result<alloc::vec::Vec<u8>, alloc::string::String> { dispatch("begin-effect", req.input.as_deref()) }
    fn confirm_effect_start(req: exports::z::breakglass_winner::contracts::GenericInput) -> Result<alloc::vec::Vec<u8>, alloc::string::String> { dispatch("confirm-effect-start", req.input.as_deref()) }
    fn finalize_effect(req: exports::z::breakglass_winner::contracts::GenericInput) -> Result<alloc::vec::Vec<u8>, alloc::string::String> { dispatch("finalize-effect", req.input.as_deref()) }
    fn reconcile_effect(req: exports::z::breakglass_winner::contracts::GenericInput) -> Result<alloc::vec::Vec<u8>, alloc::string::String> { dispatch("reconcile-effect", req.input.as_deref()) }
}

#[cfg(target_arch = "wasm32")]
export!(Component);

#[cfg(target_arch = "wasm32")]
fn dispatch(function_name: &str, raw: Option<&[u8]>) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
    use crate::host::{interfaces::{kv_store, logging}, tenant::tenant_context};

    match function_name {
        "create-incident" => return create_incident(raw),
        "get-incident" => return get_incident(raw),
        _ => {}
    }

    let request_id = match function_name {
        "reserve-incident" => parse_incident(raw)?,
        "claim-effect" => {
            let parsed: model::ClaimRequest = parse_json(raw)?;
            if parsed.incident_id.trim().is_empty() { return Err("incident_id is invalid".into()) }
            parsed.incident_id
        }
        "confirm-claim" => {
            let parsed: model::ClaimIdentityRequest = parse_json(raw)?;
            if parsed.incident_id.trim().is_empty() || parsed.claim_id.trim().is_empty() { return Err("incident_id and claim_id are required".into()) }
            parsed.incident_id
        }
        "release-not-attempted" => {
            let parsed: model::ClaimIdentityRequest = parse_json(raw)?;
            if parsed.incident_id.trim().is_empty() || parsed.claim_id.trim().is_empty() { return Err("incident_id and claim_id are required".into()) }
            parsed.incident_id
        }
        "finalize-effect" => {
            let parsed: model::FinalizeRequest = parse_json(raw)?;
            if parsed.incident_id.trim().is_empty() || parsed.claim_id.trim().is_empty() { return Err("incident_id and claim_id are required".into()) }
            parsed.incident_id
        }
        "reconcile-effect" => {
            let parsed: model::FinalizeRequest = parse_json(raw)?;
            if parsed.incident_id.trim().is_empty() || parsed.claim_id.trim().is_empty() { return Err("incident_id and claim_id are required".into()) }
            parsed.incident_id
        }
        "begin-effect" => {
            let parsed: model::BeginEffectRequest = parse_json(raw)?;
            if parsed.incident_id.trim().is_empty() || parsed.claim_id.trim().is_empty() || parsed.start_nonce.trim().is_empty() { return Err("incident_id, claim_id, and start_nonce are required".into()) }
            parsed.incident_id
        }
        "confirm-effect-start" => {
            let parsed: model::ConfirmEffectStartRequest = parse_json(raw)?;
            if parsed.incident_id.trim().is_empty() || parsed.claim_id.trim().is_empty() || parsed.effect_start_id.trim().is_empty() { return Err("incident_id, claim_id, and effect_start_id are required".into()) }
            parsed.incident_id
        }
        _ => return Err("unknown function".into()),
    };

    let map = incident_map();
    let raw_authority = kv_store::get(&map, request_id.as_bytes()).map_err(|_| "incident authority read failed".to_string())?;
    let Some(raw_authority) = raw_authority else { return json_result(&request_id, function_name, "DENIED", None, "incident authority does not exist") };
    let mut authority: model::IncidentAuthority = serde_json::from_slice(&raw_authority).map_err(|_| "incident authority is malformed".to_string())?;
    if authority.incident_id != request_id || !model::valid_shape(&authority) { return json_result(&request_id, function_name, "DENIED", None, "incident authority is invalid") }
    let caller = tenant_context::calling_user_did();
    let now = tenant_context::cluster_timestamp_secs();

    let decision = match function_name {
        "reserve-incident" => model::reserve(&mut authority, caller.as_deref(), now),
        "claim-effect" => {
            let request: model::ClaimRequest = parse_json(raw)?;
            model::claim_with_nonce(&mut authority, caller.as_deref(), now, request.expected_claim_version, &request.contender_nonce)
        }
        "confirm-claim" => {
            let request: model::ClaimIdentityRequest = parse_json(raw)?;
            let confirmation = model::confirm_claim(&authority, caller.as_deref(), &request.claim_id);
            let (result, note, detail) = match confirmation {
                model::Confirmation::Confirmed => ("CONFIRMED", "persisted claim ownership confirmed", serde_json::json!({"action": authority.action, "github_owner": authority.github_owner, "github_repo": authority.github_repo, "deploy_key_id": authority.deploy_key_id, "claim_id": authority.effect_claim_id, "claim_version": authority.effect_claim_version})),
                model::Confirmation::NotOwner => ("NOT_OWNER", "persisted authority is owned by another claim identity", serde_json::json!({})),
                model::Confirmation::Denied(note) => ("DENIED", note, serde_json::json!({})),
            };
            let response = json_result_with_detail(&request.incident_id, "confirm-claim", result, Some(&authority), detail, note)?;
            let _ = logging::info(&alloc::format!("winner-c1 function=confirm-claim incident={} result={}", request.incident_id, result));
            return Ok(response);
        }
        "release-not-attempted" => {
            let request: model::ClaimIdentityRequest = parse_json(raw)?;
            model::release_not_attempted(&mut authority, caller.as_deref(), &request.claim_id, now)
        }
        "finalize-effect" => {
            let request: model::FinalizeRequest = parse_json(raw)?;
            model::finalize_with_start(&mut authority, caller.as_deref(), &request.claim_id, &request.effect_start_id, &request.classification)
        }
        "reconcile-effect" => {
            let request: model::FinalizeRequest = parse_json(raw)?;
            model::reconcile_with_start(&mut authority, caller.as_deref(), &request.claim_id, &request.effect_start_id, &request.classification)
        }
        "begin-effect" => {
            let request: model::BeginEffectRequest = parse_json(raw)?;
            model::begin_effect_with_nonce(&mut authority, caller.as_deref(), &request.claim_id, &request.start_nonce, now)
        }
        "confirm-effect-start" => {
            let request: model::ConfirmEffectStartRequest = parse_json(raw)?;
            let confirmation = model::confirm_effect_start(&authority, caller.as_deref(), &request.claim_id, &request.effect_start_id);
            let (result, note) = match confirmation {
                model::Confirmation::Confirmed => ("CONFIRMED", "persisted effect-start ownership confirmed"),
                model::Confirmation::NotOwner => ("NOT_OWNER", "persisted authority is owned by another effect-start identity"),
                model::Confirmation::Denied(note) => ("DENIED", note),
            };
            let response = json_result(&request.incident_id, "confirm-effect-start", result, Some(&authority), note)?;
            let _ = logging::info(&alloc::format!("winner-c1 function=confirm-effect-start incident={} result={}", request.incident_id, result));
            return Ok(response);
        }
        _ => unreachable!(),
    };

    let (result, note) = match decision {
        model::Decision::Won => ("WON", "state transition committed in this transaction"),
        model::Decision::Proposed => ("PROPOSED", "claim proposal committed; ownership requires confirm-claim"),
        model::Decision::Lost => ("LOST", "another committed state transition already won"),
        model::Decision::Denied(note) => ("DENIED", note),
    };
    if matches!(&decision, model::Decision::Won | model::Decision::Proposed) || authority.status == model::Status::Expired {
        let encoded = serde_json::to_vec(&authority).map_err(|_| "incident authority serialization failed".to_string())?;
        kv_store::put(&map, request_id.as_bytes(), &encoded).map_err(|_| "incident authority write failed".to_string())?;
    }
    let _ = logging::info(&alloc::format!("winner-c1 function={} incident={} result={} status={}", function_name, request_id, result, authority.status.label()));
    let detail = if function_name == "claim-effect" && result == "PROPOSED" {
        serde_json::json!({"claim_id": authority.effect_claim_id, "claim_version": authority.effect_claim_version})
    } else if function_name == "begin-effect" && result == "WON" {
        serde_json::json!({"claim_id": authority.effect_claim_id, "claim_version": authority.effect_claim_version, "effect_start_id": authority.effect_start_id})
    } else { serde_json::json!({}) };
    json_result_with_detail(&request_id, function_name, result, Some(&authority), detail, note)
}

#[cfg(target_arch = "wasm32")]
fn incident_map() -> alloc::string::String {
    use crate::host::tenant::tenant_context;
    let tenant_hex = hex::encode(tenant_context::tenant_did());
    alloc::format!("z:{tenant_hex}:{}", model::MAP_TAIL)
}

#[cfg(target_arch = "wasm32")]
fn create_incident(raw: Option<&[u8]>) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
    use crate::host::{interfaces::{kv_store, logging}, tenant::tenant_context};

    let request: model::CreateIncidentRequest = parse_json(raw)?;
    let tenant_did = tenant_context::tenant_did();
    let caller = tenant_context::calling_user_did();
    if !model::operator_matches_tenant(caller.as_deref(), &tenant_did) {
        return json_result(&request.incident_id, "create-incident", "DENIED", None, "caller is not the current tenant operator")
    }
    let now = tenant_context::cluster_timestamp_secs();
    let authority = match model::build_incident_authority(&request, caller.as_deref(), &tenant_did, now) {
        Ok(authority) => authority,
        Err(note) => return json_result(&request.incident_id, "create-incident", "DENIED", None, note),
    };
    let map = incident_map();
    let existing = kv_store::get(&map, request.incident_id.as_bytes()).map_err(|_| "incident authority read failed".to_string())?;
    if existing.is_some() {
        return json_result(&request.incident_id, "create-incident", "DENIED", None, "incident authority already exists")
    }
    let encoded = serde_json::to_vec(&authority).map_err(|_| "incident authority serialization failed".to_string())?;
    kv_store::put(&map, request.incident_id.as_bytes(), &encoded).map_err(|_| "incident authority write failed".to_string())?;
    let detail = serde_json::to_value(&authority).map_err(|_| "incident authority serialization failed".to_string())?;
    let _ = logging::info(&alloc::format!("winner-c1 function=create-incident incident={} result=WON status={}", request.incident_id, authority.status.label()));
    json_result_with_detail(&request.incident_id, "create-incident", "WON", Some(&authority), detail, "incident authority created in this transaction")
}

#[cfg(target_arch = "wasm32")]
fn get_incident(raw: Option<&[u8]>) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
    use crate::host::{interfaces::kv_store, tenant::tenant_context};

    let request: model::GetIncidentRequest = parse_json(raw)?;
    if !model::valid_incident_id(&request.incident_id) {
        return Err("incident_id is invalid".into())
    }
    let tenant_did = tenant_context::tenant_did();
    let caller = tenant_context::calling_user_did();
    if !model::operator_matches_tenant(caller.as_deref(), &tenant_did) {
        return json_result(&request.incident_id, "get-incident", "DENIED", None, "caller is not the current tenant operator")
    }
    let map = incident_map();
    let raw_authority = kv_store::get(&map, request.incident_id.as_bytes()).map_err(|_| "incident authority read failed".to_string())?;
    let Some(raw_authority) = raw_authority else {
        return json_result(&request.incident_id, "get-incident", "DENIED", None, "incident authority does not exist")
    };
    let authority: model::IncidentAuthority = serde_json::from_slice(&raw_authority).map_err(|_| "incident authority is malformed".to_string())?;
    if authority.incident_id != request.incident_id || !model::valid_shape(&authority) {
        return json_result(&request.incident_id, "get-incident", "DENIED", None, "incident authority is invalid")
    }
    let detail = serde_json::to_value(&authority).map_err(|_| "incident authority serialization failed".to_string())?;
    json_result_with_detail(&request.incident_id, "get-incident", "FOUND", Some(&authority), detail, "incident authority read through the C1 contract")
}

#[cfg(target_arch = "wasm32")]
fn parse_incident(raw: Option<&[u8]>) -> Result<alloc::string::String, alloc::string::String> {
    let request: model::IncidentRequest = parse_json(raw)?;
    if request.incident_id.trim().is_empty() || request.incident_id.len() > 128 { return Err("incident_id is invalid".into()) }
    Ok(request.incident_id)
}

#[cfg(target_arch = "wasm32")]
fn parse_json<T: serde::de::DeserializeOwned>(raw: Option<&[u8]>) -> Result<T, alloc::string::String> {
    let bytes = raw.ok_or_else(|| "request input is required".to_string())?;
    serde_json::from_slice(bytes).map_err(|_| "request contains invalid or unsupported fields".to_string())
}

#[cfg(target_arch = "wasm32")]
fn json_result(incident_id: &str, function_name: &str, result: &str, authority: Option<&model::IncidentAuthority>, note: &str) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
    json_result_with_detail(incident_id, function_name, result, authority, serde_json::json!({}), note)
}

#[cfg(target_arch = "wasm32")]
fn json_result_with_detail(incident_id: &str, function_name: &str, result: &str, authority: Option<&model::IncidentAuthority>, detail: serde_json::Value, note: &str) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
    let value = serde_json::json!({
        "result": result, "function": function_name, "incident_id": incident_id,
        "state": authority.map(|a| a.status.label()), "effect_attempts": authority.map(|a| a.effect_attempts),
        "detail": detail, "provider_http": {"attempted": false, "count": 0}, "note": note,
    });
    serde_json::to_vec(&value).map_err(|_| "result serialization failed".to_string())
}

#[cfg(test)]
mod tests {
    use super::CONTRACT_VERSION;
    #[test] fn version_is_c1() { assert_eq!(CONTRACT_VERSION, "2.0.4"); }
}
