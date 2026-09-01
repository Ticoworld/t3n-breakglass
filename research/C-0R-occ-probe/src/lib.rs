#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

extern crate alloc;

wit_bindgen::generate!({
    world: "occ-probe",
    path: "wit",
    generate_all,
});

struct Component;

#[derive(serde::Deserialize)]
struct ReserveRequest {
    target_id: alloc::string::String,
    contender_id: alloc::string::String,
}

#[cfg(target_arch = "wasm32")]
impl exports::z::c0r_occ_probe::contracts::Guest for Component {
    fn reserve(
        req: exports::z::c0r_occ_probe::contracts::GenericInput,
    ) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
        use crate::host::{interfaces::{kv_store, logging}, tenant::tenant_context};

        let raw = req.input.unwrap_or_default();
        let request: ReserveRequest = serde_json::from_slice(&raw)
            .map_err(|error| format!("invalid reserve input: {error}"))?;
        if request.target_id.is_empty() || request.contender_id.is_empty() {
            return Err("target_id and contender_id are required".to_string());
        }

        let map = format!("z:{}:c0r-occ-reservations", hex::encode(tenant_context::tenant_did()));
        let key = request.target_id.as_bytes();
        let caller = tenant_context::calling_user_did().map(|did| format!("did:t3n:{}", hex::encode(did)));
        let seq_before = tenant_context::seq_no();
        let current = kv_store::get(&map, key)
            .map_err(|error| format!("kv get failed: {error}"))?;
        let read_state = current.as_ref().map(|value| String::from_utf8_lossy(value).to_string());
        let _ = logging::info(&format!("c0r-occ read target={} current={:?} contender={}", request.target_id, read_state, request.contender_id));

        // Keep the read and put in the same transaction while making two
        // simultaneous remote calls overlap on the disposable testnet key.
        let mut checksum = 0u64;
        for value in 0..2_000_000u64 {
            checksum = checksum.wrapping_add(value ^ checksum.rotate_left(7));
        }

        let result = if current.is_some() {
            "LOST"
        } else {
            kv_store::put(&map, key, request.contender_id.as_bytes())
                .map_err(|error| format!("kv put failed: {error}"))?;
            "WON"
        };
        let seq_after = tenant_context::seq_no();
        let _ = logging::info(&format!("c0r-occ write target={} result={} checksum={} seq={}", request.target_id, result, checksum, seq_after));
        serde_json::to_vec(&serde_json::json!({
            "target_id": request.target_id,
            "contender_id": request.contender_id,
            "caller_did": caller,
            "read_state": read_state,
            "result": result,
            "seq_before": seq_before,
            "seq_after": seq_after,
            "checksum": checksum,
        })).map_err(|error| error.to_string())
    }
}

#[cfg(target_arch = "wasm32")]
export!(Component);
