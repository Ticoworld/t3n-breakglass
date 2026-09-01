#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

extern crate alloc;

wit_bindgen::generate!({
    world: "outbox-probe",
    path: "wit",
    generate_all,
});

struct Component;

#[cfg(target_arch = "wasm32")]
impl exports::z::c0r_outbox_probe::contracts::Guest for Component {
    fn link_probe(
        _req: exports::z::c0r_outbox_probe::contracts::GenericInput,
    ) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
        Ok(b"{\"import\":\"linked\",\"outbox_call\":false}".to_vec())
    }

    fn enqueue_probe(
        req: exports::z::c0r_outbox_probe::contracts::GenericInput,
    ) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
        use crate::host::outbox::outbox;

        let body = req.input.unwrap_or_default();
        let idk = "c0r-outbox-probe@disposable-01".to_string();
        let request = outbox::Request {
            method: outbox::Verb::Get,
            url: "https://example.com/".to_string(),
            headers: vec![("Accept".to_string(), "text/plain".to_string())],
            body,
        };

        match outbox::enqueue(&idk, &request) {
            Ok(()) => serde_json::to_vec(&serde_json::json!({
                "enqueue": "ok",
                "idempotency_key": idk,
                "request_url": request.url,
                "method": "get"
            })).map_err(|e| e.to_string()),
            Err(error) => serde_json::to_vec(&serde_json::json!({
                "enqueue": "error",
                "error": format!("{error:?}"),
                "idempotency_key": idk
            })).map_err(|e| e.to_string()),
        }
    }
}

#[cfg(target_arch = "wasm32")]
export!(Component);
