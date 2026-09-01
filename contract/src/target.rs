//! Fixed policy boundaries. Incident-specific target values are stored in the
//! operator-created private authority map, never compiled into the WASM.

pub const API_BASE: &str = "https://api.github.com";
pub const SECRET_MAP_TAIL: &str = "secrets";
pub const INCIDENT_MAP_TAIL: &str = "incidents";
pub const GITHUB_PAT_KEY: &[u8] = b"github_pat";
