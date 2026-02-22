//! Secrets tools: secrets_list, secrets_get, secrets_store.
//!
//! These are stub implementations. Real execution is intercepted by the gateway
//! before `execute_tool` is reached. If we end up here it means something
//! bypassed the gateway interception layer, so we refuse with a clear message.

use serde_json::Value;
use std::path::Path;
use tracing::warn;

/// Stub executor for secrets tools – always errors.
pub fn exec_secrets_stub(_args: &Value, _workspace_dir: &Path) -> Result<String, String> {
    warn!("Secrets tool called outside gateway layer");
    Err("Secrets tools must be executed through the gateway layer".to_string())
}
