//! Protocol types for gateway WebSocket communication.
//!
//! This module provides typed frame definitions to replace magic string
//! literals like `"type": "secrets_list_result"` with type-safe enums.

use serde::{Deserialize, Serialize};

/// Incoming frame types from client to gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientFrameType {
    /// Authentication response with TOTP code.
    AuthResponse,
    /// Unlock the vault with password.
    UnlockVault,
    /// List all secrets.
    SecretsList,
    /// Get a specific secret.
    SecretsGet,
    /// Store a secret.
    SecretsStore,
    /// Delete a secret.
    SecretsDelete,
    /// Peek at a credential (display without exposing value).
    SecretsPeek,
    /// Set access policy for a credential.
    SecretsSetPolicy,
    /// Enable/disable a credential.
    SecretsSetDisabled,
    /// Delete a credential entirely.
    SecretsDeleteCredential,
    /// Check if TOTP is configured.
    SecretsHasTotp,
    /// Set up TOTP for the vault.
    SecretsSetupTotp,
    /// Verify a TOTP code.
    SecretsVerifyTotp,
    /// Remove TOTP from the vault.
    SecretsRemoveTotp,
    /// Reload configuration.
    Reload,
    /// Cancel the current tool loop.
    Cancel,
    /// Chat message (default).
    Chat,
}

impl ClientFrameType {
    /// Parse from a string, returning None for unknown types.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "auth_response" => Some(Self::AuthResponse),
            "unlock_vault" => Some(Self::UnlockVault),
            "secrets_list" => Some(Self::SecretsList),
            "secrets_get" => Some(Self::SecretsGet),
            "secrets_store" => Some(Self::SecretsStore),
            "secrets_delete" => Some(Self::SecretsDelete),
            "secrets_peek" => Some(Self::SecretsPeek),
            "secrets_set_policy" => Some(Self::SecretsSetPolicy),
            "secrets_set_disabled" => Some(Self::SecretsSetDisabled),
            "secrets_delete_credential" => Some(Self::SecretsDeleteCredential),
            "secrets_has_totp" => Some(Self::SecretsHasTotp),
            "secrets_setup_totp" => Some(Self::SecretsSetupTotp),
            "secrets_verify_totp" => Some(Self::SecretsVerifyTotp),
            "secrets_remove_totp" => Some(Self::SecretsRemoveTotp),
            "reload" => Some(Self::Reload),
            "cancel" => Some(Self::Cancel),
            "chat" => Some(Self::Chat),
            _ => None,
        }
    }

    /// Convert to the string representation used in the protocol.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AuthResponse => "auth_response",
            Self::UnlockVault => "unlock_vault",
            Self::SecretsList => "secrets_list",
            Self::SecretsGet => "secrets_get",
            Self::SecretsStore => "secrets_store",
            Self::SecretsDelete => "secrets_delete",
            Self::SecretsPeek => "secrets_peek",
            Self::SecretsSetPolicy => "secrets_set_policy",
            Self::SecretsSetDisabled => "secrets_set_disabled",
            Self::SecretsDeleteCredential => "secrets_delete_credential",
            Self::SecretsHasTotp => "secrets_has_totp",
            Self::SecretsSetupTotp => "secrets_setup_totp",
            Self::SecretsVerifyTotp => "secrets_verify_totp",
            Self::SecretsRemoveTotp => "secrets_remove_totp",
            Self::Reload => "reload",
            Self::Cancel => "cancel",
            Self::Chat => "chat",
        }
    }
}

/// Outgoing frame types from gateway to client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerFrameType {
    /// Authentication challenge request.
    AuthChallenge,
    /// Authentication result.
    AuthResult,
    /// Too many auth attempts, locked out.
    AuthLocked,
    /// Hello message on connect.
    Hello,
    /// Status update frame.
    Status,
    /// Vault unlocked result.
    VaultUnlocked,
    /// Secrets list result.
    SecretsListResult,
    /// Secrets store result.
    SecretsStoreResult,
    /// Secrets get result.
    SecretsGetResult,
    /// Secrets delete result.
    SecretsDeleteResult,
    /// Secrets peek result.
    SecretsPeekResult,
    /// Secrets set policy result.
    SecretsSetPolicyResult,
    /// Secrets set disabled result.
    SecretsSetDisabledResult,
    /// Secrets delete credential result.
    SecretsDeleteCredentialResult,
    /// Secrets has TOTP result.
    SecretsHasTotpResult,
    /// Secrets setup TOTP result.
    SecretsSetupTotpResult,
    /// Secrets verify TOTP result.
    SecretsVerifyTotpResult,
    /// Secrets remove TOTP result.
    SecretsRemoveTotpResult,
    /// Reload result.
    ReloadResult,
    /// Error frame.
    Error,
    /// Info frame.
    Info,
    /// Stream start.
    StreamStart,
    /// Chunk of response text.
    Chunk,
    /// Thinking start (for extended thinking).
    ThinkingStart,
    /// Thinking delta (streaming thinking content).
    ThinkingDelta,
    /// Thinking end.
    ThinkingEnd,
    /// Tool call from model.
    ToolCall,
    /// Tool result from execution.
    ToolResult,
    /// Response complete.
    ResponseDone,
}

impl ServerFrameType {
    /// Convert to the string representation used in the protocol.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AuthChallenge => "auth_challenge",
            Self::AuthResult => "auth_result",
            Self::AuthLocked => "auth_locked",
            Self::Hello => "hello",
            Self::Status => "status",
            Self::VaultUnlocked => "vault_unlocked",
            Self::SecretsListResult => "secrets_list_result",
            Self::SecretsStoreResult => "secrets_store_result",
            Self::SecretsGetResult => "secrets_get_result",
            Self::SecretsDeleteResult => "secrets_delete_result",
            Self::SecretsPeekResult => "secrets_peek_result",
            Self::SecretsSetPolicyResult => "secrets_set_policy_result",
            Self::SecretsSetDisabledResult => "secrets_set_disabled_result",
            Self::SecretsDeleteCredentialResult => "secrets_delete_credential_result",
            Self::SecretsHasTotpResult => "secrets_has_totp_result",
            Self::SecretsSetupTotpResult => "secrets_setup_totp_result",
            Self::SecretsVerifyTotpResult => "secrets_verify_totp_result",
            Self::SecretsRemoveTotpResult => "secrets_remove_totp_result",
            Self::ReloadResult => "reload_result",
            Self::Error => "error",
            Self::Info => "info",
            Self::StreamStart => "stream_start",
            Self::Chunk => "chunk",
            Self::ThinkingStart => "thinking_start",
            Self::ThinkingDelta => "thinking_delta",
            Self::ThinkingEnd => "thinking_end",
            Self::ToolCall => "tool_call",
            Self::ToolResult => "tool_result",
            Self::ResponseDone => "response_done",
        }
    }
}

/// Status frame sub-types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusType {
    /// Model is configured.
    ModelConfigured,
    /// Credentials loaded.
    CredentialsLoaded,
    /// Credentials missing.
    CredentialsMissing,
    /// Model connecting.
    ModelConnecting,
    /// Model ready.
    ModelReady,
    /// Model error.
    ModelError,
    /// No model configured.
    NoModel,
    /// Vault is locked.
    VaultLocked,
}

impl StatusType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ModelConfigured => "model_configured",
            Self::CredentialsLoaded => "credentials_loaded",
            Self::CredentialsMissing => "credentials_missing",
            Self::ModelConnecting => "model_connecting",
            Self::ModelReady => "model_ready",
            Self::ModelError => "model_error",
            Self::NoModel => "no_model",
            Self::VaultLocked => "vault_locked",
        }
    }
}

/// Helper to build typed frames.
pub mod frame {
    use super::*;
    use serde_json::{json, Value};

    /// Create a simple frame with just a type field.
    pub fn simple(frame_type: ServerFrameType) -> Value {
        json!({ "type": frame_type.as_str() })
    }

    /// Create a frame with type and additional fields.
    pub fn with_fields<T: Serialize>(frame_type: ServerFrameType, fields: T) -> Value {
        let mut value = serde_json::to_value(fields).unwrap_or_default();
        if let Some(map) = value.as_object_mut() {
            map.insert("type".to_string(), json!(frame_type.as_str()));
            json!(map)
        } else {
            json!({ "type": frame_type.as_str(), "data": value })
        }
    }

    /// Create an error frame.
    pub fn error(message: &str) -> Value {
        json!({
            "type": ServerFrameType::Error.as_str(),
            "ok": false,
            "message": message
        })
    }

    /// Create an info frame.
    pub fn info(message: &str) -> Value {
        json!({
            "type": ServerFrameType::Info.as_str(),
            "message": message
        })
    }

    /// Create a status frame.
    pub fn status(status: StatusType, detail: &str) -> Value {
        json!({
            "type": ServerFrameType::Status.as_str(),
            "status": status.as_str(),
            "detail": detail
        })
    }

    /// Create an auth challenge frame.
    pub fn auth_challenge() -> Value {
        json!({
            "type": ServerFrameType::AuthChallenge.as_str(),
            "method": "totp"
        })
    }

    /// Create an auth result frame.
    pub fn auth_result(ok: bool, message: Option<&str>, retry: Option<bool>) -> Value {
        let mut map = serde_json::Map::new();
        map.insert(
            "type".to_string(),
            json!(ServerFrameType::AuthResult.as_str()),
        );
        map.insert("ok".to_string(), json!(ok));
        if let Some(msg) = message {
            map.insert("message".to_string(), json!(msg));
        }
        if let Some(r) = retry {
            map.insert("retry".to_string(), json!(r));
        }
        json!(map)
    }

    /// Create an auth locked frame.
    pub fn auth_locked(message: &str, retry_after: Option<u64>) -> Value {
        let mut map = serde_json::Map::new();
        map.insert(
            "type".to_string(),
            json!(ServerFrameType::AuthLocked.as_str()),
        );
        map.insert("message".to_string(), json!(message));
        if let Some(secs) = retry_after {
            map.insert("retry_after".to_string(), json!(secs));
        }
        json!(map)
    }

    /// Create a hello frame.
    pub fn hello(agent: &str, settings_dir: &std::path::Path, vault_locked: bool) -> Value {
        let mut map = serde_json::Map::new();
        map.insert("type".to_string(), json!(ServerFrameType::Hello.as_str()));
        map.insert("agent".to_string(), json!(agent));
        map.insert(
            "settings_dir".to_string(),
            json!(settings_dir.display().to_string()),
        );
        map.insert("vault_locked".to_string(), json!(vault_locked));
        json!(map)
    }

    /// Create a tool call frame.
    pub fn tool_call(id: &str, name: &str, arguments: &serde_json::Value) -> Value {
        json!({
            "type": ServerFrameType::ToolCall.as_str(),
            "id": id,
            "name": name,
            "arguments": arguments
        })
    }

    /// Create a tool result frame.
    pub fn tool_result(id: &str, name: &str, result: &str, is_error: bool) -> Value {
        json!({
            "type": ServerFrameType::ToolResult.as_str(),
            "id": id,
            "name": name,
            "result": result,
            "is_error": is_error
        })
    }

    /// Create a chunk frame for streaming.
    pub fn chunk(delta: &str) -> Value {
        json!({
            "type": ServerFrameType::Chunk.as_str(),
            "delta": delta
        })
    }

    /// Create a response done frame.
    pub fn response_done(ok: bool) -> Value {
        json!({
            "type": ServerFrameType::ResponseDone.as_str(),
            "ok": ok
        })
    }
}
