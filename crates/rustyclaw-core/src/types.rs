// ── Shared display types ────────────────────────────────────────────────────
//
// These types are used by both the core library and all clients.
// They were originally defined in the TUI panes module but are
// client-agnostic concepts.

/// Connection status of the gateway WebSocket.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayStatus {
    /// No gateway URL configured
    #[default]
    Unconfigured,
    /// Not connected / connection lost
    Disconnected,
    /// Connection attempt in progress
    Connecting,
    /// Successfully connected to the gateway
    Connected,
    /// Gateway has validated the model connection and is ready for chat
    ModelReady,
    /// Gateway reported a model/credential error
    ModelError,
    /// Connection attempt failed
    Error,
    /// Gateway vault is locked — password needed
    VaultLocked,
    /// Gateway requires TOTP authentication
    AuthRequired,
}

impl GatewayStatus {
    pub fn label(self) -> &'static str {
        match self {
            GatewayStatus::Unconfigured => "no gateway",
            GatewayStatus::Disconnected => "disconnected",
            GatewayStatus::Connecting => "connecting…",
            GatewayStatus::Connected => "connected",
            GatewayStatus::ModelReady => "model ready",
            GatewayStatus::ModelError => "model error",
            GatewayStatus::Error => "error",
            GatewayStatus::VaultLocked => "vault locked 🔒",
            GatewayStatus::AuthRequired => "auth required 🔑",
        }
    }
}

/// Role / category of a chat-pane message.
///
/// Determines the icon and colour used when rendering the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageRole {
    /// User-submitted prompt (▶)
    User,
    /// Model / assistant reply (◀)
    Assistant,
    /// Neutral informational (ℹ)
    Info,
    /// Positive confirmation (✅)
    Success,
    /// Non-critical warning (⚠)
    Warning,
    /// Hard error (❌)
    Error,
    /// Generic system status (📡)
    System,
    /// The model is invoking a tool (🔧)
    ToolCall,
    /// Result of a tool invocation (📎)
    ToolResult,
    /// Collapsed thinking summary from an intermediate tool-loop round (💭)
    Thinking,
}

impl MessageRole {
    /// Leading icon character for display.
    pub fn icon(self) -> &'static str {
        match self {
            Self::User => "▶",
            Self::Assistant => "◀",
            Self::Info => "ℹ",
            Self::Success => "✅",
            Self::Warning => "⚠",
            Self::Error => "❌",
            Self::System => "📡",
            Self::ToolCall => "🔧",
            Self::ToolResult => "📎",
            Self::Thinking => "💭",
        }
    }
}

/// Input mode state (client-agnostic).
#[derive(Default, PartialEq, Eq, Clone, Copy, Debug)]
pub enum InputMode {
    /// Navigation keys are active (input is not focused)
    #[default]
    Normal,
    /// User is typing in the input area
    Input,
}
