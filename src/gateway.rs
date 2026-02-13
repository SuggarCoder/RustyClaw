use crate::config::Config;
use crate::providers;
use crate::secrets::{AccessContext, AccessPolicy, CredentialValue, SecretEntry, SecretKind, SecretsManager};
use crate::skills::SkillManager;
use crate::tools;
use anyhow::{Context, Result};
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tokio_util::sync::CancellationToken;
use url::Url;

/// Type alias for the server-side WebSocket write half.
type WsWriter = SplitSink<WebSocketStream<tokio::net::TcpStream>, Message>;

#[derive(Debug, Clone)]
pub struct GatewayOptions {
    pub listen: String,
}

// ── TOTP rate limiter ───────────────────────────────────────────────────────

/// Maximum consecutive TOTP failures before lockout.
const MAX_TOTP_FAILURES: u32 = 3;
/// Duration of the lockout after exceeding the failure limit.
const TOTP_LOCKOUT_SECS: u64 = 30;
/// Window within which failures are counted (resets after this).
const TOTP_FAILURE_WINDOW_SECS: u64 = 60;

/// Compaction fires when estimated usage exceeds this fraction of the context window.
const COMPACTION_THRESHOLD: f64 = 0.75;
/// After compaction, we aim to keep this fraction of the window for fresh context.
const COMPACTION_TARGET: f64 = 0.40;

/// Return the context-window size (in tokens) for a given model name.
/// Conservative defaults — these are *input* token limits.
fn context_window_for_model(model: &str) -> usize {
    let m = model.to_lowercase();
    // Anthropic
    if m.contains("claude-opus")   { return 200_000; }
    if m.contains("claude-sonnet") { return 200_000; }
    if m.contains("claude-haiku")  { return 200_000; }
    // OpenAI
    if m.starts_with("gpt-4.1")    { return 1_000_000; }
    if m.starts_with("o3") || m.starts_with("o4") { return 200_000; }
    // Google Gemini
    if m.contains("gemini-2.5-pro")  { return 1_000_000; }
    if m.contains("gemini-2.5-flash") { return 1_000_000; }
    if m.contains("gemini-2.0-flash") { return 1_000_000; }
    // xAI
    if m.contains("grok-3")  { return 131_072; }
    // Ollama / unknown — conservative
    if m.contains("llama")   { return 128_000; }
    if m.contains("mistral") { return 128_000; }
    if m.contains("deepseek") { return 128_000; }
    // Fallback: 128k is a safe default for modern models
    128_000
}

/// Fast token estimate: roughly 1 token ≈ 4 characters for English text.
/// This is intentionally conservative (over-estimates) to trigger compaction
/// early rather than hitting the provider's hard limit.
fn estimate_tokens(messages: &[ChatMessage]) -> usize {
    let total_chars: usize = messages.iter().map(|m| m.role.len() + m.content.len()).sum();
    // ~3.5 chars/token for English; we round down to be conservative.
    total_chars / 3
}

/// Per-IP TOTP failure tracking.
#[derive(Debug, Clone)]
struct TotpAttempt {
    failures: u32,
    first_failure: Instant,
    lockout_until: Option<Instant>,
}

/// Thread-safe rate limiter shared across all connections.
type RateLimiter = Arc<Mutex<HashMap<IpAddr, TotpAttempt>>>;

fn new_rate_limiter() -> RateLimiter {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Check whether an IP is currently locked out. Returns the number of
/// seconds remaining if locked, or `None` if the IP may attempt auth.
async fn check_rate_limit(limiter: &RateLimiter, ip: IpAddr) -> Option<u64> {
    let mut map = limiter.lock().await;
    if let Some(attempt) = map.get_mut(&ip) {
        // Expire old failure windows.
        if attempt.first_failure.elapsed().as_secs() > TOTP_FAILURE_WINDOW_SECS {
            *attempt = TotpAttempt {
                failures: 0,
                first_failure: Instant::now(),
                lockout_until: None,
            };
            return None;
        }
        // Check active lockout.
        if let Some(until) = attempt.lockout_until {
            if Instant::now() < until {
                let remaining = (until - Instant::now()).as_secs() + 1;
                return Some(remaining);
            }
            // Lockout expired — reset.
            *attempt = TotpAttempt {
                failures: 0,
                first_failure: Instant::now(),
                lockout_until: None,
            };
        }
    }
    None
}

/// Record a failed TOTP attempt. Returns `true` if the IP is now locked out.
async fn record_totp_failure(limiter: &RateLimiter, ip: IpAddr) -> bool {
    let mut map = limiter.lock().await;
    let attempt = map.entry(ip).or_insert_with(|| TotpAttempt {
        failures: 0,
        first_failure: Instant::now(),
        lockout_until: None,
    });

    // Reset if the window has expired.
    if attempt.first_failure.elapsed().as_secs() > TOTP_FAILURE_WINDOW_SECS {
        attempt.failures = 0;
        attempt.first_failure = Instant::now();
        attempt.lockout_until = None;
    }

    attempt.failures += 1;
    if attempt.failures >= MAX_TOTP_FAILURES {
        attempt.lockout_until = Some(Instant::now() + std::time::Duration::from_secs(TOTP_LOCKOUT_SECS));
        true
    } else {
        false
    }
}

/// Clear failure tracking for an IP after a successful auth.
async fn clear_rate_limit(limiter: &RateLimiter, ip: IpAddr) {
    let mut map = limiter.lock().await;
    map.remove(&ip);
}

// ── Vault state ─────────────────────────────────────────────────────────────

/// Gateway-owned secrets vault, shared across connections.
///
/// The vault may start in a locked state (no password provided yet) and
/// be unlocked later via a control message from an authenticated client.
pub type SharedVault = Arc<Mutex<SecretsManager>>;

/// Gateway-owned skill manager, shared across connections.
pub type SharedSkillManager = Arc<Mutex<SkillManager>>;

// ── Model context (resolved once at startup) ────────────────────────────────

/// Pre-resolved model configuration created at gateway startup.
///
/// The gateway reads the configured provider + model from `Config`, fetches
/// the API key from the secrets vault, and holds everything in this struct
/// so per-connection handlers can call the provider without the client
/// needing to send credentials.
#[derive(Debug, Clone)]
pub struct ModelContext {
    pub provider: String,
    pub model: String,
    pub base_url: String,
    pub api_key: Option<String>,
}

impl ModelContext {
    /// Resolve the model context from the app configuration and secrets vault.
    ///
    /// Returns an error if no `[model]` section is present in the config.
    /// A missing API key is treated as a warning (the provider may not need
    /// one — e.g. Ollama), not a hard error.
    pub fn resolve(config: &Config, secrets: &mut SecretsManager) -> Result<Self> {
        let mp = config
            .model
            .as_ref()
            .context("No [model] section in config — run `rustyclaw onboard` or add one to config.toml")?;

        let provider = mp.provider.clone();
        let model = mp.model.clone().unwrap_or_default();
        let base_url = mp.base_url.clone().unwrap_or_else(|| {
            providers::base_url_for_provider(&provider)
                .unwrap_or("")
                .to_string()
        });

        let api_key = providers::secret_key_for_provider(&provider).and_then(|key_name| {
            secrets.get_secret(key_name, true).ok().flatten()
        });

        if api_key.is_none() && providers::secret_key_for_provider(&provider).is_some() {
            eprintln!(
                "⚠ No API key found for provider '{}' — model calls will likely fail",
                provider,
            );
        }

        Ok(Self {
            provider,
            model,
            base_url,
            api_key,
        })
    }

    /// Build a model context from configuration and a pre-resolved API key.
    ///
    /// Use this when the caller has already extracted the key (e.g. the CLI
    /// passes just the provider key to the daemon via an environment
    /// variable, so the gateway never needs vault access).
    pub fn from_config(config: &Config, api_key: Option<String>) -> Result<Self> {
        let mp = config
            .model
            .as_ref()
            .context("No [model] section in config — run `rustyclaw onboard` or add one to config.toml")?;

        let provider = mp.provider.clone();
        let model = mp.model.clone().unwrap_or_default();
        let base_url = mp.base_url.clone().unwrap_or_else(|| {
            providers::base_url_for_provider(&provider)
                .unwrap_or("")
                .to_string()
        });

        if api_key.is_none() && providers::secret_key_for_provider(&provider).is_some() {
            eprintln!(
                "⚠ No API key provided for provider '{}' — model calls will likely fail",
                provider,
            );
        }

        Ok(Self {
            provider,
            model,
            base_url,
            api_key,
        })
    }
}

// ── Copilot session token cache ──────────────────────────────────────────────

/// Manages a short-lived Copilot session token, auto-refreshing on expiry.
///
/// GitHub Copilot's chat API requires a session token obtained by
/// exchanging the long-lived OAuth device-flow token.  Session tokens
/// expire after ~30 minutes.  This struct caches the active session and
/// transparently refreshes it when needed.
pub struct CopilotSession {
    oauth_token: String,
    inner: tokio::sync::Mutex<Option<CopilotSessionEntry>>,
}

struct CopilotSessionEntry {
    token: String,
    expires_at: i64,
}

impl CopilotSession {
    /// Create a new session manager wrapping the given OAuth token.
    pub fn new(oauth_token: String) -> Self {
        Self {
            oauth_token,
            inner: tokio::sync::Mutex::new(None),
        }
    }

    /// Return a valid session token, exchanging or refreshing as needed.
    ///
    /// Caches the token and only calls the exchange endpoint when the
    /// cached token is missing or within 60 seconds of expiry.
    pub async fn get_token(&self, http: &reqwest::Client) -> Result<String> {
        let mut guard = self.inner.lock().await;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Return cached token if still valid (with 60 s safety margin).
        if let Some(ref entry) = *guard {
            if now < entry.expires_at - 60 {
                return Ok(entry.token.clone());
            }
        }

        // Exchange the OAuth token for a fresh session token.
        let session = providers::exchange_copilot_session(http, &self.oauth_token)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        let token = session.token.clone();
        *guard = Some(CopilotSessionEntry {
            token: session.token,
            expires_at: session.expires_at,
        });
        Ok(token)
    }
}

/// Resolve the effective bearer token for an API call.
///
/// For Copilot providers the raw API key is an OAuth token that must be
/// exchanged for a short-lived session token.  For all other providers
/// the raw key is returned as-is.
async fn resolve_bearer_token(
    http: &reqwest::Client,
    provider: &str,
    raw_key: Option<&str>,
    session: Option<&CopilotSession>,
) -> Result<Option<String>> {
    if providers::needs_copilot_session(provider) {
        if let Some(session) = session {
            return Ok(Some(session.get_token(http).await?));
        }
    }
    Ok(raw_key.map(String::from))
}

// ── Status reporting ─────────────────────────────────────────────────────────

/// Build a JSON status frame to push to connected clients.
///
/// Status frames use `{ "type": "status", "status": "…", "detail": "…" }`.
/// The TUI uses these to update the gateway badge and display progress.
fn status_frame(status: &str, detail: &str) -> String {
    json!({
        "type": "status",
        "status": status,
        "detail": detail,
    })
    .to_string()
}

/// Result of a model connection probe.
pub enum ProbeResult {
    /// Provider responded successfully — everything works.
    Ready,
    /// Authenticated and reachable, but the specific model or request format
    /// wasn't accepted (e.g. 400 "model not supported").  Chat may still
    /// work with the real request format.
    Connected { warning: String },
    /// Hard failure — authentication rejected (401/403).
    AuthError { detail: String },
    /// Hard failure — network error or unexpected server error.
    Unreachable { detail: String },
}

/// Validate the model connection by probing the provider.
///
/// The probe strategy differs by provider:
/// - **OpenAI-compatible**: `GET /models` — an auth-only check that does
///   not send a chat request, avoiding model-format mismatches.
/// - **Anthropic**: `POST /v1/messages` with `max_tokens: 1`.
/// - **Google Gemini**: `GET /models/{model}` metadata endpoint.
///
/// For Copilot providers the optional [`CopilotSession`] is used to
/// exchange the OAuth token for a session token before probing.
///
/// Returns a [`ProbeResult`] that lets the caller distinguish between
/// "fully ready", "connected with a warning", and "hard failure".
pub async fn validate_model_connection(
    http: &reqwest::Client,
    ctx: &ModelContext,
    copilot_session: Option<&CopilotSession>,
) -> ProbeResult {
    // Resolve the bearer token (session token for Copilot, raw key otherwise).
    let effective_key = match resolve_bearer_token(
        http,
        &ctx.provider,
        ctx.api_key.as_deref(),
        copilot_session,
    )
    .await
    {
        Ok(k) => k,
        Err(err) => {
            return ProbeResult::AuthError {
                detail: format!("Token exchange failed: {}", err),
            };
        }
    };

    let result: Result<reqwest::Response> = if ctx.provider == "anthropic" {
        // Anthropic has no /models list endpoint — use a minimal chat.
        let url = format!("{}/v1/messages", ctx.base_url.trim_end_matches('/'));
        let body = json!({
            "model": ctx.model,
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "Hi"}],
        });
        http.post(&url)
            .header("x-api-key", ctx.api_key.as_deref().unwrap_or(""))
            .header("anthropic-version", "2023-06-01")
            .json(&body)
            .send()
            .await
            .context("Probe request to Anthropic failed")
    } else if ctx.provider == "google" {
        // Google: check the model metadata endpoint (no chat needed).
        let key = ctx.api_key.as_deref().unwrap_or("");
        let url = format!(
            "{}/models/{}?key={}",
            ctx.base_url.trim_end_matches('/'),
            ctx.model,
            key,
        );
        http.get(&url)
            .send()
            .await
            .context("Probe request to Google failed")
    } else {
        // OpenAI-compatible: GET /models — lightweight auth check.
        let url = format!("{}/models", ctx.base_url.trim_end_matches('/'));
        let mut builder = http.get(&url);
        if let Some(ref key) = effective_key {
            builder = builder.bearer_auth(key);
        }
        builder = apply_copilot_headers(builder, &ctx.provider);
        builder
            .send()
            .await
            .context("Probe request to provider failed")
    };

    match result {
        Ok(resp) if resp.status().is_success() => ProbeResult::Ready,
        Ok(resp) => {
            let status = resp.status();
            let code = status.as_u16();
            let body = resp.text().await.unwrap_or_default();

            // Try to extract a human-readable error message from JSON.
            let detail = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| {
                    v.get("error")
                        .and_then(|e| e.get("message").or(Some(e)))
                        .and_then(|m| m.as_str().map(String::from))
                })
                .unwrap_or(body);

            match code {
                401 | 403 => ProbeResult::AuthError {
                    detail: format!("{} — {}", status, detail),
                },
                // 400, 404, 422 etc — the server answered, auth is fine,
                // but something about the request/model wasn't accepted.
                // Chat may still work with the full request format.
                400..=499 => ProbeResult::Connected {
                    warning: format!("{} — {}", status, detail),
                },
                _ => ProbeResult::Unreachable {
                    detail: format!("{} — {}", status, detail),
                },
            }
        }
        Err(err) => ProbeResult::Unreachable {
            detail: err.to_string(),
        },
    }
}

// ── Chat protocol types ─────────────────────────────────────────────────────

/// A single message in a chat conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

/// An incoming chat request from the TUI.
///
/// All fields except `messages` and `type` are optional — the gateway fills
/// missing values from its own [`ModelContext`] (resolved at startup).
#[derive(Debug, Deserialize)]
struct ChatRequest {
    /// Must be `"chat"`.
    #[serde(rename = "type")]
    msg_type: String,
    /// Conversation messages (system, user, assistant).
    messages: Vec<ChatMessage>,
    /// Model name (e.g. `"claude-sonnet-4-20250514"`).
    #[serde(default)]
    model: Option<String>,
    /// Provider id (e.g. `"anthropic"`, `"openai"`).
    #[serde(default)]
    provider: Option<String>,
    /// API base URL.
    #[serde(default)]
    base_url: Option<String>,
    /// API key / bearer token (optional for providers like Ollama).
    #[serde(default)]
    api_key: Option<String>,
}

/// Fully-resolved request ready for dispatch to a model provider.
///
/// Created by merging an incoming [`ChatRequest`] with the gateway's
/// [`ModelContext`] defaults.
struct ProviderRequest {
    messages: Vec<ChatMessage>,
    model: String,
    provider: String,
    base_url: String,
    api_key: Option<String>,
}

/// Merge an incoming chat request with the gateway's model context.
///
/// Fields present in the request take priority; missing fields fall back
/// to the gateway defaults.  Returns an error message string if a required
/// field cannot be resolved from either source.
fn resolve_request(
    req: ChatRequest,
    ctx: Option<&ModelContext>,
) -> std::result::Result<ProviderRequest, String> {
    let provider = req
        .provider
        .or_else(|| ctx.map(|c| c.provider.clone()))
        .ok_or_else(|| "No provider specified and gateway has no model configured".to_string())?;
    let model = req
        .model
        .or_else(|| ctx.map(|c| c.model.clone()))
        .ok_or_else(|| "No model specified and gateway has no model configured".to_string())?;
    let base_url = req
        .base_url
        .or_else(|| ctx.map(|c| c.base_url.clone()))
        .ok_or_else(|| "No base_url specified and gateway has no model configured".to_string())?;
    let api_key = req
        .api_key
        .or_else(|| ctx.and_then(|c| c.api_key.clone()));

    Ok(ProviderRequest {
        messages: req.messages,
        model,
        provider,
        base_url,
        api_key,
    })
}

/// Run the gateway WebSocket server.
///
/// Accepts connections in a loop until the `cancel` token is triggered,
/// at which point the server shuts down gracefully.
///
/// The gateway owns the secrets vault (`vault`) — it uses the vault to
/// verify TOTP codes during the WebSocket authentication handshake and
/// to resolve model credentials.  The vault may be in a locked state
/// (password not yet provided); authenticated clients can unlock it via
/// a control message.
///
/// When `model_ctx` is provided the gateway owns the provider credentials
/// and every chat request is resolved against that context.  If `None`,
/// clients must send full `ChatRequest` payloads including provider info.
pub async fn run_gateway(
    config: Config,
    options: GatewayOptions,
    model_ctx: Option<ModelContext>,
    vault: SharedVault,
    skill_mgr: SharedSkillManager,
    cancel: CancellationToken,
) -> Result<()> {
    // Register the credentials directory so file-access tools can enforce
    // the vault boundary (blocks read_file, execute_command, etc.).
    tools::set_credentials_dir(config.credentials_dir());

    let addr = resolve_listen_addr(&options.listen)?;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("Failed to bind gateway to {}", addr))?;

    // If the provider uses Copilot session tokens, wrap the OAuth token in
    // a CopilotSession so all connections share the same cached session.
    let copilot_session: Option<Arc<CopilotSession>> = model_ctx
        .as_ref()
        .filter(|ctx| providers::needs_copilot_session(&ctx.provider))
        .and_then(|ctx| ctx.api_key.clone())
        .map(|oauth| Arc::new(CopilotSession::new(oauth)));

    let model_ctx = model_ctx.map(Arc::new);
    let rate_limiter = new_rate_limiter();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                break;
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let config_clone = config.clone();
                let ctx_clone = model_ctx.clone();
                let session_clone = copilot_session.clone();
                let vault_clone = vault.clone();
                let skill_clone = skill_mgr.clone();
                let limiter_clone = rate_limiter.clone();
                let child_cancel = cancel.child_token();
                tokio::spawn(async move {
                    if let Err(err) = handle_connection(
                        stream, peer, config_clone, ctx_clone,
                        session_clone, vault_clone, skill_clone,
                        limiter_clone, child_cancel,
                    ).await {
                        eprintln!("Gateway connection error from {}: {}", peer, err);
                    }
                });
            }
        }
    }

    Ok(())
}

fn resolve_listen_addr(listen: &str) -> Result<SocketAddr> {
    let trimmed = listen.trim();
    if trimmed.starts_with("ws://") || trimmed.starts_with("wss://") {
        let url = Url::parse(trimmed).context("Invalid WebSocket URL")?;
        let host = url.host_str().context("WebSocket URL missing host")?;
        let port = url
            .port_or_known_default()
            .context("WebSocket URL missing port")?;
        let addr = format!("{}:{}", host, port);
        return addr
            .parse()
            .with_context(|| format!("Invalid listen address {}", addr));
    }

    trimmed
        .parse()
        .with_context(|| format!("Invalid listen address {}", trimmed))
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    config: Config,
    model_ctx: Option<Arc<ModelContext>>,
    copilot_session: Option<Arc<CopilotSession>>,
    vault: SharedVault,
    skill_mgr: SharedSkillManager,
    rate_limiter: RateLimiter,
    cancel: CancellationToken,
) -> Result<()> {
    let ws_stream = tokio_tungstenite::accept_async(stream)
        .await
        .context("WebSocket handshake failed")?;
    let (mut writer, mut reader) = ws_stream.split();
    let peer_ip = peer.ip();

    // ── TOTP authentication challenge ───────────────────────────────
    //
    // If TOTP 2FA is enabled, we require the client to prove identity
    // before granting access to the gateway's capabilities.
    if config.totp_enabled {
        // Check rate limit first.
        if let Some(remaining) = check_rate_limit(&rate_limiter, peer_ip).await {
            let frame = json!({
                "type": "auth_locked",
                "message": format!("Too many failed attempts. Try again in {}s.", remaining),
                "retry_after": remaining,
            });
            writer.send(Message::Text(frame.to_string().into())).await?;
            writer.send(Message::Close(None)).await?;
            return Ok(());
        }

        // Send challenge.
        let challenge = json!({ "type": "auth_challenge", "method": "totp" });
        writer.send(Message::Text(challenge.to_string().into())).await
            .context("Failed to send auth_challenge")?;

        // Wait for auth_response (with a timeout).
        let auth_result = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            wait_for_auth_response(&mut reader),
        )
        .await;

        match auth_result {
            Ok(Ok(code)) => {
                let valid = {
                    let mut v = vault.lock().await;
                    v.verify_totp(code.trim()).unwrap_or(false)
                };
                if valid {
                    clear_rate_limit(&rate_limiter, peer_ip).await;
                    let ok = json!({ "type": "auth_result", "ok": true });
                    writer.send(Message::Text(ok.to_string().into())).await?;
                } else {
                    let locked_out = record_totp_failure(&rate_limiter, peer_ip).await;
                    let msg = if locked_out {
                        format!(
                            "Invalid code. Too many failures — locked out for {}s.",
                            TOTP_LOCKOUT_SECS,
                        )
                    } else {
                        "Invalid 2FA code.".to_string()
                    };
                    let fail = json!({ "type": "auth_result", "ok": false, "message": msg });
                    writer.send(Message::Text(fail.to_string().into())).await?;
                    writer.send(Message::Close(None)).await?;
                    return Ok(());
                }
            }
            Ok(Err(e)) => {
                eprintln!("Auth error from {}: {}", peer, e);
                return Ok(());
            }
            Err(_) => {
                let timeout = json!({
                    "type": "auth_result",
                    "ok": false,
                    "message": "Authentication timed out.",
                });
                let _ = writer.send(Message::Text(timeout.to_string().into())).await;
                let _ = writer.send(Message::Close(None)).await;
                return Ok(());
            }
        }
    }

    // ── Check vault status ──────────────────────────────────────────
    let vault_is_locked = {
        let v = vault.lock().await;
        v.is_locked()
    };

    // ── Send hello ──────────────────────────────────────────────────
    let mut hello = json!({
        "type": "hello",
        "agent": "rustyclaw",
        "settings_dir": config.settings_dir,
        "vault_locked": vault_is_locked,
    });
    if let Some(ref ctx) = model_ctx {
        hello["provider"] = serde_json::Value::String(ctx.provider.clone());
        hello["model"] = serde_json::Value::String(ctx.model.clone());
    }
    writer
        .send(Message::Text(hello.to_string().into()))
        .await
        .context("Failed to send hello message")?;

    if vault_is_locked {
        writer
            .send(Message::Text(
                status_frame("vault_locked", "Secrets vault is locked — provide password to unlock")
                    .into(),
            ))
            .await
            .context("Failed to send vault_locked status")?;
    }

    // ── Report model status to the freshly-connected client ────────
    let http = reqwest::Client::new();

    match model_ctx {
        Some(ref ctx) => {
            let display = providers::display_name_for_provider(&ctx.provider);

            // 1. Model configured
            let detail = format!("{} / {}", display, ctx.model);
            writer
                .send(Message::Text(
                    status_frame("model_configured", &detail).into(),
                ))
                .await
                .context("Failed to send model_configured status")?;

            // 2. Credentials
            if ctx.api_key.is_some() {
                writer
                    .send(Message::Text(
                        status_frame("credentials_loaded", &format!("{} API key loaded", display))
                            .into(),
                    ))
                    .await
                    .context("Failed to send credentials_loaded status")?;
            } else if providers::secret_key_for_provider(&ctx.provider).is_some() {
                writer
                    .send(Message::Text(
                        status_frame(
                            "credentials_missing",
                            &format!("No API key for {} — model calls will fail", display),
                        )
                        .into(),
                    ))
                    .await
                    .context("Failed to send credentials_missing status")?;
            }

            // 3. Validate the connection with a lightweight probe
            //
            // For Copilot providers, exchange the OAuth token for a session
            // token first — the probe must use the session token too.
            writer
                .send(Message::Text(
                    status_frame("model_connecting", &format!("Probing {} …", ctx.base_url))
                        .into(),
                ))
                .await
                .context("Failed to send model_connecting status")?;

            match validate_model_connection(&http, ctx, copilot_session.as_deref()).await {
                ProbeResult::Ready => {
                    writer
                        .send(Message::Text(
                            status_frame(
                                "model_ready",
                                &format!("{} / {} ready", display, ctx.model),
                            )
                            .into(),
                        ))
                        .await
                        .context("Failed to send model_ready status")?;
                }
                ProbeResult::Connected { warning } => {
                    // Auth is fine, provider is reachable — the specific
                    // probe request wasn't accepted, but chat will likely
                    // work with the real request format.
                    writer
                        .send(Message::Text(
                            status_frame(
                                "model_ready",
                                &format!("{} / {} connected (probe: {})", display, ctx.model, warning),
                            )
                            .into(),
                        ))
                        .await
                        .context("Failed to send model_ready status")?;
                }
                ProbeResult::AuthError { detail } => {
                    writer
                        .send(Message::Text(
                            status_frame(
                                "model_error",
                                &format!("{} auth failed: {}", display, detail),
                            )
                            .into(),
                        ))
                        .await
                        .context("Failed to send model_error status")?;
                }
                ProbeResult::Unreachable { detail } => {
                    writer
                        .send(Message::Text(
                            status_frame(
                                "model_error",
                                &format!("{} probe failed: {}", display, detail),
                            )
                            .into(),
                        ))
                        .await
                        .context("Failed to send model_error status")?;
                }
            }
        }
        None => {
            writer
                .send(Message::Text(
                    status_frame(
                        "no_model",
                        "No model configured — clients must send full credentials",
                    )
                    .into(),
                ))
                .await
                .context("Failed to send no_model status")?;
        }
    }

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                let _ = writer.send(Message::Close(None)).await;
                break;
            }
            msg = reader.next() => {
                let message = match msg {
                    Some(Ok(m)) => m,
                    Some(Err(e)) => return Err(e.into()),
                    None => break,
                };
                match message {
                    Message::Text(text) => {
                        // ── Handle unlock_vault control message ─────
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(text.as_str()) {
                            if val.get("type").and_then(|t| t.as_str()) == Some("unlock_vault") {
                                if let Some(pw) = val.get("password").and_then(|p| p.as_str()) {
                                    let mut v = vault.lock().await;
                                    v.set_password(pw.to_string());
                                    // Try to access the vault to verify the password works.
                                    // get_secret returns Err if the vault cannot be decrypted.
                                    match v.get_secret("__vault_check__", true) {
                                        Ok(_) => {
                                            let ok = json!({
                                                "type": "vault_unlocked",
                                                "ok": true,
                                            });
                                            let _ = writer.send(Message::Text(ok.to_string().into())).await;
                                        }
                                        Err(e) => {
                                            // Revert to locked state.
                                            v.clear_password();
                                            let fail = json!({
                                                "type": "vault_unlocked",
                                                "ok": false,
                                                "message": format!("Failed to unlock vault: {}", e),
                                            });
                                            let _ = writer.send(Message::Text(fail.to_string().into())).await;
                                        }
                                    }
                                }
                                continue;
                            }
                        }

                        let workspace_dir = config.workspace_dir();
                        if let Err(err) = dispatch_text_message(
                            &http,
                            text.as_str(),
                            model_ctx.as_deref(),
                            copilot_session.as_deref(),
                            &mut writer,
                            &workspace_dir,
                            &vault,
                            &skill_mgr,
                        )
                        .await
                        {
                            let frame = json!({
                                "type": "error",
                                "ok": false,
                                "message": err.to_string(),
                            });
                            let _ = writer
                                .send(Message::Text(frame.to_string().into()))
                                .await;
                        }
                    }
                    Message::Binary(_) => {
                        let response = json!({
                            "type": "error",
                            "ok": false,
                            "message": "Binary frames are not supported",
                        });
                        writer
                            .send(Message::Text(response.to_string().into()))
                            .await
                            .context("Failed to send error response")?;
                    }
                    Message::Close(_) => {
                        break;
                    }
                    Message::Ping(payload) => {
                        writer.send(Message::Pong(payload)).await?;
                    }
                    Message::Pong(_) => {}
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

/// Wait for an `auth_response` frame from the client.
///
/// Reads WebSocket messages until we get a JSON frame with
/// `{"type": "auth_response", "code": "..."}` or the connection drops.
async fn wait_for_auth_response(
    reader: &mut futures_util::stream::SplitStream<WebSocketStream<tokio::net::TcpStream>>,
) -> Result<String> {
    while let Some(msg) = reader.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(text.as_str()) {
                    if val.get("type").and_then(|t| t.as_str()) == Some("auth_response") {
                        if let Some(code) = val.get("code").and_then(|c| c.as_str()) {
                            return Ok(code.to_string());
                        }
                        anyhow::bail!("auth_response missing 'code' field");
                    }
                }
                // Ignore non-auth frames during the handshake.
            }
            Ok(Message::Close(_)) => {
                anyhow::bail!("Client disconnected during authentication");
            }
            Err(e) => {
                anyhow::bail!("WebSocket error during authentication: {}", e);
            }
            _ => {} // Ignore ping/pong/binary during auth
        }
    }
    anyhow::bail!("Connection closed before authentication completed")
}

/// Execute a secrets-vault tool against the shared vault.
///
/// These are intercepted before the generic `tools::execute_tool` path
/// because they require `SharedVault` access — the normal tool signature
/// only receives `(args, workspace_dir)`.
///
/// Access control is delegated entirely to [`SecretsManager::check_access`]
/// and the per-credential [`AccessPolicy`].  The agent gets an
/// [`AccessContext`] with `user_approved = false` (the tool invocation
/// itself does not constitute user approval) and `authenticated = false`
/// (no re-auth has occurred).  This means:
///
/// - `Always` credentials are readable.
/// - `WithApproval` credentials are only readable if `agent_access_enabled`
///   is set in config.
/// - `WithAuth` and `SkillOnly` credentials are denied.
async fn execute_secrets_tool(
    name: &str,
    args: &serde_json::Value,
    vault: &SharedVault,
) -> Result<String, String> {
    match name {
        "secrets_list" => exec_secrets_list(vault).await,
        "secrets_get" => exec_secrets_get(args, vault).await,
        "secrets_store" => exec_secrets_store(args, vault).await,
        _ => Err(format!("Unknown secrets tool: {}", name)),
    }
}

/// List all credentials in the vault (names, kinds, policies — no values).
async fn exec_secrets_list(vault: &SharedVault) -> Result<String, String> {
    let mut mgr = vault.lock().await;
    let entries = mgr.list_all_entries();

    if entries.is_empty() {
        return Ok("No credentials stored in the vault.".into());
    }

    let mut lines = Vec::with_capacity(entries.len() + 1);
    lines.push(format!("{} credential(s) in vault:\n", entries.len()));

    for (name, entry) in &entries {
        let disabled = if entry.disabled { " [DISABLED]" } else { "" };
        let desc = entry
            .description
            .as_deref()
            .map(|d| format!(" — {}", d))
            .unwrap_or_default();
        lines.push(format!(
            "  • {} ({}, policy: {}){}{}\n",
            name, entry.kind, entry.policy, disabled, desc,
        ));
    }

    Ok(lines.join(""))
}

/// Retrieve a single credential value from the vault.
async fn exec_secrets_get(
    args: &serde_json::Value,
    vault: &SharedVault,
) -> Result<String, String> {
    let cred_name = args
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter: name".to_string())?;

    let ctx = AccessContext {
        user_approved: false,
        authenticated: false,
        active_skill: None,
    };

    let mut mgr = vault.lock().await;
    match mgr.get_credential(cred_name, &ctx) {
        Ok(Some((entry, value))) => {
            Ok(format_credential_value(cred_name, &entry, &value))
        }
        Ok(None) => Err(format!(
            "Credential '{}' not found. Use secrets_list to see available credentials.",
            cred_name,
        )),
        Err(e) => Err(e.to_string()),
    }
}

/// Format a credential value for returning to the model.
fn format_credential_value(
    name: &str,
    entry: &SecretEntry,
    value: &CredentialValue,
) -> String {
    match value {
        CredentialValue::Single(v) => {
            format!("[{}] {} = {}", entry.kind, name, v)
        }
        CredentialValue::UserPass { username, password } => {
            format!(
                "[{}] {}\n  username: {}\n  password: {}",
                entry.kind, name, username, password,
            )
        }
        CredentialValue::SshKeyPair { private_key, public_key } => {
            format!(
                "[{}] {}\n  public_key: {}\n  private_key: <{} chars>",
                entry.kind,
                name,
                public_key,
                private_key.len(),
            )
        }
        CredentialValue::FormFields(fields) => {
            let mut out = format!("[{}] {}\n", entry.kind, name);
            for (k, v) in fields {
                out.push_str(&format!("  {}: {}\n", k, v));
            }
            out
        }
        CredentialValue::PaymentCard {
            cardholder,
            number,
            expiry,
            cvv,
            extra,
        } => {
            let mut out = format!(
                "[{}] {}\n  cardholder: {}\n  number: {}\n  expiry: {}\n  cvv: {}",
                entry.kind, name, cardholder, number, expiry, cvv,
            );
            for (k, v) in extra {
                out.push_str(&format!("\n  {}: {}", k, v));
            }
            out
        }
    }
}

/// Store a new credential in the vault.
async fn exec_secrets_store(
    args: &serde_json::Value,
    vault: &SharedVault,
) -> Result<String, String> {
    let cred_name = args
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter: name".to_string())?;

    let kind_str = args
        .get("kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter: kind".to_string())?;

    let value = args
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter: value".to_string())?;

    let description = args
        .get("description")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let username = args.get("username").and_then(|v| v.as_str());

    let kind = match kind_str {
        "api_key" => SecretKind::ApiKey,
        "token" => SecretKind::Token,
        "username_password" => SecretKind::UsernamePassword,
        "ssh_key" => SecretKind::SshKey,
        "secure_note" => SecretKind::SecureNote,
        "http_passkey" => SecretKind::HttpPasskey,
        "form_autofill" => SecretKind::FormAutofill,
        "payment_method" => SecretKind::PaymentMethod,
        "other" => SecretKind::Other,
        _ => {
            return Err(format!(
                "Unknown credential kind: '{}'. Use one of: api_key, token, \
                 username_password, ssh_key, secure_note, http_passkey, \
                 form_autofill, payment_method, other.",
                kind_str,
            ));
        }
    };

    if kind == SecretKind::UsernamePassword && username.is_none() {
        return Err(
            "username_password credentials require the 'username' parameter.".into(),
        );
    }

    let entry = SecretEntry {
        label: cred_name.to_string(),
        kind,
        policy: AccessPolicy::default(), // WithApproval
        description,
        disabled: false,
    };

    let mut mgr = vault.lock().await;
    mgr.store_credential(cred_name, &entry, value, username)
        .map_err(|e| format!("Failed to store credential: {}", e))?;

    Ok(format!(
        "Credential '{}' stored successfully (kind: {}, policy: {}).",
        cred_name, entry.kind, entry.policy,
    ))
}

// ── Skill tool execution (gateway-side) ─────────────────────────────────────

/// Dispatch a skill management tool call.
///
/// Like `execute_secrets_tool`, these tools bypass the normal
/// `tools::execute_tool` path because they need access to the shared
/// `SkillManager` that lives in the gateway process.
async fn execute_skill_tool(
    name: &str,
    args: &serde_json::Value,
    skill_mgr: &SharedSkillManager,
) -> Result<String, String> {
    match name {
        "skill_list" => exec_gw_skill_list(args, skill_mgr).await,
        "skill_search" => exec_gw_skill_search(args, skill_mgr).await,
        "skill_install" => exec_gw_skill_install(args, skill_mgr).await,
        "skill_info" => exec_gw_skill_info(args, skill_mgr).await,
        "skill_enable" => exec_gw_skill_enable(args, skill_mgr).await,
        "skill_link_secret" => exec_gw_skill_link_secret(args, skill_mgr).await,
        _ => Err(format!("Unknown skill tool: {}", name)),
    }
}

/// List all loaded skills, optionally filtered.
async fn exec_gw_skill_list(
    args: &serde_json::Value,
    skill_mgr: &SharedSkillManager,
) -> Result<String, String> {
    let filter = args
        .get("filter")
        .and_then(|v| v.as_str())
        .unwrap_or("all");

    let mgr = skill_mgr.lock().await;
    let skills = mgr.get_skills();

    if skills.is_empty() {
        return Ok("No skills loaded.".into());
    }

    let filtered: Vec<_> = skills
        .iter()
        .filter(|s| match filter {
            "enabled" => s.enabled,
            "disabled" => !s.enabled,
            "registry" => matches!(s.source, crate::skills::SkillSource::Registry { .. }),
            _ => true, // "all"
        })
        .collect();

    if filtered.is_empty() {
        return Ok(format!("No skills match filter '{}'.", filter));
    }

    let mut lines = Vec::with_capacity(filtered.len() + 1);
    lines.push(format!("{} skill(s):\n", filtered.len()));
    for s in &filtered {
        let status = if s.enabled { "✓" } else { "✗" };
        let source = match &s.source {
            crate::skills::SkillSource::Local => "local".to_string(),
            crate::skills::SkillSource::Registry { version, .. } => {
                format!("registry v{}", version)
            }
        };
        let secrets = if s.linked_secrets.is_empty() {
            String::new()
        } else {
            format!(" [secrets: {}]", s.linked_secrets.join(", "))
        };
        lines.push(format!(
            "  {} {} ({}) — {}{}\n",
            status,
            s.name,
            source,
            s.description.as_deref().unwrap_or("(no description)"),
            secrets,
        ));
    }
    Ok(lines.join(""))
}

/// Search the ClawHub registry.
async fn exec_gw_skill_search(
    args: &serde_json::Value,
    skill_mgr: &SharedSkillManager,
) -> Result<String, String> {
    let query = args
        .get("query")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter: query".to_string())?;

    let mgr = skill_mgr.lock().await;
    let results = mgr.search_registry(query).map_err(|e| e.to_string())?;

    if results.is_empty() {
        return Ok(format!("No skills found matching '{}'.", query));
    }

    let mut lines = Vec::with_capacity(results.len() + 1);
    lines.push(format!("{} result(s) for '{}':\n", results.len(), query));
    for r in &results {
        let secrets_note = if r.required_secrets.is_empty() {
            String::new()
        } else {
            format!(" (needs: {})", r.required_secrets.join(", "))
        };
        lines.push(format!(
            "  • {} v{} by {} — {}{}\n",
            r.name, r.version, r.author, r.description, secrets_note,
        ));
    }
    Ok(lines.join(""))
}

/// Install a skill from the ClawHub registry.
async fn exec_gw_skill_install(
    args: &serde_json::Value,
    skill_mgr: &SharedSkillManager,
) -> Result<String, String> {
    let name = args
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter: name".to_string())?;
    let version = args.get("version").and_then(|v| v.as_str());

    let mut mgr = skill_mgr.lock().await;
    mgr.install_from_registry(name, version).map_err(|e| e.to_string())?;

    // Reload skills so the new one is available immediately.
    mgr.load_skills().map_err(|e| e.to_string())?;

    let version_note = version
        .map(|v| format!(" v{}", v))
        .unwrap_or_else(|| " (latest)".into());
    Ok(format!(
        "Skill '{}'{} installed from ClawHub and loaded.",
        name, version_note,
    ))
}

/// Show detailed information about a skill.
async fn exec_gw_skill_info(
    args: &serde_json::Value,
    skill_mgr: &SharedSkillManager,
) -> Result<String, String> {
    let name = args
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter: name".to_string())?;

    let mgr = skill_mgr.lock().await;
    mgr.skill_info(name)
        .ok_or_else(|| format!("Skill '{}' not found.", name))
}

/// Enable or disable a skill.
async fn exec_gw_skill_enable(
    args: &serde_json::Value,
    skill_mgr: &SharedSkillManager,
) -> Result<String, String> {
    let name = args
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter: name".to_string())?;
    let enabled = args
        .get("enabled")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| "Missing required parameter: enabled".to_string())?;

    let mut mgr = skill_mgr.lock().await;
    mgr.set_skill_enabled(name, enabled)
        .map_err(|e| e.to_string())?;

    let state = if enabled { "enabled" } else { "disabled" };
    Ok(format!("Skill '{}' is now {}.", name, state))
}

/// Link or unlink a vault credential to a skill.
async fn exec_gw_skill_link_secret(
    args: &serde_json::Value,
    skill_mgr: &SharedSkillManager,
) -> Result<String, String> {
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter: action".to_string())?;
    let skill = args
        .get("skill")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter: skill".to_string())?;
    let secret = args
        .get("secret")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter: secret".to_string())?;

    let mut mgr = skill_mgr.lock().await;
    match action {
        "link" => {
            mgr.link_secret(skill, secret).map_err(|e| e.to_string())?;
            Ok(format!(
                "Secret '{}' linked to skill '{}'.",
                secret, skill,
            ))
        }
        "unlink" => {
            mgr.unlink_secret(skill, secret).map_err(|e| e.to_string())?;
            Ok(format!(
                "Secret '{}' unlinked from skill '{}'.",
                secret, skill,
            ))
        }
        _ => Err(format!(
            "Unknown action '{}'. Use 'link' or 'unlink'.",
            action,
        )),
    }
}

/// Route an incoming text frame to the appropriate handler.
///
/// Implements an agentic tool loop: the model is called, and if it
/// requests tool calls, the gateway executes them locally and feeds
/// the results back into the conversation, repeating until the model
/// produces a final text response (or a safety limit is hit).
async fn dispatch_text_message(
    http: &reqwest::Client,
    text: &str,
    model_ctx: Option<&ModelContext>,
    copilot_session: Option<&CopilotSession>,
    writer: &mut WsWriter,
    workspace_dir: &std::path::Path,
    vault: &SharedVault,
    skill_mgr: &SharedSkillManager,
) -> Result<()> {
    // Try to parse as a structured JSON request.
    let req = match serde_json::from_str::<ChatRequest>(text) {
        Ok(r) if r.msg_type == "chat" => r,
        Ok(r) => {
            let frame = json!({
                "type": "error",
                "ok": false,
                "message": format!("Unknown message type: {:?}", r.msg_type),
            });
            writer
                .send(Message::Text(frame.to_string().into()))
                .await
                .context("Failed to send error frame")?;
            return Ok(());
        }
        Err(err) => {
            let frame = json!({
                "type": "error",
                "ok": false,
                "message": format!("Invalid JSON: {}", err),
            });
            writer
                .send(Message::Text(frame.to_string().into()))
                .await
                .context("Failed to send error frame")?;
            return Ok(());
        }
    };

    let mut resolved = match resolve_request(req, model_ctx) {
        Ok(r) => r,
        Err(msg) => {
            let frame = json!({ "type": "error", "ok": false, "message": msg });
            writer
                .send(Message::Text(frame.to_string().into()))
                .await
                .context("Failed to send error frame")?;
            return Ok(());
        }
    };

    // For Copilot providers, swap the raw OAuth token for a session token.
    match resolve_bearer_token(
        http,
        &resolved.provider,
        resolved.api_key.as_deref(),
        copilot_session,
    )
    .await
    {
        Ok(token) => resolved.api_key = token,
        Err(err) => {
            let frame = json!({
                "type": "error",
                "ok": false,
                "message": format!("Token exchange failed: {}", err),
            });
            writer
                .send(Message::Text(frame.to_string().into()))
                .await
                .context("Failed to send error frame")?;
            return Ok(());
        }
    }

    // ── Agentic tool loop ───────────────────────────────────────────
    const MAX_TOOL_ROUNDS: usize = 25;

    let context_limit = context_window_for_model(&resolved.model);

    for _round in 0..MAX_TOOL_ROUNDS {
        // ── Auto-compact if context is getting large ────────────────
        let estimated = estimate_tokens(&resolved.messages);
        let threshold = (context_limit as f64 * COMPACTION_THRESHOLD) as usize;
        if estimated > threshold {
            match compact_conversation(
                http,
                &mut resolved,
                context_limit,
                writer,
            )
            .await
            {
                Ok(()) => {} // compacted in-place
                Err(err) => {
                    // Non-fatal — log a warning and keep going with the
                    // full context; the provider may still accept it.
                    let warn_frame = json!({
                        "type": "info",
                        "message": format!("Context compaction failed: {}", err),
                    });
                    let _ = writer
                        .send(Message::Text(warn_frame.to_string().into()))
                        .await;
                }
            }
        }

        let result = if resolved.provider == "anthropic" {
            call_anthropic_with_tools(http, &resolved).await
        } else if resolved.provider == "google" {
            call_google_with_tools(http, &resolved).await
        } else {
            call_openai_with_tools(http, &resolved).await
        };

        let model_resp = match result {
            Ok(r) => r,
            Err(err) => {
                let frame = json!({
                    "type": "error",
                    "ok": false,
                    "message": err.to_string(),
                });
                writer
                    .send(Message::Text(frame.to_string().into()))
                    .await
                    .context("Failed to send error frame")?;
                return Ok(());
            }
        };

        // Stream any text content to the client.
        if !model_resp.text.is_empty() {
            send_chunk(writer, &model_resp.text).await?;
        }

        if model_resp.tool_calls.is_empty() {
            // No tool calls — the model is done.
            send_response_done(writer).await?;
            return Ok(());
        }

        // ── Execute each requested tool ─────────────────────────────
        let mut tool_results: Vec<ToolCallResult> = Vec::new();

        for tc in &model_resp.tool_calls {
            // Notify the client about the tool call.
            let call_frame = json!({
                "type": "tool_call",
                "id": tc.id,
                "name": tc.name,
                "arguments": tc.arguments,
            });
            writer
                .send(Message::Text(call_frame.to_string().into()))
                .await
                .context("Failed to send tool_call frame")?;

            // Execute the tool.
            let (output, is_error) = if tools::is_secrets_tool(&tc.name) {
                // Secrets tools are handled here — they need vault access.
                match execute_secrets_tool(&tc.name, &tc.arguments, vault).await {
                    Ok(text) => (text, false),
                    Err(err) => (err, true),
                }
            } else if tools::is_skill_tool(&tc.name) {
                // Skill tools are handled here — they need SkillManager access.
                match execute_skill_tool(&tc.name, &tc.arguments, skill_mgr).await {
                    Ok(text) => (text, false),
                    Err(err) => (err, true),
                }
            } else {
                match tools::execute_tool(&tc.name, &tc.arguments, workspace_dir) {
                    Ok(text) => (text, false),
                    Err(err) => (err, true),
                }
            };

            // Notify the client about the result.
            let result_frame = json!({
                "type": "tool_result",
                "id": tc.id,
                "name": tc.name,
                "result": output,
                "is_error": is_error,
            });
            writer
                .send(Message::Text(result_frame.to_string().into()))
                .await
                .context("Failed to send tool_result frame")?;

            tool_results.push(ToolCallResult {
                id: tc.id.clone(),
                name: tc.name.clone(),
                output,
                is_error,
            });
        }

        // ── Append assistant + tool-result messages to conversation ──
        // The model's response (possibly with text + tool calls) becomes
        // an assistant message, and each tool result becomes a tool message.
        append_tool_round(
            &resolved.provider,
            &mut resolved.messages,
            &model_resp,
            &tool_results,
        );
    }

    // If we exhausted all rounds, send what we have and stop.
    let frame = json!({
        "type": "error",
        "ok": false,
        "message": "Tool loop limit reached — stopping.",
    });
    writer
        .send(Message::Text(frame.to_string().into()))
        .await
        .context("Failed to send error frame")?;
    send_response_done(writer).await?;
    Ok(())
}

// ── Streaming helpers ───────────────────────────────────────────────────────

/// Send a single `{"type": "chunk", "delta": "..."}` frame.
async fn send_chunk(writer: &mut WsWriter, delta: &str) -> Result<()> {
    let frame = json!({ "type": "chunk", "delta": delta });
    writer
        .send(Message::Text(frame.to_string().into()))
        .await
        .context("Failed to send chunk frame")
}

/// Send the `{"type": "response_done"}` sentinel frame.
async fn send_response_done(writer: &mut WsWriter) -> Result<()> {
    let frame = json!({ "type": "response_done", "ok": true });
    writer
        .send(Message::Text(frame.to_string().into()))
        .await
        .context("Failed to send response_done frame")
}

// ── Context compaction ──────────────────────────────────────────────────────

/// Compact the conversation by summarizing older turns.
///
/// Strategy:
/// 1. Keep the system prompt (first message if role == "system").
/// 2. Keep the most recent turns that fit in COMPACTION_TARGET of the window.
/// 3. Ask the model to produce a concise summary of the middle (old) turns.
/// 4. Replace those old turns with a single assistant "summary" message.
///
/// This modifies `resolved.messages` in-place.
async fn compact_conversation(
    http: &reqwest::Client,
    resolved: &mut ProviderRequest,
    context_limit: usize,
    writer: &mut WsWriter,
) -> Result<()> {
    let msgs = &resolved.messages;
    if msgs.len() < 4 {
        // Too few messages to compact meaningfully.
        return Ok(());
    }

    // Separate system prompt from the rest.
    let has_system = msgs.first().is_some_and(|m| m.role == "system");
    let start_idx = if has_system { 1 } else { 0 };

    // Walk backwards to find how many recent turns fit in the target budget.
    let target_tokens = (context_limit as f64 * COMPACTION_TARGET) as usize;
    let mut tail_tokens = 0usize;
    let mut keep_from = msgs.len(); // index where "recent" messages start
    for i in (start_idx..msgs.len()).rev() {
        let msg_tokens = (msgs[i].role.len() + msgs[i].content.len()) / 3;
        if tail_tokens + msg_tokens > target_tokens {
            break;
        }
        tail_tokens += msg_tokens;
        keep_from = i;
    }

    // The middle section to summarize: everything between system and keep_from.
    if keep_from <= start_idx + 1 {
        // Nothing meaningful to summarize.
        return Ok(());
    }

    let old_turns = &msgs[start_idx..keep_from];

    // Build a summary prompt.
    let mut summary_text = String::from(
        "Summarize the following conversation turns into a concise context recap. \
         Preserve key facts, decisions, file paths, tool results, and user preferences. \
         Keep it under 500 words. Output only the summary, no preamble.\n\n",
    );
    for m in old_turns {
        // Truncate very large tool results to avoid blowing up the summary request.
        let content = if m.content.len() > 2000 {
            format!("{}… [truncated]", &m.content[..2000])
        } else {
            m.content.clone()
        };
        summary_text.push_str(&format!("[{}]: {}\n\n", m.role, content));
    }

    // Call the model to produce the summary (simple request, no tools).
    let summary_req = ProviderRequest {
        messages: vec![ChatMessage {
            role: "user".into(),
            content: summary_text,
        }],
        model: resolved.model.clone(),
        provider: resolved.provider.clone(),
        base_url: resolved.base_url.clone(),
        api_key: resolved.api_key.clone(),
    };

    let summary_result = if resolved.provider == "anthropic" {
        call_anthropic_with_tools(http, &summary_req).await
    } else if resolved.provider == "google" {
        call_google_with_tools(http, &summary_req).await
    } else {
        call_openai_with_tools(http, &summary_req).await
    };

    let summary = match summary_result {
        Ok(resp) if !resp.text.is_empty() => resp.text,
        Ok(_) => anyhow::bail!("Model returned empty summary"),
        Err(e) => anyhow::bail!("Summary request failed: {}", e),
    };

    // Rebuild messages: system + summary + recent turns.
    let mut new_messages = Vec::new();
    if has_system {
        new_messages.push(msgs[0].clone());
    }
    new_messages.push(ChatMessage {
        role: "assistant".into(),
        content: format!(
            "[Conversation summary — older messages were compacted to save context]\n\n{}",
            summary,
        ),
    });
    new_messages.extend_from_slice(&msgs[keep_from..]);

    let old_count = msgs.len();
    let new_count = new_messages.len();
    let old_tokens = estimate_tokens(msgs);
    let new_tokens = estimate_tokens(&new_messages);

    resolved.messages = new_messages;

    // Notify the client.
    let info_frame = json!({
        "type": "info",
        "message": format!(
            "Context compacted: {} → {} messages (~{}k → ~{}k tokens)",
            old_count,
            new_count,
            old_tokens / 1000,
            new_tokens / 1000,
        ),
    });
    writer
        .send(Message::Text(info_frame.to_string().into()))
        .await
        .context("Failed to send compaction info frame")?;

    Ok(())
}

// ── Model response types (shared across providers) ──────────────────────────

/// A parsed tool call from the model.
#[derive(Debug, Clone)]
struct ParsedToolCall {
    id: String,
    name: String,
    arguments: serde_json::Value,
}

/// The result of executing a tool locally.
#[derive(Debug, Clone)]
struct ToolCallResult {
    id: String,
    name: String,
    output: String,
    is_error: bool,
}

/// A complete model response: optional text + optional tool calls.
#[derive(Debug, Default)]
struct ModelResponse {
    text: String,
    tool_calls: Vec<ParsedToolCall>,
    /// Token counts reported by the provider (when available).
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
}

/// Append the model's assistant turn and tool results to the conversation
/// so the next round has full context.
fn append_tool_round(
    provider: &str,
    messages: &mut Vec<ChatMessage>,
    model_resp: &ModelResponse,
    results: &[ToolCallResult],
) {
    if provider == "anthropic" {
        // Anthropic: assistant message has content blocks (text + tool_use),
        // then one "user" message with tool_result blocks.
        let mut content_blocks = Vec::new();
        if !model_resp.text.is_empty() {
            content_blocks.push(json!({ "type": "text", "text": model_resp.text }));
        }
        for tc in &model_resp.tool_calls {
            content_blocks.push(json!({
                "type": "tool_use",
                "id": tc.id,
                "name": tc.name,
                "input": tc.arguments,
            }));
        }
        messages.push(ChatMessage {
            role: "assistant".into(),
            content: serde_json::to_string(&content_blocks).unwrap_or_default(),
        });

        let mut result_blocks = Vec::new();
        for r in results {
            result_blocks.push(json!({
                "type": "tool_result",
                "tool_use_id": r.id,
                "content": r.output,
                "is_error": r.is_error,
            }));
        }
        messages.push(ChatMessage {
            role: "user".into(),
            content: serde_json::to_string(&result_blocks).unwrap_or_default(),
        });
    } else if provider == "google" {
        // Google: model turn with function calls, then user turn with function responses.
        let mut parts = Vec::new();
        if !model_resp.text.is_empty() {
            parts.push(json!({ "text": model_resp.text }));
        }
        for tc in &model_resp.tool_calls {
            parts.push(json!({
                "functionCall": { "name": tc.name, "args": tc.arguments }
            }));
        }
        messages.push(ChatMessage {
            role: "assistant".into(),
            content: serde_json::to_string(&parts).unwrap_or_default(),
        });

        let mut resp_parts = Vec::new();
        for r in results {
            resp_parts.push(json!({
                "functionResponse": {
                    "name": r.name,
                    "response": { "content": r.output, "is_error": r.is_error }
                }
            }));
        }
        messages.push(ChatMessage {
            role: "user".into(),
            content: serde_json::to_string(&resp_parts).unwrap_or_default(),
        });
    } else {
        // OpenAI-compatible: assistant message with tool_calls array,
        // then one "tool" message per result.
        let tc_array: Vec<serde_json::Value> = model_resp
            .tool_calls
            .iter()
            .map(|tc| {
                json!({
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.name,
                        "arguments": serde_json::to_string(&tc.arguments).unwrap_or_default(),
                    }
                })
            })
            .collect();

        // The assistant message carries both text and tool_calls.
        let assistant_json = json!({
            "role": "assistant",
            "content": if model_resp.text.is_empty() { serde_json::Value::Null } else { json!(model_resp.text) },
            "tool_calls": tc_array,
        });
        messages.push(ChatMessage {
            role: "assistant".into(),
            content: serde_json::to_string(&assistant_json).unwrap_or_default(),
        });

        for r in results {
            messages.push(ChatMessage {
                role: "tool".into(),
                content: json!({
                    "role": "tool",
                    "tool_call_id": r.id,
                    "content": r.output,
                })
                .to_string(),
            });
        }
    }
}

// ── Provider-specific callers ───────────────────────────────────────────────

/// Attach GitHub-Copilot-required IDE headers to a request builder.
fn apply_copilot_headers(
    builder: reqwest::RequestBuilder,
    provider: &str,
) -> reqwest::RequestBuilder {
    if !providers::needs_copilot_session(provider) {
        return builder;
    }
    let version = env!("CARGO_PKG_VERSION");
    builder
        .header("Editor-Version", format!("RustyClaw/{}", version))
        .header("Editor-Plugin-Version", format!("rustyclaw/{}", version))
        .header("Copilot-Integration-Id", "rustyclaw")
        .header("openai-intent", "conversation-panel")
}

// ── OpenAI-compatible ───────────────────────────────────────────────────────

/// Call an OpenAI-compatible `/chat/completions` endpoint (non-streaming)
/// with tool definitions.  Returns structured text + tool calls.
async fn call_openai_with_tools(
    http: &reqwest::Client,
    req: &ProviderRequest,
) -> Result<ModelResponse> {
    let url = format!("{}/chat/completions", req.base_url.trim_end_matches('/'));

    // Build the messages array.  Most messages are simple role+content,
    // but tool-loop continuation messages have structured JSON content
    // that must be sent as raw objects rather than string-escaped.
    let messages: Vec<serde_json::Value> = req
        .messages
        .iter()
        .map(|m| {
            // Try to parse content as JSON first (for assistant messages
            // with tool_calls and tool-result messages).
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&m.content) {
                if parsed.is_object() && parsed.get("role").is_some() {
                    return parsed;
                }
            }
            json!({ "role": m.role, "content": m.content })
        })
        .collect();

    let tool_defs = tools::tools_openai();

    let mut body = json!({
        "model": req.model,
        "messages": messages,
    });
    if !tool_defs.is_empty() {
        body["tools"] = json!(tool_defs);
    }

    let mut builder = http.post(&url).json(&body);
    if let Some(ref key) = req.api_key {
        builder = builder.bearer_auth(key);
    }
    builder = apply_copilot_headers(builder, &req.provider);

    let resp = builder
        .send()
        .await
        .context("HTTP request to model provider failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Provider returned {} — {}", status, text);
    }

    let data: serde_json::Value = resp
        .json()
        .await
        .context("Invalid JSON from provider")?;

    let choice = &data["choices"][0];
    let message = &choice["message"];

    let mut result = ModelResponse::default();

    // Extract text content.
    if let Some(text) = message["content"].as_str() {
        result.text = text.to_string();
    }

    // Extract tool calls.
    if let Some(tc_array) = message["tool_calls"].as_array() {
        for tc in tc_array {
            let id = tc["id"].as_str().unwrap_or("").to_string();
            let name = tc["function"]["name"].as_str().unwrap_or("").to_string();
            let args_str = tc["function"]["arguments"].as_str().unwrap_or("{}");
            let arguments = serde_json::from_str(args_str).unwrap_or(json!({}));
            result.tool_calls.push(ParsedToolCall {
                id,
                name,
                arguments,
            });
        }
    }

    // Extract token usage if present.
    if let Some(usage) = data.get("usage") {
        result.prompt_tokens = usage["prompt_tokens"].as_u64();
        result.completion_tokens = usage["completion_tokens"].as_u64();
    }

    Ok(result)
}

// ── Anthropic ───────────────────────────────────────────────────────────────

/// Call the Anthropic Messages API with tool definitions (non-streaming).
async fn call_anthropic_with_tools(
    http: &reqwest::Client,
    req: &ProviderRequest,
) -> Result<ModelResponse> {
    let url = format!("{}/v1/messages", req.base_url.trim_end_matches('/'));

    let system = req
        .messages
        .iter()
        .filter(|m| m.role == "system")
        .map(|m| m.content.as_str())
        .collect::<Vec<_>>()
        .join("\n\n");

    // Build messages.  Tool-loop continuation messages have structured
    // JSON content (content blocks) that must be sent as arrays.
    let messages: Vec<serde_json::Value> = req
        .messages
        .iter()
        .filter(|m| m.role != "system")
        .map(|m| {
            // Try to parse content as a JSON array (content blocks).
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&m.content) {
                if parsed.is_array() {
                    return json!({ "role": m.role, "content": parsed });
                }
            }
            json!({ "role": m.role, "content": m.content })
        })
        .collect();

    let tool_defs = tools::tools_anthropic();

    let mut body = json!({
        "model": req.model,
        "max_tokens": 4096,
        "messages": messages,
    });
    if !system.is_empty() {
        body["system"] = serde_json::Value::String(system);
    }
    if !tool_defs.is_empty() {
        body["tools"] = json!(tool_defs);
    }

    let api_key = req.api_key.as_deref().unwrap_or("");
    let resp = http
        .post(&url)
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .json(&body)
        .send()
        .await
        .context("HTTP request to Anthropic failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Anthropic returned {} — {}", status, text);
    }

    let data: serde_json::Value = resp.json().await.context("Invalid JSON from Anthropic")?;

    let mut result = ModelResponse::default();

    if let Some(content) = data["content"].as_array() {
        for block in content {
            match block["type"].as_str() {
                Some("text") => {
                    if let Some(text) = block["text"].as_str() {
                        if !result.text.is_empty() {
                            result.text.push('\n');
                        }
                        result.text.push_str(text);
                    }
                }
                Some("tool_use") => {
                    let id = block["id"].as_str().unwrap_or("").to_string();
                    let name = block["name"].as_str().unwrap_or("").to_string();
                    let arguments = block["input"].clone();
                    result.tool_calls.push(ParsedToolCall {
                        id,
                        name,
                        arguments,
                    });
                }
                _ => {}
            }
        }
    }

    // Extract token usage if present.
    if let Some(usage) = data.get("usage") {
        result.prompt_tokens = usage["input_tokens"].as_u64();
        result.completion_tokens = usage["output_tokens"].as_u64();
    }

    Ok(result)
}

// ── Google Gemini ───────────────────────────────────────────────────────────

/// Call Google Gemini with function declarations (non-streaming).
async fn call_google_with_tools(
    http: &reqwest::Client,
    req: &ProviderRequest,
) -> Result<ModelResponse> {
    let api_key = req.api_key.as_deref().unwrap_or("");
    let url = format!(
        "{}/models/{}:generateContent?key={}",
        req.base_url.trim_end_matches('/'),
        req.model,
        api_key,
    );

    let system = req
        .messages
        .iter()
        .filter(|m| m.role == "system")
        .map(|m| m.content.as_str())
        .collect::<Vec<_>>()
        .join("\n\n");

    // Build contents.  Tool-loop continuation messages may have
    // structured JSON parts that need to be sent as arrays.
    let contents: Vec<serde_json::Value> = req
        .messages
        .iter()
        .filter(|m| m.role != "system")
        .map(|m| {
            let role = if m.role == "assistant" { "model" } else { "user" };
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&m.content) {
                if parsed.is_array() {
                    return json!({ "role": role, "parts": parsed });
                }
            }
            json!({ "role": role, "parts": [{ "text": m.content }] })
        })
        .collect();

    let tool_defs = tools::tools_google();

    let mut body = json!({ "contents": contents });
    if !system.is_empty() {
        body["system_instruction"] = json!({ "parts": [{ "text": system }] });
    }
    if !tool_defs.is_empty() {
        body["tools"] = json!([{ "function_declarations": tool_defs }]);
    }

    let resp = http
        .post(&url)
        .json(&body)
        .send()
        .await
        .context("HTTP request to Google failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Google returned {} — {}", status, text);
    }

    let data: serde_json::Value = resp.json().await.context("Invalid JSON from Google")?;

    let mut result = ModelResponse::default();

    if let Some(parts) = data["candidates"][0]["content"]["parts"].as_array() {
        for (i, part) in parts.iter().enumerate() {
            if let Some(text) = part["text"].as_str() {
                if !result.text.is_empty() {
                    result.text.push('\n');
                }
                result.text.push_str(text);
            }
            if let Some(fc) = part.get("functionCall") {
                let name = fc["name"].as_str().unwrap_or("").to_string();
                let arguments = fc["args"].clone();
                result.tool_calls.push(ParsedToolCall {
                    id: format!("google_call_{}", i),
                    name,
                    arguments,
                });
            }
        }
    }

    // Extract token usage if present.
    if let Some(usage) = data.get("usageMetadata") {
        result.prompt_tokens = usage["promptTokenCount"].as_u64();
        result.completion_tokens = usage["candidatesTokenCount"].as_u64();
    }

    Ok(result)
}