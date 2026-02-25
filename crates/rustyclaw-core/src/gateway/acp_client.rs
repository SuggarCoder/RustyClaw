use super::types::{ChatMessage, ModelResponse};
use anyhow::{Context, Result, anyhow};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::sync::{Mutex, Notify, oneshot};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{debug, trace, warn};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

const INIT_METHODS: &[&str] = &["initialize"];
const AUTH_METHODS: &[&str] = &["authenticate"];
const NEW_SESSION_METHODS: &[&str] = &["session/new", "new_session"];
const PROMPT_METHODS: &[&str] = &["session/prompt", "prompt"];

#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: &'static str,
    pub id: u64,
    pub method: String,
    pub params: Value,
}

#[derive(Debug, Clone)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: u64,
    pub result: Option<Value>,
    pub error: Option<JsonRpcError>,
}

#[derive(Clone)]
pub struct AcpClientManager {
    inner: Arc<Inner>,
}

struct Inner {
    state: Mutex<AcpState>,
    ready_notify: Notify,
}

enum AcpState {
    Stopped,
    Starting,
    Ready(Arc<AcpRuntime>),
    Failed { message: String, at: Instant },
}

struct AcpRuntime {
    child: Arc<Mutex<Child>>,
    stdin: Arc<Mutex<ChildStdin>>,
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<Value>>>>,
    next_request_id: AtomicU64,
    active_prompt: Arc<Mutex<Option<PromptAggregation>>>,
    prompt_lock: Mutex<()>,
    broken: Arc<AtomicBool>,
    session_id: Mutex<String>,
    stdout_task: JoinHandle<()>,
    stderr_task: JoinHandle<()>,
}

struct PromptAggregation {
    session_id: String,
    text: String,
}

impl Default for AcpClientManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AcpClientManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(AcpState::Stopped),
                ready_notify: Notify::new(),
            }),
        }
    }

    pub async fn prompt_text(&self, messages: &[ChatMessage]) -> Result<ModelResponse> {
        // Retry once after invalidating a broken runtime.
        for attempt in 0..2 {
            let runtime = self.ensure_ready().await?;
            match runtime.prompt_text(messages).await {
                Ok(resp) => return Ok(resp),
                Err(err) => {
                    self.mark_failed(format!("ACP prompt failed: {}", err))
                        .await;
                    if attempt == 1 {
                        return Err(err);
                    }
                }
            }
        }

        Err(anyhow!("ACP prompt failed"))
    }

    async fn ensure_ready(&self) -> Result<Arc<AcpRuntime>> {
        loop {
            let mut state = self.inner.state.lock().await;
            match &*state {
                AcpState::Ready(runtime) => {
                    if runtime.is_broken() {
                        let old = match std::mem::replace(&mut *state, AcpState::Stopped) {
                            AcpState::Ready(rt) => Some(rt),
                            _ => None,
                        };
                        drop(state);
                        if let Some(rt) = old {
                            rt.shutdown().await;
                        }
                        continue;
                    }
                    return Ok(runtime.clone());
                }
                AcpState::Starting => {
                    let notified = self.inner.ready_notify.notified();
                    drop(state);
                    notified.await;
                }
                AcpState::Failed { message, at } => {
                    debug!(
                        error = %message,
                        failed_for_ms = at.elapsed().as_millis(),
                        "ACP runtime in failed state, retrying initialization"
                    );
                    *state = AcpState::Starting;
                    drop(state);
                    let startup = timeout(STARTUP_TIMEOUT, AcpRuntime::start()).await;
                    match startup {
                        Ok(Ok(runtime)) => {
                            let runtime = Arc::new(runtime);
                            let mut state = self.inner.state.lock().await;
                            *state = AcpState::Ready(runtime.clone());
                            self.inner.ready_notify.notify_waiters();
                            return Ok(runtime);
                        }
                        Ok(Err(err)) => {
                            let msg = err.to_string();
                            let mut state = self.inner.state.lock().await;
                            *state = AcpState::Failed {
                                message: msg.clone(),
                                at: Instant::now(),
                            };
                            self.inner.ready_notify.notify_waiters();
                            return Err(anyhow!(msg));
                        }
                        Err(_) => {
                            let mut state = self.inner.state.lock().await;
                            *state = AcpState::Failed {
                                message: "ACP startup timed out".to_string(),
                                at: Instant::now(),
                            };
                            self.inner.ready_notify.notify_waiters();
                            return Err(anyhow!("ACP startup timed out"));
                        }
                    }
                }
                AcpState::Stopped => {
                    *state = AcpState::Starting;
                    drop(state);
                    let startup = timeout(STARTUP_TIMEOUT, AcpRuntime::start()).await;
                    match startup {
                        Ok(Ok(runtime)) => {
                            let runtime = Arc::new(runtime);
                            let mut state = self.inner.state.lock().await;
                            *state = AcpState::Ready(runtime.clone());
                            self.inner.ready_notify.notify_waiters();
                            return Ok(runtime);
                        }
                        Ok(Err(err)) => {
                            let msg = err.to_string();
                            let mut state = self.inner.state.lock().await;
                            *state = AcpState::Failed {
                                message: msg.clone(),
                                at: Instant::now(),
                            };
                            self.inner.ready_notify.notify_waiters();
                            return Err(anyhow!(msg));
                        }
                        Err(_) => {
                            let mut state = self.inner.state.lock().await;
                            *state = AcpState::Failed {
                                message: "ACP startup timed out".to_string(),
                                at: Instant::now(),
                            };
                            self.inner.ready_notify.notify_waiters();
                            return Err(anyhow!("ACP startup timed out"));
                        }
                    }
                }
            }
        }
    }

    async fn mark_failed(&self, message: String) {
        let old_runtime = {
            let mut state = self.inner.state.lock().await;
            let old = match std::mem::replace(
                &mut *state,
                AcpState::Failed {
                    message,
                    at: Instant::now(),
                },
            ) {
                AcpState::Ready(rt) => Some(rt),
                _ => None,
            };
            self.inner.ready_notify.notify_waiters();
            old
        };

        if let Some(runtime) = old_runtime {
            runtime.shutdown().await;
        }
    }
}

impl AcpRuntime {
    async fn start() -> Result<Self> {
        let mut cmd = Command::new("codex-acp");
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = cmd
            .spawn()
            .context("Failed to spawn `codex-acp` (ensure it is in PATH)")?;

        let stdin = child
            .stdin
            .take()
            .context("Failed to capture codex-acp stdin")?;
        let stdout = child
            .stdout
            .take()
            .context("Failed to capture codex-acp stdout")?;
        let stderr = child
            .stderr
            .take()
            .context("Failed to capture codex-acp stderr")?;

        let child = Arc::new(Mutex::new(child));
        let stdin = Arc::new(Mutex::new(stdin));
        let pending: Arc<Mutex<HashMap<u64, oneshot::Sender<Value>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let active_prompt: Arc<Mutex<Option<PromptAggregation>>> = Arc::new(Mutex::new(None));
        let broken = Arc::new(AtomicBool::new(false));

        let stdout_task = spawn_stdout_task(
            stdout,
            pending.clone(),
            active_prompt.clone(),
            broken.clone(),
        );
        let stderr_task = spawn_stderr_task(stderr, broken.clone());

        let runtime = Self {
            child,
            stdin,
            pending,
            next_request_id: AtomicU64::new(1),
            active_prompt,
            prompt_lock: Mutex::new(()),
            broken,
            session_id: Mutex::new(String::new()),
            stdout_task,
            stderr_task,
        };

        runtime.initialize().await?;
        Ok(runtime)
    }

    async fn shutdown(&self) {
        self.stdout_task.abort();
        self.stderr_task.abort();

        let mut child = self.child.lock().await;
        let _ = child.start_kill();
    }

    fn is_broken(&self) -> bool {
        self.broken.load(Ordering::Relaxed)
    }

    async fn initialize(&self) -> Result<()> {
        // Initialize ACP connection.
        let _ = self
            .call_method_variants(
                INIT_METHODS,
                &[
                    json!({ "client_capabilities": { "fs": true, "terminal": false } }),
                    json!({ "clientCapabilities": { "fs": true, "terminal": false } }),
                    json!({}),
                ],
            )
            .await
            .context("ACP initialize failed")?;

        // Authenticate via ChatGPT method first, then API key fallback.
        let auth_result = self
            .call_method_variants(
                AUTH_METHODS,
                &[
                    json!({ "method_id": "chatgpt" }),
                    json!({ "methodId": "chatgpt" }),
                    json!({ "method_id": "apikey" }),
                    json!({ "methodId": "apikey" }),
                ],
            )
            .await;

        if let Err(err) = auth_result {
            return Err(anyhow!("ACP authenticate failed: {}", err));
        }

        let session_result = self
            .call_method_variants(NEW_SESSION_METHODS, &[json!({})])
            .await
            .context("ACP session/new failed")?;

        let session_id = extract_session_id(&session_result)
            .ok_or_else(|| anyhow!("ACP session/new response missing session id"))?;

        let mut sid = self.session_id.lock().await;
        *sid = session_id;
        Ok(())
    }

    async fn prompt_text(&self, messages: &[ChatMessage]) -> Result<ModelResponse> {
        if self.is_broken() {
            return Err(anyhow!("ACP runtime is not healthy"));
        }

        let _prompt_guard = self.prompt_lock.lock().await;

        let session_id = {
            let sid = self.session_id.lock().await;
            sid.clone()
        };
        if session_id.is_empty() {
            return Err(anyhow!("ACP session is not initialized"));
        }

        {
            let mut active = self.active_prompt.lock().await;
            *active = Some(PromptAggregation {
                session_id: session_id.clone(),
                text: String::new(),
            });
        }

        let prompt_text = build_prompt_text(messages);
        let prompt_params = [
            json!({
                "session_id": session_id,
                "prompt": [
                    { "type": "text", "text": prompt_text }
                ]
            }),
            json!({
                "sessionId": session_id,
                "prompt": [
                    { "type": "text", "text": prompt_text }
                ]
            }),
        ];

        let prompt_result = self
            .call_method_variants(PROMPT_METHODS, &prompt_params)
            .await;

        let mut aggregated_text = String::new();
        {
            let mut active = self.active_prompt.lock().await;
            if let Some(agg) = active.take() {
                aggregated_text = agg.text;
            }
        }

        let result = prompt_result.context("ACP prompt request failed")?;

        if aggregated_text.trim().is_empty()
            && let Some(fallback_text) = extract_text_from_prompt_result(&result)
        {
            aggregated_text = fallback_text;
        }

        let stop_reason = extract_stop_reason(&result).unwrap_or("end_turn");
        let finish_reason = match stop_reason {
            "end_turn" => "stop",
            "cancelled" | "canceled" => "cancelled",
            other => other,
        };

        Ok(ModelResponse {
            text: aggregated_text,
            tool_calls: Vec::new(),
            finish_reason: Some(finish_reason.to_string()),
            prompt_tokens: None,
            completion_tokens: None,
        })
    }

    async fn call_method_variants(&self, methods: &[&str], params: &[Value]) -> Result<Value> {
        let mut last_err: Option<anyhow::Error> = None;

        for method in methods {
            for p in params {
                match self.call_json_rpc(method, p.clone()).await {
                    Ok(result) => return Ok(result),
                    Err(err) => {
                        trace!(method = %method, error = %err, "ACP method variant failed");
                        last_err = Some(err);
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("All ACP method variants failed")))
    }

    async fn call_json_rpc(&self, method: &str, params: Value) -> Result<Value> {
        if self.is_broken() {
            return Err(anyhow!("ACP runtime pipe is broken"));
        }

        let id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            id,
            method: method.to_string(),
            params,
        };

        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock().await;
            pending.insert(id, tx);
        }

        let line = serde_json::to_string(&req).context("Failed to serialize ACP request")?;
        {
            let mut stdin = self.stdin.lock().await;
            if let Err(err) = stdin.write_all(format!("{}\n", line).as_bytes()).await {
                let mut pending = self.pending.lock().await;
                pending.remove(&id);
                self.broken.store(true, Ordering::Relaxed);
                return Err(anyhow!("Failed writing ACP request to stdin: {}", err));
            }
            if let Err(err) = stdin.flush().await {
                let mut pending = self.pending.lock().await;
                pending.remove(&id);
                self.broken.store(true, Ordering::Relaxed);
                return Err(anyhow!("Failed writing ACP request to stdin: {}", err));
            }
        }

        let raw = match timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(v)) => v,
            Ok(Err(_)) => {
                let mut pending = self.pending.lock().await;
                pending.remove(&id);
                return Err(anyhow!("ACP response channel closed (method: {})", method));
            }
            Err(_) => {
                let mut pending = self.pending.lock().await;
                pending.remove(&id);
                return Err(anyhow!("ACP request timed out (method: {})", method));
            }
        };

        let response = parse_jsonrpc_response(raw)?;
        if response.id != id {
            warn!(
                expected_id = id,
                actual_id = response.id,
                method = %method,
                "ACP response id mismatch"
            );
        }
        if response.jsonrpc != "2.0" {
            warn!(
                version = %response.jsonrpc,
                method = %method,
                "Unexpected ACP jsonrpc version"
            );
        }

        if let Some(err) = response.error {
            return Err(anyhow!(
                "ACP error {}: {}{}",
                err.code,
                err.message,
                err.data
                    .as_ref()
                    .map(|d| format!(" ({})", d))
                    .unwrap_or_default()
            ));
        }

        response
            .result
            .ok_or_else(|| anyhow!("ACP response missing result for method {}", method))
    }
}

fn spawn_stdout_task(
    stdout: ChildStdout,
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<Value>>>>,
    active_prompt: Arc<Mutex<Option<PromptAggregation>>>,
    broken: Arc<AtomicBool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut reader = BufReader::new(stdout).lines();

        loop {
            let line = match reader.next_line().await {
                Ok(Some(line)) => line,
                Ok(None) => {
                    warn!("codex-acp stdout closed");
                    broken.store(true, Ordering::Relaxed);
                    break;
                }
                Err(err) => {
                    warn!(error = %err, "Failed reading codex-acp stdout");
                    broken.store(true, Ordering::Relaxed);
                    break;
                }
            };

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let value: Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(err) => {
                    warn!(error = %err, line = %trimmed, "Invalid JSON line from codex-acp stdout");
                    continue;
                }
            };

            if let Some(id) = value.get("id").and_then(jsonrpc_id_as_u64) {
                let tx = {
                    let mut map = pending.lock().await;
                    map.remove(&id)
                };

                if let Some(tx) = tx {
                    let _ = tx.send(value);
                } else {
                    debug!(id, "Received ACP response with unknown id");
                }
                continue;
            }

            if let Some((session_id, text)) = extract_session_update_chunk(&value) {
                let mut guard = active_prompt.lock().await;
                if let Some(active) = guard.as_mut()
                    && active.session_id == session_id
                {
                    active.text.push_str(&text);
                }
            }
        }

        // Fail all pending requests if the stdout task exits.
        let mut map = pending.lock().await;
        let failed = json!({
            "jsonrpc": "2.0",
            "id": 0,
            "error": {
                "code": -32000,
                "message": "codex-acp stdout task terminated"
            }
        });
        for (_, tx) in map.drain() {
            let _ = tx.send(failed.clone());
        }
    })
}

fn spawn_stderr_task(stderr: ChildStderr, broken: Arc<AtomicBool>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut reader = BufReader::new(stderr).lines();

        loop {
            match reader.next_line().await {
                Ok(Some(line)) => {
                    warn!(target: "codex_acp", "codex-acp stderr: {}", line);
                }
                Ok(None) => {
                    trace!("codex-acp stderr closed");
                    break;
                }
                Err(err) => {
                    warn!(error = %err, "Failed reading codex-acp stderr");
                    broken.store(true, Ordering::Relaxed);
                    break;
                }
            }
        }
    })
}

fn parse_jsonrpc_response(raw: Value) -> Result<JsonRpcResponse> {
    let id = raw
        .get("id")
        .and_then(jsonrpc_id_as_u64)
        .ok_or_else(|| anyhow!("Invalid ACP response id: {}", raw))?;

    let error = raw.get("error").and_then(|e| {
        Some(JsonRpcError {
            code: e.get("code")?.as_i64()?,
            message: e.get("message")?.as_str()?.to_string(),
            data: e.get("data").cloned(),
        })
    });

    Ok(JsonRpcResponse {
        jsonrpc: raw
            .get("jsonrpc")
            .and_then(Value::as_str)
            .unwrap_or("2.0")
            .to_string(),
        id,
        result: raw.get("result").cloned(),
        error,
    })
}

fn jsonrpc_id_as_u64(v: &Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    v.as_str()?.parse::<u64>().ok()
}

fn extract_session_id(v: &Value) -> Option<String> {
    v.get("session_id")
        .or_else(|| v.get("sessionId"))
        .and_then(Value::as_str)
        .map(|s| s.to_string())
}

fn extract_stop_reason(v: &Value) -> Option<&str> {
    v.get("stop_reason")
        .or_else(|| v.get("stopReason"))
        .and_then(Value::as_str)
}

fn extract_text_from_prompt_result(v: &Value) -> Option<String> {
    if let Some(s) = v.get("text").and_then(Value::as_str) {
        return Some(s.to_string());
    }
    if let Some(msg) = v.get("message")
        && let Some(text) = extract_text_node(msg)
    {
        return Some(text);
    }
    None
}

fn extract_session_update_chunk(notification: &Value) -> Option<(String, String)> {
    let method = notification.get("method")?.as_str()?;
    if method != "session/update" && method != "session.update" {
        return None;
    }

    let params = notification.get("params")?;
    let session_id = params
        .get("session_id")
        .or_else(|| params.get("sessionId"))
        .and_then(Value::as_str)?
        .to_string();

    let update = params
        .get("update")
        .or_else(|| params.get("session_update"))
        .or_else(|| params.get("sessionUpdate"))?;

    let payload = update
        .get("agent_message_chunk")
        .or_else(|| update.get("agentMessageChunk"))
        .or_else(|| update.get("AgentMessageChunk"))
        .or_else(|| update.get("agent_message"))
        .or_else(|| update.get("agentMessage"))
        .or_else(|| update.get("AgentMessage"))?;

    let text = extract_text_node(payload)?;
    if text.is_empty() {
        return None;
    }

    Some((session_id, text))
}

fn extract_text_node(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Array(items) => {
            let mut out = String::new();
            for item in items {
                if let Some(piece) = extract_text_node(item) {
                    out.push_str(&piece);
                }
            }
            if out.is_empty() { None } else { Some(out) }
        }
        Value::Object(map) => {
            if let Some(text) = map.get("text").and_then(Value::as_str) {
                return Some(text.to_string());
            }
            if let Some(delta) = map.get("delta").and_then(Value::as_str) {
                return Some(delta.to_string());
            }
            if let Some(content) = map.get("content")
                && let Some(text) = extract_text_node(content)
            {
                return Some(text);
            }
            if let Some(block) = map.get("content_block")
                && let Some(text) = extract_text_node(block)
            {
                return Some(text);
            }
            None
        }
        _ => None,
    }
}

fn build_prompt_text(messages: &[ChatMessage]) -> String {
    if messages.is_empty() {
        return "Hello".to_string();
    }

    // Keep a bounded context window because ACP sessions are already stateful.
    let start = messages.len().saturating_sub(20);
    let mut out = String::new();

    for m in &messages[start..] {
        let content = m.content.trim();
        if content.is_empty() {
            continue;
        }
        out.push_str(&format!("{}: {}\n\n", m.role, content));
    }

    if out.is_empty() {
        "Please respond to the latest user request.".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_session_update_chunk_snake_case() {
        let v = json!({
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {
                "session_id": "abc",
                "update": {
                    "agent_message_chunk": {
                        "content": {
                            "text": "hello"
                        }
                    }
                }
            }
        });

        let out = extract_session_update_chunk(&v).expect("chunk");
        assert_eq!(out.0, "abc");
        assert_eq!(out.1, "hello");
    }

    #[test]
    fn parses_jsonrpc_response_error() {
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 42,
            "error": {
                "code": -32601,
                "message": "Method not found"
            }
        });

        let resp = parse_jsonrpc_response(raw).expect("response parsed");
        assert!(resp.error.is_some());
        assert_eq!(resp.id, 42);
    }
}
