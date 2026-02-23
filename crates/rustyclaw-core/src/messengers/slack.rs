//! Slack messenger using bot token and Web API.

use std::collections::HashMap;

use super::{Message, Messenger, SendOptions};
use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::Mutex;

/// Slack messenger using bot token and polling channel history.
pub struct SlackMessenger {
    name: String,
    bot_token: String,
    connected: bool,
    http: reqwest::Client,
    channels: Vec<String>,
    allowed_users: Vec<String>,
    last_ts_by_channel: Mutex<HashMap<String, String>>,
}

impl SlackMessenger {
    pub fn new(
        name: String,
        bot_token: String,
        channels: Vec<String>,
        allowed_users: Vec<String>,
    ) -> Self {
        Self {
            name,
            bot_token,
            connected: false,
            http: reqwest::Client::new(),
            channels,
            allowed_users,
            last_ts_by_channel: Mutex::new(HashMap::new()),
        }
    }

    fn api_url(&self, method: &str) -> String {
        format!("https://slack.com/api/{}", method)
    }

    async fn poll_channel_messages(&self, channel: &str) -> Result<Vec<Message>> {
        let oldest = {
            let guard = self.last_ts_by_channel.lock().await;
            guard.get(channel).cloned()
        };

        let mut payload = serde_json::json!({
            "channel": channel,
            "limit": 100,
            "inclusive": false
        });
        if let Some(ref ts) = oldest {
            payload["oldest"] = serde_json::json!(ts);
        }

        let resp = self
            .http
            .post(self.api_url("conversations.history"))
            .header("Authorization", format!("Bearer {}", self.bot_token))
            .json(&payload)
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Slack receive failed: {}", resp.status());
        }

        let data: Value = resp.json().await?;
        if data["ok"].as_bool() != Some(true) {
            let detail = data["error"].as_str().unwrap_or("unknown");
            anyhow::bail!("Slack receive failed: {}", detail);
        }

        let mut out = Vec::new();
        let mut newest_seen: Option<String> = oldest.clone();

        if let Some(items) = data["messages"].as_array() {
            for item in items {
                let ts = item
                    .get("ts")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                if !ts.is_empty() {
                    if newest_seen
                        .as_ref()
                        .map(|current| slack_ts_is_newer(&ts, current))
                        .unwrap_or(true)
                    {
                        newest_seen = Some(ts.clone());
                    }
                }

                if item.get("type").and_then(|v| v.as_str()) != Some("message") {
                    continue;
                }
                if item.get("subtype").is_some() {
                    continue;
                }

                let sender = item
                    .get("user")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if sender.is_empty() {
                    continue;
                }
                if !self.allowed_users.is_empty()
                    && !self.allowed_users.iter().any(|u| u == &sender)
                {
                    continue;
                }

                let content = item
                    .get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if content.trim().is_empty() {
                    continue;
                }
                if ts.is_empty() {
                    continue;
                }

                let reply_to =
                    item.get("thread_ts")
                        .and_then(|v| v.as_str())
                        .and_then(|thread_ts| {
                            if thread_ts != ts {
                                Some(thread_ts.to_string())
                            } else {
                                None
                            }
                        });

                out.push(Message {
                    id: ts.clone(),
                    sender,
                    content,
                    timestamp: parse_slack_ts_seconds(&ts),
                    channel: Some(channel.to_string()),
                    reply_to,
                    media: None,
                });
            }
        }

        if let Some(newest) = newest_seen {
            let mut guard = self.last_ts_by_channel.lock().await;
            let update = guard
                .get(channel)
                .map(|current| slack_ts_is_newer(&newest, current))
                .unwrap_or(true);
            if update {
                guard.insert(channel.to_string(), newest);
            }
        }

        out.sort_by_key(|m| (m.timestamp, m.id.clone()));
        Ok(out)
    }
}

#[async_trait]
impl Messenger for SlackMessenger {
    fn name(&self) -> &str {
        &self.name
    }

    fn messenger_type(&self) -> &str {
        "slack"
    }

    async fn initialize(&mut self) -> Result<()> {
        let resp = self
            .http
            .post(self.api_url("auth.test"))
            .header("Authorization", format!("Bearer {}", self.bot_token))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Slack auth failed: {}", resp.status());
        }

        let data: Value = resp.json().await?;
        if data["ok"].as_bool() == Some(true) {
            self.connected = true;
            Ok(())
        } else {
            let detail = data["error"].as_str().unwrap_or("unknown");
            anyhow::bail!("Slack auth failed: {}", detail)
        }
    }

    async fn send_message(&self, channel_id: &str, content: &str) -> Result<String> {
        let resp = self
            .http
            .post(self.api_url("chat.postMessage"))
            .header("Authorization", format!("Bearer {}", self.bot_token))
            .json(&serde_json::json!({
                "channel": channel_id,
                "text": content
            }))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Slack send failed: {}", resp.status());
        }

        let data: Value = resp.json().await?;
        if data["ok"].as_bool() == Some(true) {
            Ok(data["ts"].as_str().unwrap_or("unknown").to_string())
        } else {
            let detail = data["error"].as_str().unwrap_or("unknown");
            anyhow::bail!("Slack send failed: {}", detail)
        }
    }

    async fn send_message_with_options(&self, opts: SendOptions<'_>) -> Result<String> {
        let mut payload = serde_json::json!({
            "channel": opts.recipient,
            "text": opts.content
        });
        if let Some(thread_ts) = opts.reply_to {
            payload["thread_ts"] = serde_json::json!(thread_ts);
        }

        let resp = self
            .http
            .post(self.api_url("chat.postMessage"))
            .header("Authorization", format!("Bearer {}", self.bot_token))
            .json(&payload)
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Slack send failed: {}", resp.status());
        }

        let data: Value = resp.json().await?;
        if data["ok"].as_bool() == Some(true) {
            Ok(data["ts"].as_str().unwrap_or("unknown").to_string())
        } else {
            let detail = data["error"].as_str().unwrap_or("unknown");
            anyhow::bail!("Slack send failed: {}", detail)
        }
    }

    async fn receive_messages(&self) -> Result<Vec<Message>> {
        if self.channels.is_empty() {
            return Ok(Vec::new());
        }

        let mut all_messages = Vec::new();
        for channel in &self.channels {
            let mut messages = self.poll_channel_messages(channel).await?;
            all_messages.append(&mut messages);
        }
        all_messages.sort_by_key(|m| (m.timestamp, m.id.clone()));
        Ok(all_messages)
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.connected = false;
        Ok(())
    }
}

fn parse_slack_ts_seconds(ts: &str) -> i64 {
    ts.split('.')
        .next()
        .and_then(|sec| sec.parse::<i64>().ok())
        .unwrap_or(0)
}

fn parse_slack_ts_parts(ts: &str) -> (i64, i64) {
    let mut parts = ts.split('.');
    let sec = parts
        .next()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    let frac = parts
        .next()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    (sec, frac)
}

fn slack_ts_is_newer(candidate: &str, current: &str) -> bool {
    parse_slack_ts_parts(candidate) > parse_slack_ts_parts(current)
}
