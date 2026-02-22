//! Webhook messenger - POST messages to a URL.

use super::{Message, Messenger, SendOptions};
use anyhow::Result;
use async_trait::async_trait;
use serde::Serialize;

/// Simple webhook messenger that POSTs messages to a URL
pub struct WebhookMessenger {
    name: String,
    webhook_url: String,
    connected: bool,
    http: reqwest::Client,
}

impl WebhookMessenger {
    pub fn new(name: String, webhook_url: String) -> Self {
        Self {
            name,
            webhook_url,
            connected: false,
            http: reqwest::Client::new(),
        }
    }
}

#[derive(Serialize)]
struct WebhookPayload<'a> {
    content: &'a str,
    recipient: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_to: Option<&'a str>,
}

#[async_trait]
impl Messenger for WebhookMessenger {
    fn name(&self) -> &str {
        &self.name
    }

    fn messenger_type(&self) -> &str {
        "webhook"
    }

    async fn initialize(&mut self) -> Result<()> {
        self.connected = true;
        Ok(())
    }

    async fn send_message(&self, recipient: &str, content: &str) -> Result<String> {
        let payload = WebhookPayload {
            content,
            recipient,
            reply_to: None,
        };

        let resp = self
            .http
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(format!("webhook-{}", chrono::Utc::now().timestamp_millis()))
        } else {
            anyhow::bail!("Webhook returned {}", resp.status())
        }
    }

    async fn send_message_with_options(&self, opts: SendOptions<'_>) -> Result<String> {
        let payload = WebhookPayload {
            content: opts.content,
            recipient: opts.recipient,
            reply_to: opts.reply_to,
        };

        let resp = self
            .http
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(format!("webhook-{}", chrono::Utc::now().timestamp_millis()))
        } else {
            anyhow::bail!("Webhook returned {}", resp.status())
        }
    }

    async fn receive_messages(&self) -> Result<Vec<Message>> {
        // Webhooks are typically outbound-only
        Ok(Vec::new())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.connected = false;
        Ok(())
    }
}
