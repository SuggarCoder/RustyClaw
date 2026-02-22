//! Console messenger - prints to stdout (for testing/debugging).

use super::{Message, Messenger};
use anyhow::Result;
use async_trait::async_trait;
use tracing::debug;

/// Console messenger that prints to stdout (useful for testing/debugging)
pub struct ConsoleMessenger {
    name: String,
    connected: bool,
}

impl ConsoleMessenger {
    pub fn new(name: String) -> Self {
        Self {
            name,
            connected: false,
        }
    }
}

#[async_trait]
impl Messenger for ConsoleMessenger {
    fn name(&self) -> &str {
        &self.name
    }

    fn messenger_type(&self) -> &str {
        "console"
    }

    async fn initialize(&mut self) -> Result<()> {
        self.connected = true;
        debug!(name = %self.name, "ConsoleMessenger initialized");
        Ok(())
    }

    async fn send_message(&self, recipient: &str, content: &str) -> Result<String> {
        let id = format!("console-{}", chrono::Utc::now().timestamp_millis());
        println!("[{}] To {}: {}", self.name, recipient, content);
        Ok(id)
    }

    async fn receive_messages(&self) -> Result<Vec<Message>> {
        Ok(Vec::new())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.connected = false;
        debug!(name = %self.name, "ConsoleMessenger disconnected");
        Ok(())
    }
}
