//! Signal messenger using presage library.
//!
//! This requires the `signal` feature to be enabled.
//!
//! Signal requires device linking or registration before use.
//! Use `SignalMessenger::link_device()` to generate a QR code for linking,
//! or `SignalMessenger::register()` for SMS registration.

use super::{Message, Messenger, SendOptions};
use anyhow::{Context, Result};
use async_trait::async_trait;
use presage::{
    libsignal_service::{
        content::ContentBody,
        prelude::Uuid,
        proto::DataMessage,
    },
    manager::ReceivingMode,
    Manager,
};
use presage_store_sled::SledStore;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Signal messenger using presage
pub struct SignalMessenger {
    name: String,
    store_path: PathBuf,
    manager: Option<Arc<Mutex<Manager<SledStore, presage::manager::Registered>>>>,
    connected: bool,
    /// Pending incoming messages
    pending_messages: Arc<Mutex<Vec<Message>>>,
}

impl SignalMessenger {
    /// Create a new Signal messenger
    ///
    /// The store_path should be a directory where Signal state will be stored.
    /// If the store already contains registration data, it will be used.
    /// Otherwise, you must call `link_device()` or `register()` before use.
    pub fn new(name: String, store_path: PathBuf) -> Self {
        Self {
            name,
            store_path,
            manager: None,
            connected: false,
            pending_messages: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Link as a secondary device by scanning a QR code from the primary device.
    ///
    /// Returns the provisioning URL to display as a QR code.
    /// The callback will be called with progress updates.
    pub async fn link_device<F>(&mut self, device_name: &str, mut on_qr: F) -> Result<()>
    where
        F: FnMut(&str) + Send,
    {
        let store = SledStore::open(&self.store_path, None)
            .await
            .context("Failed to open Signal store")?;

        let (manager, provisioning_link) = Manager::link_secondary_device(
            store,
            device_name.to_string(),
        )
        .await
        .context("Failed to start device linking")?;

        // Call the QR code callback with the provisioning URL
        on_qr(&provisioning_link.to_string());

        // Wait for the linking to complete
        let registered_manager = manager.await.context("Device linking failed")?;

        self.manager = Some(Arc::new(Mutex::new(registered_manager)));
        self.connected = true;
        Ok(())
    }

    /// Register a new account using SMS verification
    pub async fn register(&mut self, phone_number: &str, use_voice: bool) -> Result<String> {
        let store = SledStore::open(&self.store_path, None)
            .await
            .context("Failed to open Signal store")?;

        let manager = Manager::register(
            store,
            presage::libsignal_service::configuration::SignalServers::Production,
            phone_number.to_string(),
            use_voice,
        )
        .await
        .context("Failed to start registration")?;

        // The manager is now in "awaiting verification" state
        // Return instructions - caller must call confirm_registration with the code
        Ok("Verification code sent. Call confirm_registration() with the code.".to_string())
    }

    /// Confirm registration with the SMS verification code
    pub async fn confirm_registration(&mut self, _code: &str) -> Result<()> {
        // This would complete the registration process
        // presage handles this internally during the register() flow
        anyhow::bail!("Registration confirmation not yet implemented - use link_device instead")
    }

    /// Check if the device is registered
    pub fn is_registered(&self) -> bool {
        self.manager.is_some()
    }

    /// Get the manager (must be registered first)
    fn manager(&self) -> Result<&Arc<Mutex<Manager<SledStore, presage::manager::Registered>>>> {
        self.manager
            .as_ref()
            .context("Signal not registered - call link_device() first")
    }

    /// Parse a recipient (phone number or UUID)
    fn parse_recipient(recipient: &str) -> Result<Uuid> {
        // Try parsing as UUID first
        if let Ok(uuid) = Uuid::parse_str(recipient) {
            return Ok(uuid);
        }

        // For phone numbers, we'd need to look up the UUID via the Signal server
        // This is a simplified version - real implementation would use contacts
        anyhow::bail!(
            "Recipient must be a UUID. Phone number lookup not yet implemented: {}",
            recipient
        )
    }
}

#[async_trait]
impl Messenger for SignalMessenger {
    fn name(&self) -> &str {
        &self.name
    }

    fn messenger_type(&self) -> &str {
        "signal"
    }

    async fn initialize(&mut self) -> Result<()> {
        // Try to open existing store with registration
        let store = SledStore::open(&self.store_path, None)
            .await
            .context("Failed to open Signal store")?;

        // Check if we have registration data
        match Manager::load_registered(store).await {
            Ok(manager) => {
                self.manager = Some(Arc::new(Mutex::new(manager)));
                self.connected = true;
                Ok(())
            }
            Err(_) => {
                // Not registered yet - that's OK, user needs to call link_device
                self.connected = false;
                Ok(())
            }
        }
    }

    async fn send_message(&self, recipient: &str, content: &str) -> Result<String> {
        let manager = self.manager()?;
        let recipient_uuid = Self::parse_recipient(recipient)?;

        let mut manager_guard = manager.lock().await;

        // Create the data message
        let data_message = DataMessage {
            body: Some(content.to_string()),
            timestamp: Some(chrono::Utc::now().timestamp_millis() as u64),
            ..Default::default()
        };

        // Send the message
        manager_guard
            .send_message(recipient_uuid, data_message, chrono::Utc::now().timestamp_millis() as u64)
            .await
            .context("Failed to send Signal message")?;

        Ok(format!(
            "signal-{}",
            chrono::Utc::now().timestamp_millis()
        ))
    }

    async fn send_message_with_options(&self, opts: SendOptions<'_>) -> Result<String> {
        // Signal doesn't have native reply support in the same way
        // We could quote the message, but for now just send normally
        self.send_message(opts.recipient, opts.content).await
    }

    async fn receive_messages(&self) -> Result<Vec<Message>> {
        let manager = self.manager()?;
        let mut manager_guard = manager.lock().await;

        let mut messages = Vec::new();

        // Receive messages (non-blocking)
        let mut receiving = manager_guard.receive_messages(ReceivingMode::WaitForContacts).await?;

        // Process a few messages without blocking
        use futures_util::StreamExt;
        let timeout = tokio::time::Duration::from_millis(100);
        
        loop {
            match tokio::time::timeout(timeout, receiving.next()).await {
                Ok(Some(Ok(content))) => {
                    if let ContentBody::DataMessage(data_message) = content.body {
                        if let Some(body) = data_message.body {
                            let message = Message {
                                id: format!("signal-{}", data_message.timestamp.unwrap_or(0)),
                                sender: content.metadata.sender.uuid.to_string(),
                                content: body,
                                timestamp: (data_message.timestamp.unwrap_or(0) / 1000) as i64,
                                channel: None, // Signal doesn't have channels in the same way
                                reply_to: None,
                                media: None,
                            };
                            messages.push(message);
                        }
                    }
                }
                Ok(Some(Err(_))) => continue,
                Ok(None) => break,
                Err(_) => break, // Timeout
            }
        }

        Ok(messages)
    }

    fn is_connected(&self) -> bool {
        self.connected && self.manager.is_some()
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.connected = false;
        // Manager will be dropped when the struct is dropped
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_messenger_creation() {
        let messenger = SignalMessenger::new(
            "test".to_string(),
            PathBuf::from("/tmp/signal-test"),
        );
        assert_eq!(messenger.name(), "test");
        assert_eq!(messenger.messenger_type(), "signal");
        assert!(!messenger.is_connected());
        assert!(!messenger.is_registered());
    }
}
