//! Server-side helpers for the gateway protocol.
//!
//! This module provides helpers for the gateway server to send frames to clients.

use super::frames::{
    ClientFrame, deserialize_frame, serialize_frame, ServerFrame, ServerFrameType, ServerPayload,
};
use anyhow::Result;
use futures_util::SinkExt;
use tokio_tungstenite::tungstenite::Message;

/// Send a ServerFrame as a binary WebSocket message.
/// Works with any sink that accepts Binary messages.
pub async fn send_frame<S>(writer: &mut S, frame: &ServerFrame) -> Result<()>
where
    S: SinkExt<Message> + Unpin,
{
    let bytes = serialize_frame(frame).map_err(|e| anyhow::anyhow!("serialize failed: {}", e))?;
    writer
        .send(Message::Binary(bytes.into()))
        .await
        .map_err(|_e| anyhow::anyhow!("send failed"))
}

/// Parse a ClientFrame from binary WebSocket message bytes.
pub fn parse_client_frame(bytes: &[u8]) -> Result<ClientFrame> {
    deserialize_frame(bytes).map_err(|e| anyhow::anyhow!("parse failed: {}", e))
}

/// Helper to send a hello frame.
pub async fn send_hello<S>(
    writer: &mut S,
    agent: &str,
    settings_dir: &str,
    vault_locked: bool,
    provider: Option<&str>,
    model: Option<&str>,
) -> Result<()>
where
    S: SinkExt<Message> + Unpin,
{
    let frame = ServerFrame {
        frame_type: ServerFrameType::Hello,
        payload: ServerPayload::Hello {
            agent: agent.into(),
            settings_dir: settings_dir.into(),
            vault_locked,
            provider: provider.map(|s| s.into()),
            model: model.map(|s| s.into()),
        },
    };
    send_frame(writer, &frame).await
}

/// Helper to send an auth challenge frame.
pub async fn send_auth_challenge<S>(writer: &mut S, method: &str) -> Result<()>
where
    S: SinkExt<Message> + Unpin,
{
    let frame = ServerFrame {
        frame_type: ServerFrameType::AuthChallenge,
        payload: ServerPayload::AuthChallenge {
            method: method.into(),
        },
    };
    send_frame(writer, &frame).await
}

/// Helper to send an auth result frame.
pub async fn send_auth_result<S>(
    writer: &mut S,
    ok: bool,
    message: Option<&str>,
    retry: Option<bool>,
) -> Result<()>
where
    S: SinkExt<Message> + Unpin,
{
    let frame = ServerFrame {
        frame_type: ServerFrameType::AuthResult,
        payload: ServerPayload::AuthResult {
            ok,
            message: message.map(|s| s.into()),
            retry,
        },
    };
    send_frame(writer, &frame).await
}

/// Helper to send an error frame.
pub async fn send_error<S>(writer: &mut S, message: &str) -> Result<()>
where
    S: SinkExt<Message> + Unpin,
{
    let frame = ServerFrame {
        frame_type: ServerFrameType::Error,
        payload: ServerPayload::Error {
            ok: false,
            message: message.into(),
        },
    };
    send_frame(writer, &frame).await
}

/// Helper to send an info frame.
pub async fn send_info<S>(writer: &mut S, message: &str) -> Result<()>
where
    S: SinkExt<Message> + Unpin,
{
    let frame = ServerFrame {
        frame_type: ServerFrameType::Info,
        payload: ServerPayload::Info {
            message: message.into(),
        },
    };
    send_frame(writer, &frame).await
}

/// Helper to send a status frame.
pub async fn send_status<S>(
    writer: &mut S,
    status: super::frames::StatusType,
    detail: &str,
) -> Result<()>
where
    S: SinkExt<Message> + Unpin,
{
    let frame = ServerFrame {
        frame_type: ServerFrameType::Status,
        payload: ServerPayload::Status {
            status,
            detail: detail.into(),
        },
    };
    send_frame(writer, &frame).await
}

/// Helper to send a chunk frame.
pub async fn send_chunk<S>(writer: &mut S, delta: &str) -> Result<()>
where
    S: SinkExt<Message> + Unpin,
{
    let frame = ServerFrame {
        frame_type: ServerFrameType::Chunk,
        payload: ServerPayload::Chunk {
            delta: delta.into(),
        },
    };
    send_frame(writer, &frame).await
}

/// Helper to send a response done frame.
pub async fn send_response_done<S>(writer: &mut S, ok: bool) -> Result<()>
where
    S: SinkExt<Message> + Unpin,
{
    let frame = ServerFrame {
        frame_type: ServerFrameType::ResponseDone,
        payload: ServerPayload::ResponseDone { ok },
    };
    send_frame(writer, &frame).await
}
