//! Server-side helpers for the gateway protocol.
//!
//! This module provides helpers for the gateway server to send frames to clients.

use super::frames::{
    ClientFrame, deserialize_frame, serialize_frame, ServerFrame, ServerFrameType, ServerPayload,
};
use anyhow::Result;
use futures_util::SinkExt;
use tokio_tungstenite::tungstenite::Message;

pub type WsWriter = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

/// Send a ServerFrame as a binary WebSocket message.
pub async fn send_frame(writer: &mut WsWriter, frame: &ServerFrame) -> Result<()> {
    let bytes = serialize_frame(frame).map_err(|e| anyhow::anyhow!("serialize failed: {}", e))?;
    writer
        .send(Message::Binary(bytes.into()))
        .await
        .map_err(|e| anyhow::anyhow!("send failed: {}", e))
}

/// Parse a ClientFrame from binary WebSocket message bytes.
pub fn parse_client_frame(bytes: &[u8]) -> Result<ClientFrame> {
    deserialize_frame(bytes).map_err(|e| anyhow::anyhow!("parse failed: {}", e))
}

/// Helper to send a hello frame.
pub async fn send_hello(
    writer: &mut WsWriter,
    agent: &str,
    settings_dir: &str,
    vault_locked: bool,
    provider: Option<&str>,
    model: Option<&str>,
) -> Result<()> {
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
pub async fn send_auth_challenge(writer: &mut WsWriter, method: &str) -> Result<()> {
    let frame = ServerFrame {
        frame_type: ServerFrameType::AuthChallenge,
        payload: ServerPayload::AuthChallenge {
            method: method.into(),
        },
    };
    send_frame(writer, &frame).await
}

/// Helper to send an auth result frame.
pub async fn send_auth_result(
    writer: &mut WsWriter,
    ok: bool,
    message: Option<&str>,
    retry: Option<bool>,
) -> Result<()> {
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
pub async fn send_error(writer: &mut WsWriter, message: &str) -> Result<()> {
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
pub async fn send_info(writer: &mut WsWriter, message: &str) -> Result<()> {
    let frame = ServerFrame {
        frame_type: ServerFrameType::Info,
        payload: ServerPayload::Info {
            message: message.into(),
        },
    };
    send_frame(writer, &frame).await
}

/// Helper to send a status frame.
pub async fn send_status(
    writer: &mut WsWriter,
    status: super::frames::StatusType,
    detail: &str,
) -> Result<()> {
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
pub async fn send_chunk(writer: &mut WsWriter, delta: &str) -> Result<()> {
    let frame = ServerFrame {
        frame_type: ServerFrameType::Chunk,
        payload: ServerPayload::Chunk {
            delta: delta.into(),
        },
    };
    send_frame(writer, &frame).await
}

/// Helper to send a response done frame.
pub async fn send_response_done(writer: &mut WsWriter, ok: bool) -> Result<()> {
    let frame = ServerFrame {
        frame_type: ServerFrameType::ResponseDone,
        payload: ServerPayload::ResponseDone { ok },
    };
    send_frame(writer, &frame).await
}
