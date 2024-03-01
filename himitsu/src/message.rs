use serde_derive::{Deserialize, Serialize};
use serde::de::DeserializeOwned;

use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::UnixStream};

use crate::{error::HResult, HimitsuError, ScanResults};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum HimitsuMessage {
    ScanCodeDiff {
        diff: String,
    },
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum HimitsuResponse {
    Clean,
    SecretsFound(ScanResults),
    Error(String),
}

/// Read a message from a Himitsu unix socket and parse it into the provided
/// message type.
pub async fn parse_incoming_message<T>(mut stream: &mut UnixStream) -> HResult<T>
where
    T: DeserializeOwned,
{
    // Read length of message
    let len = AsyncReadExt::read_u32(stream).await?;
    let mut buf = vec![0; len as usize];
    AsyncReadExt::read_exact(&mut stream, &mut buf).await?;

    let message: T = serde_json::from_slice(&buf).map_err(|e| HimitsuError::IncomingMessageError(e.to_string()))?;

    Ok(message)
}

pub async fn serialize_and_send_response<T: serde::Serialize>(
    response: T,
    stream: &mut UnixStream,
) -> HResult<()> {
    let response = serde_json::to_string(&response).map_err(|e| HimitsuError::OutgoingMessageError(e.to_string()))?;
    stream.write_u32(response.len() as u32).await?;
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}
