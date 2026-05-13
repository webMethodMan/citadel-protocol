use async_trait::async_trait;
use crate::AppState;
use crate::mcp::{McpRequest, process_request_matrix};
use crate::transport::InboundTransport;
use sakshi_core::Error;
use std::sync::Arc;
use tokio::io::{stdin, stdout};
use tokio_util::codec::{FramedRead, FramedWrite, LinesCodec};
use futures::{StreamExt, SinkExt};
use tracing::info;

pub struct McpStdioTransport;

#[async_trait]
impl InboundTransport for McpStdioTransport {
    async fn listen(&self, state: Arc<AppState>) -> Result<(), Error> {
        info!("--- Citadel Stdio Adapter: ACTIVE ---");
        let stdin = stdin();
        let stdout = stdout();

        let mut reader = FramedRead::new(stdin, LinesCodec::new());
        let mut writer = FramedWrite::new(stdout, LinesCodec::new());

        while let Some(line) = reader.next().await {
            let buffer = match line {
                Ok(b) => b,
                Err(_) => break,
            };

            if buffer.trim().is_empty() { continue; }

            let req: McpRequest = match serde_json::from_str(&buffer) {
                Ok(r) => r,
                Err(_) => continue,
            };
            
            let resp = process_request_matrix(state.clone(), req).await;
            let _ = writer.send(serde_json::to_string(&resp).unwrap()).await;
        }
        Ok(())
    }
}
