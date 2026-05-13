use async_trait::async_trait;
use crate::AppState;
use crate::mcp::{McpRequest, McpResponse, process_request_matrix};
use crate::transport::InboundTransport;
use sakshi_core::Error;
use std::sync::Arc;
use axum::{routing::post, Json, Router, extract::State, extract::DefaultBodyLimit};
use tokio::net::TcpListener;
use tracing::info;

pub struct McpSseTransport {
    pub port: u16,
}

#[async_trait]
impl InboundTransport for McpSseTransport {
    async fn listen(&self, state: Arc<AppState>) -> Result<(), Error> {
        let addr = format!("127.0.0.1:{}", self.port);
        let app = Router::new()
            .route("/mcp", post(mcp_handler))
            .layer(DefaultBodyLimit::max(10 * 1024 * 1024))
            .with_state(state);

        info!("--- Citadel SSE Gateway: ACTIVE | Port {} ---", addr);
        let listener = TcpListener::bind(&addr).await.map_err(|_| Error::InitializationError)?;
        axum::serve(listener, app).await.map_err(|_| Error::InitializationError)?;
        Ok(())
    }
}

async fn mcp_handler(State(state): State<Arc<AppState>>, Json(req): Json<McpRequest>) -> Json<McpResponse> {
    Json(process_request_matrix(state, req).await)
}
