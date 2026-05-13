use async_trait::async_trait;
use crate::AppState;
use std::sync::Arc;
use sakshi_core::Error;

#[async_trait]
pub trait InboundTransport: Send + Sync {
    async fn listen(&self, state: Arc<AppState>) -> Result<(), Error>;
}

#[cfg(feature = "stdio")]
pub mod stdio;
#[cfg(feature = "sse")]
pub mod sse;
pub mod grpc;
