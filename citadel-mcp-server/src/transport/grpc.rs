use async_trait::async_trait;
use crate::AppState;
use crate::transport::InboundTransport;
use sakshi_core::Error;
use std::sync::Arc;
use citadel_a2a_connector::{SovereignHandshakeService};
use citadel_verifier::TdxVerifier;
use citadel_a2a_connector::proto::sovereign_handshake_server::SovereignHandshakeServer;
use tracing::info;

pub struct GrpcTransport {
    pub port: u16,
}

#[async_trait]
impl InboundTransport for GrpcTransport {
    async fn listen(&self, state: Arc<AppState>) -> Result<(), Error> {
        let addr: std::net::SocketAddr = format!("127.0.0.1:{}", self.port).parse().map_err(|_| Error::InitializationError)?;
        
        let service = SovereignHandshakeService {
            verifier: Arc::new(TdxVerifier { golden_mrtd: None }),
            active_challenges: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            authenticated_peers: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        };

        info!("--- Sovereign Spine gRPC: ACTIVE | Port {} ---", addr.port());
        
        let t = state.token.clone();
        tonic::transport::Server::builder()
            .add_service(SovereignHandshakeServer::new(service))
            .serve_with_shutdown(addr, t.cancelled())
            .await
            .map_err(|_| Error::InitializationError)?;
            
        Ok(())
    }
}
