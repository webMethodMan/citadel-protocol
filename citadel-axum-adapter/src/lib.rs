use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use base64::{engine::general_purpose, Engine as _};
use citadel_verifier::CitadelVerifier;
use sakshi_core::EvidenceVerifier;
use std::sync::Arc;
use tracing::{error, info};

/// Configuration for the Citadel Admissibility Guard.
#[derive(Clone)]
pub struct CitadelGuardConfig {
    pub verifier: Arc<dyn CitadelVerifier>,
    pub ledger_verifier: Option<Arc<dyn EvidenceVerifier>>,
    pub expected_mrtd: Option<[u8; 48]>,
}

/// Axum Middleware that enforces hardware-rooted technical integrity.
pub async fn citadel_admissibility_guard(
    State(config): State<CitadelGuardConfig>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    info!("GUARD: Intercepting request for Technical Integrity validation...");

    // 1. Extract X-Sakshi-Quote header
    let quote_header = req.headers()
        .get("X-Sakshi-Quote")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| hex::decode(s).ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // 2. Extract Client Certificate (from extensions, usually populated by mTLS terminator)
    // Note: This requires the Axum server to be running behind a proxy or with a custom 
    // acceptor that populates the TlsClientConfig extension.
    // For this scaffold, we look for a placeholder header if the extension is missing.
    let cert_der = req.extensions()
        .get::<axum::extract::connect_info::ConnectInfo<std::net::SocketAddr>>()
        .and_then(|_| {
            // In a real mTLS setup, extract actual DER from the peer certificate
            None::<Vec<u8>>
        })
        .or_else(|| {
            req.headers()
                .get("X-Sakshi-Cert-Placeholder")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| general_purpose::STANDARD.decode(s).ok())
        })
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // 3. Perform Verification
    match config.verifier.verify_pramana(
        &quote_header,
        &cert_der,
        config.expected_mrtd.as_ref(),
        None,
        config.ledger_verifier.as_ref().map(|v| v.as_ref()),
    ).await {
        Ok(identity) => {
            info!("GUARD: Admissibility GRANTED for SPIFFE: {}", identity.spiffe_id);
            // Optionally inject identity into request extensions for the next handler
            let mut req = req;
            req.extensions_mut().insert(identity);
            Ok(next.run(req).await)
        },
        Err(e) => {
            error!("GUARD: Admissibility REFUSED: {:?}", e);
            Err(StatusCode::FORBIDDEN)
        }
    }
}
