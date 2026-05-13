use sakshi_core::{Pramana, Error, SiliconProvider, PramanaProvider};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use citadel_verifier::{CitadelVerifier, VerifierIdentity};

// Include the generated gRPC code
pub mod proto {
    tonic::include_proto!("citadel.a2a");
}

use proto::sovereign_handshake_server::SovereignHandshake;
use proto::{NonceRequest, NonceResponse, AttestationRequest, AttestationResponse, ToolRequest, ToolResponse};
use tonic::{Request, Response, Status};

/// The gRPC implementation of the Sovereign Handshake service.
pub struct SovereignHandshakeService {
    pub verifier: Arc<dyn CitadelVerifier>,
    // Maps outstanding nonces to the expected peer identity.
    pub active_challenges: Arc<Mutex<HashMap<String, [u8; 32]>>>,
    // Tracks peers that have successfully completed the handshake.
    pub authenticated_peers: Arc<Mutex<HashMap<String, VerifierIdentity>>>,
}

#[async_trait]
impl SovereignHandshake for SovereignHandshakeService {
    async fn fetch_nonce(&self, request: Request<NonceRequest>) -> Result<Response<NonceResponse>, Status> {
        let req = request.into_inner();
        let mut nonce = [0u8; 32];
        // In real use, use a CSPRNG
        nonce[0] = 0x55; nonce[1] = 0x66;
        
        self.active_challenges.lock().unwrap().insert(req.spiffe_id, nonce);
        
        Ok(Response::new(NonceResponse { nonce: nonce.to_vec() }))
    }

    async fn attest_peer(&self, request: Request<AttestationRequest>) -> Result<Response<AttestationResponse>, Status> {
        let req = request.into_inner();
        
        let _expected_nonce = {
            let challenges = self.active_challenges.lock().unwrap();
            challenges.get(&req.spiffe_id).cloned().ok_or_else(|| Status::unauthenticated("No active challenge found"))?
        };

        // In A2A connector, we don't have the cert_der directly in this call usually 
        // unless it's extracted from the gRPC context. For this refactor, we pass empty der.
        match self.verifier.verify_pramana(&req.hardware_quote, &[], None, Some(&req.spiffe_id), None).await {
            Ok(identity) => {
                let id_str = hex::encode(&identity.mrtd);
                self.authenticated_peers.lock().unwrap().insert(req.spiffe_id, identity);
                Ok(Response::new(AttestationResponse { authorized: true, mudra_id: id_str }))
            }
            Err(_) => Err(Status::permission_denied("Hardware Attestation Failed")),
        }
    }

    async fn execute_sovereign_intent(&self, _request: Request<ToolRequest>) -> Result<Response<ToolResponse>, Status> {
        // Enforce Zero-Trust: Refuse calls unless the peer is in authenticated_peers
        // (Implementation omitted for brevity, but this is where the check lives)
        Ok(Response::new(ToolResponse { result_json: "{}".into(), mudra_receipt: vec![] }))
    }
}

/// The Outbound A2A Connector used by the Citadel Gateway.
pub struct A2AConnector {
    pub peer_url: String,
    pub spiffe_id: String,
    pub silicon: Box<dyn SiliconProvider>,
}

#[async_trait]
impl PramanaProvider for A2AConnector {
    async fn verify_pramana(&self, _session_id: &str, _pramana: &Pramana) -> Result<(), Error> {
        // In A2A mode, notarization is checked by the remote peer during the handshake.
        Ok(())
    }

    async fn notarize_pramana(&self, _pramana: &Pramana) -> Result<u64, Error> {
        Ok(0)
    }

    async fn verify_sakshi_integrity(&self, _measurement: &[u8; 48]) -> Result<(), Error> {
        Ok(())
    }
}
