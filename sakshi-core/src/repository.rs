use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use minicbor::{Encode, Decode};

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec, boxed::Box};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Encode, Decode)]
#[cbor(index_only)]
pub enum LifecycleStage {
    #[n(0)] AdmissibilityRefusal,
    #[n(1)] SankalpaIntent,
    #[n(2)] ExecutionCompletion,
    #[n(3)] SystemFailure,
    #[n(4)] SovereignAnchor,
    #[n(5)] PolicyUpdate,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SovereignEvent {
    #[n(0)] pub stage: LifecycleStage,
    #[n(1)] pub sankalpa_hash: [u8; 32],
    #[n(2)] pub ve_decay_rate: f64,
    #[n(3)] pub spiffe_id: String,
    #[n(4)] #[cbor(with = "minicbor::bytes")] pub tdx_quote: Option<Vec<u8>>,
    #[n(5)] pub response_hash: Option<[u8; 32]>,
    #[n(6)] pub error_message: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error("Evidence submission timeout")]
    Timeout,
    #[error("Transport error: {0}")]
    TransportError(String),
}

#[async_trait]
pub trait PramanaRepository: Send + Sync {
    /// Appends evidence to the repository and returns the sequence number (u64)
    async fn append_evidence(&self, event: SovereignEvent) -> Result<u64, EvidenceError>;
}

#[async_trait]
pub trait EvidenceVerifier: Send + Sync {
    /// Checks if a specific intent (Mudra seal) has been notarized on the ledger.
    async fn check_notarization(&self, mudra_seal: &[u8; 32]) -> Result<bool, EvidenceError>;

    /// Performs an O(1) lookup at a specific sequence number to verify admissibility.
    async fn verify_at_sequence(&self, sequence_number: u64, expected_sankalpa_hash: &[u8; 32]) -> Result<bool, EvidenceError>;
}
