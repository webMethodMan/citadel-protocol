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

#[derive(Debug)]
pub enum EvidenceError {
    Timeout,
    TransportError(String),
}

#[async_trait]
pub trait PramanaRepository: Send + Sync {
    async fn append_evidence(&self, event: SovereignEvent) -> Result<(), EvidenceError>;
}

#[async_trait]
pub trait EvidenceVerifier: Send + Sync {
    /// Checks if a specific intent (Mudra seal) has been notarized on the ledger.
    async fn check_notarization(&self, mudra_seal: &[u8; 32]) -> Result<bool, EvidenceError>;
}
