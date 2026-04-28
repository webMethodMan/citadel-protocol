use minicbor::{Encode, Decode};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[cbor(index_only)]
pub enum Error {
    #[n(0)] SecurityViolation,
    #[n(1)] HardwareFault,
    #[n(2)] DeviceError,
    #[n(3)] ProtocolMismatch,
    #[n(4)] InitializationError,
}

#[derive(Debug, Clone, Encode, Decode, serde::Serialize)]
pub struct Mudra {
    #[n(0)] pub seal: [u8; 32],
    #[n(1)] #[cbor(with = "minicbor::bytes")] pub hardware_quote: Vec<u8>,
}

/// Pramana (The Admissible Proof): The unforgeable artifact attesting to the deterministic
/// validity of the reasoning chain. It bridges the Sakshi's observation to the Mudra.
#[derive(Debug, Clone, Encode, Decode, serde::Serialize)]
pub struct Pramana {
    #[n(0)] #[cbor(with = "minicbor::bytes")] pub report: Vec<u8>,
    #[n(1)] pub ledger_hash: Option<[u8; 32]>,
}

/// Recommendation 1: W3C VC Alignment via portable CBOR
#[derive(Debug, Clone, Encode, Decode)]
pub struct VerifiableCredential<'a> {
    #[n(0)] pub context: u8, 
    #[n(1)] pub issuer: [u8; 32],
    #[n(2)] pub valid_from: u64,
    #[n(3)] pub valid_until: u64,
    #[n(4)] pub identity_hash: [u8; 32],
    #[n(5)] pub capability: &'a str, 
    #[n(6)] pub signature: [u8; 64],
}

/// Recommendation 4: Contextual Envelope
#[derive(Debug, Clone, Encode, Decode)]
pub struct EnvironmentContext {
    #[n(0)] pub current_timestamp: u64,
    #[n(1)] pub system_state_hash: [u8; 32],
}

#[derive(Debug, Clone, Encode, Decode, serde::Serialize)]
pub struct AttestationCollateral {
    #[n(0)] #[cbor(with = "minicbor::bytes")] pub pck_certificate: Vec<u8>, // Intel PCK Cert
    #[n(1)] #[cbor(with = "minicbor::bytes")] pub tcb_info: Vec<u8>,        // Intel TCB Info JSON
    #[n(2)] #[cbor(with = "minicbor::bytes")] pub qe_identity: Vec<u8>,      // Quoting Enclave Identity
}

#[derive(Debug, Clone, Encode, Decode, serde::Serialize)]
pub struct ProvenanceBundle {
    #[n(0)] #[cbor(with = "minicbor::bytes")] pub quote: Vec<u8>,           // The TEE-signed Quote
    #[n(1)] pub collateral: AttestationCollateral,
}

/// Recommendation 3: CCC and NIST alignment for Workload Identity
#[derive(Debug, Clone, Encode, Decode)]
pub struct WorkloadIdentity<'a> {
    #[n(0)] pub measurement: [u8; 48],     // MRTD / Static Identity
    #[n(1)] pub tcb_svn: u16,              // Security Version Number
    #[n(2)] pub hardware_root: [u8; 32],   // Root of Trust
    #[n(3)] pub runtime_claims: [u8; 32],  // RTMR / Dynamic Identity
    #[n(4)] #[cbor(with = "minicbor::bytes")] pub attestation_cert: Option<&'a [u8]>, // Hardware AK Certificate
}
