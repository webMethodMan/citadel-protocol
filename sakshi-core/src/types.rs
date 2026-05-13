use minicbor::{Encode, Decode};
use thiserror::Error;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, Error, Encode, Decode, PartialEq, Eq)]
#[cbor(index_only)]
pub enum Error {
    #[error("Security violation: Technical integrity compromised")]
    #[n(0)] SecurityViolation,
    
    #[error("Hardware fault: TEE device failure")]
    #[n(1)] HardwareFault,
    
    #[error("Device error: IO or driver failure")]
    #[n(2)] DeviceError,
    
    #[error("Protocol mismatch: Unexpected message format")]
    #[n(3)] ProtocolMismatch,
    
    #[error("Initialization error: Failed to bootstrap protocol")]
    #[n(4)] InitializationError,

    #[error("Policy violation: Admissibility gate refusal")]
    #[n(5)] PolicyViolation,

    #[error("Registry error: Failed to notarize or verify evidence")]
    #[n(6)] RegistryError,
}

// Implement a simple copy for compatibility if needed, though thiserror might make it harder if we have String.
// Since we used String in DeviceError, it's no longer Copy.
// Let's check if we really need Copy. The original had Copy.
// If we want to keep Copy, we can't have String.
// For now, I'll remove Copy and see what breaks.

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, serde::Serialize)]
#[cbor(transparent)]
pub struct Mrtd(
    #[n(0)] 
    #[serde(with = "serde_bytes")]
    pub [u8; 48]
);

impl Mrtd {
    pub fn from_hex(hex_str: &str) -> Result<Self, Error> {
        let clean_hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(clean_hex).map_err(|_| Error::InitializationError)?;
        if bytes.len() != 48 {
            return Err(Error::InitializationError);
        }
        let mut mrtd = [0u8; 48];
        mrtd.copy_from_slice(&bytes);
        Ok(Mrtd(mrtd))
    }
}

impl AsRef<[u8; 48]> for Mrtd {
    fn as_ref(&self) -> &[u8; 48] {
        &self.0
    }
}

/// Recommendation 3: CCC and NIST alignment for Workload Identity
#[derive(Debug, Clone, Encode, Decode)]
pub struct WorkloadIdentity<'a> {
    #[n(0)] pub measurement: Mrtd,         // MRTD / Static Identity
    #[n(1)] pub tcb_svn: u16,              // Security Version Number
    #[n(2)] pub hardware_root: [u8; 32],   // Root of Trust
    #[n(3)] pub runtime_claims: [u8; 32],  // RTMR / Dynamic Identity
    #[n(4)] #[cbor(with = "minicbor::bytes")] pub attestation_cert: Option<&'a [u8]>, // Hardware AK Certificate
}
