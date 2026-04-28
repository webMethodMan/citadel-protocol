use crate::types::{Error, VerifiableCredential, EnvironmentContext, Pramana};
use sha3::{Digest, Sha3_256};

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String, vec, vec::Vec};

pub trait SankalpaHasher: Send + Sync {
    fn hash(&self, data: &[&[u8]]) -> [u8; 32];
}

pub struct Sha3_256Hasher;

impl SankalpaHasher for Sha3_256Hasher {
    fn hash(&self, data: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        for chunk in data {
            hasher.update(chunk);
        }
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

pub trait Sankalpa: Send + Sync {
    fn identifier(&self) -> &[u8];
    fn generate_auth_hash(&self, hasher: &dyn SankalpaHasher) -> Result<[u8; 32], Error>;
    fn max_decay(&self) -> f64;
}

pub struct SovereignPayload<'a> {
    pub resource: [u8; 32],
    pub mudra: [u8; 32], 
    pub tool_id:  &'a str,
    pub spiffe_id: Option<String>,
    pub nonce: [u8; 32],
    pub max_decay: f64, // Mandated degradation limit from the mandate
    pub authority_hash: [u8; 32],
    pub integrity_hash: [u8; 32],
}

impl<'a> Sankalpa for SovereignPayload<'a> {
    fn identifier(&self) -> &[u8] {
        self.tool_id.as_bytes()
    }

    fn generate_auth_hash(&self, hasher: &dyn SankalpaHasher) -> Result<[u8; 32], Error> {
        let max_decay_bytes = self.max_decay.to_be_bytes();
        let mut data = vec![
            &self.resource[..],
            &self.mudra[..],
            self.tool_id.as_bytes(),
        ];
        if let Some(ref id) = self.spiffe_id {
            data.push(id.as_bytes());
        }
        data.push(&self.nonce[..]);
        data.push(&max_decay_bytes[..]);
        data.push(&self.authority_hash[..]);
        data.push(&self.integrity_hash[..]);
        
        Ok(hasher.hash(&data))
    }

    fn max_decay(&self) -> f64 {
        self.max_decay
    }
}

pub trait PolicyComparator: Send + Sync {
    /// Deterministically evaluates the empirical state against the mandate
    fn evaluate_synthesis(&self, telemetry: &TelemetryState, mandate: &dyn Sankalpa) -> Result<(), Error>;
}

/// SignedTelemetry: The cryptographically notarized reading from the MTCP node
#[derive(Clone)]
pub struct SignedTelemetry {
    pub state: TelemetryState,
    pub signature: [u8; 64],
}

#[derive(Clone)]
pub struct TelemetryState {
    pub ve_decay_rate: f64,
    pub authority_hash: [u8; 32],
    pub integrity_hash: [u8; 32],
}

impl TelemetryState {
    /// Extracts a byte representation for signature verification
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.ve_decay_rate.to_be_bytes());
        b.extend_from_slice(&self.authority_hash);
        b.extend_from_slice(&self.integrity_hash);
        b
    }
}

/// Recommendation 2: Interface Decoupling (Inbound)
/// Decouples hardware witness from specific upstream protocols (MCP, A2A)
pub enum InboundContext<'a> {
    Mcp { 
        tool_name: &'a str, 
        mudra: [u8; 32], 
        resource: [u8; 32], 
        spiffe_id: Option<String>,
        nonce: [u8; 32],
        telemetry: SignedTelemetry,
        max_decay: f64,
    },
    A2A { 
        agent_id: &'a [u8; 32], 
        action: &'a str, 
        nonce: [u8; 32],
        telemetry: SignedTelemetry,
        max_decay: f64,
    },
}

pub trait IntentTranslator: Send + Sync {
    fn translate_intent<'a>(&self, ctx: InboundContext<'a>) -> Result<SovereignPayload<'a>, Error>;
}

/// PramanaProvider: The deterministic interface for verifying and notarizing Pramanas
/// against a hardware root of trust and a shared ledger.
#[async_trait::async_trait]
pub trait PramanaProvider: Send + Sync {
    async fn verify_pramana(&self, pramana: &Pramana) -> Result<(), Error>;
    async fn notarize_pramana(&self, pramana: &Pramana) -> Result<(), Error>;
    async fn verify_sakshi_integrity(&self, measurement: &[u8; 48]) -> Result<(), Error>;
}

/// Recommendation 4: The Granular Airlock
pub trait AirlockPolicyEngine: Send + Sync {
    fn evaluate_admissibility(
        &self,
        intent: &dyn Sankalpa,
        credential: &VerifiableCredential,
        env: &EnvironmentContext,
        hasher: &dyn SankalpaHasher,
    ) -> Result<(), Error>;
}

pub struct DeterministicAirlock;

impl AirlockPolicyEngine for DeterministicAirlock {
    fn evaluate_admissibility(
        &self,
        intent: &dyn Sankalpa,
        credential: &VerifiableCredential,
        env: &EnvironmentContext,
        hasher: &dyn SankalpaHasher,
    ) -> Result<(), Error> {
        // 1. Temporal Window Envelope (Hard-fail on logical discontinuity)
        if env.current_timestamp != 0 && (env.current_timestamp < credential.valid_from || env.current_timestamp > credential.valid_until) {
            return Err(Error::SecurityViolation);
        }

        // 2. Cryptographic Binding (Ensures VC maps to the requested intent)
        let intent_hash = intent.generate_auth_hash(hasher)?;
        if intent_hash != credential.identity_hash {
            return Err(Error::SecurityViolation);
        }

        // 3. Capability Scope Verification
        if intent.identifier() != credential.capability.as_bytes() {
            return Err(Error::SecurityViolation);
        }

        Ok(())
    }
}
