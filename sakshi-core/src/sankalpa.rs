use crate::types::{Error, VerifiableCredential, EnvironmentContext};
use sha3::{Digest, Sha3_256};

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

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
}

pub struct SankalpaPayload<'a> {
    pub resource: [u8; 32],
    pub mudra: [u8; 32], // This is now the static seal/binding, not the full Mudra struct
    pub tool_id:  &'a str,
    pub spiffe_id: Option<String>,
    pub nonce: [u8; 32],
}

impl<'a> Sankalpa for SankalpaPayload<'a> {
    fn identifier(&self) -> &[u8] {
        self.tool_id.as_bytes()
    }

    fn generate_auth_hash(&self, hasher: &dyn SankalpaHasher) -> Result<[u8; 32], Error> {
        let mut data = vec![
            &self.resource[..],
            &self.mudra[..],
            self.tool_id.as_bytes(),
        ];
        if let Some(ref id) = self.spiffe_id {
            data.push(id.as_bytes());
        }
        // Strictly concatenate the nonce as per Sovereign Handshake Scope 1
        data.push(&self.nonce[..]);
        
        Ok(hasher.hash(&data))
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
    },
    A2A { agent_id: &'a [u8; 32], action: &'a str, nonce: [u8; 32] },
}

pub trait IntentTranslator: Send + Sync {
    fn translate_intent<'a>(&self, ctx: InboundContext<'a>) -> Result<SankalpaPayload<'a>, Error>;
}

/// Recommendation 2/3: Attestation Connector (Outbound to Attestor/Hashgraph)
#[async_trait::async_trait]
pub trait AttestationConnector: Send + Sync {
    async fn validate_notarization(&self, riom_hash: &[u8; 32]) -> Result<(), Error>;
    async fn submit_hardware_proof(&self, report: &[u8; 1024]) -> Result<(), Error>;
    async fn verify_self_integrity(&self, measurement: &[u8; 48]) -> Result<(), Error>;
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
