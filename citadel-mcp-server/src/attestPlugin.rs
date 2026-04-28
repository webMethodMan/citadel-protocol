use async_trait::async_trait;
use sakshi_core::{Error, Pramana, PramanaProvider};

#[async_trait]
pub trait PramanaValidator: Send + Sync {
    /// The "Pre-Flight" check: Does the ledger/policy allow this intent?
    async fn validate_intent(&self, riom_hash: &[u8; 32]) -> Result<(), Error>;
}

// --- Implementation 1: The Hedera-Ready Mock ---
pub struct HederaPlugin {
    pub topic_id: String,
}

#[async_trait]
impl PramanaProvider for HederaPlugin {
    async fn verify_pramana(&self, _pramana: &Pramana) -> Result<(), Error> {
        Ok(())
    }

    async fn notarize_pramana(&self, _pramana: &Pramana) -> Result<(), Error> {
        eprintln!("HEDERA_PLUGIN: Submitting Pramana to HCS Topic {}...", self.topic_id);
        Ok(())
    }

    async fn verify_sakshi_integrity(&self, _measurement: &[u8; 48]) -> Result<(), Error> {
        Ok(())
    }
}

impl HederaPlugin {
    pub async fn validate_intent(&self, riom_hash: &[u8; 32]) -> Result<(), Error> {
        eprintln!("HEDERA_PLUGIN: Validating hash {:02x?} against Topic {}", 
            &riom_hash[..4], self.topic_id);
        
        if riom_hash[0] == 0x28 { 
            Ok(()) 
        } else {
            Err(Error::SecurityViolation)
        }
    }
}
