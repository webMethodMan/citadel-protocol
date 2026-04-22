use async_trait::async_trait;
use witness::WitnessError;

#[async_trait]
pub trait AttestationPlugin: Send + Sync {
    /// The "Pre-Flight" check: Does the ledger/policy allow this intent?
    async fn validate_intent(&self, riom_hash: &[u8; 32]) -> Result<(), WitnessError>;
    
    /// The "Post-Flight" check: Notarize the hardware report to the ledger.
    async fn notarize_report(&self, report: &[u8; 1024]) -> Result<(), WitnessError>;
}

// --- Implementation 1: The Hedera-Ready Mock ---
pub struct HederaPlugin {
    pub topic_id: String,
}

#[async_trait]
impl AttestationPlugin for HederaPlugin {
    async fn validate_intent(&self, riom_hash: &[u8; 32]) -> Result<(), WitnessError> {
        eprintln!("HEDERA_PLUGIN: Validating hash {:02x?} against Topic {}", 
            &riom_hash[..4], self.topic_id);
        
        // This is where the Hedera Mirror Node call will eventually go.
        // For now, we allow everything that starts with our known bytes.
        if riom_hash[0] == 0x28 { 
            Ok(()) 
        } else {
            Err(WitnessError::SecurityViolation)
        }
    }

    async fn notarize_report(&self, _report: &[u8; 1024]) -> Result<(), WitnessError> {
        eprintln!("HEDERA_PLUGIN: Submitting hardware proof to HCS...");
        // This is where 'TopicMessageSubmitTransaction' will live.
        Ok(())
    }
}
