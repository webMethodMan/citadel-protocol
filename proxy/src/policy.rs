use std::collections::HashMap;
use sha3::{Digest, Sha3_256};

pub struct PolicyEngine {
    // Key: RIOM Hash, Value: Metadata (e.g., "Authorized by Theo")
    authorized_intents: HashMap<[u8; 32], String>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        let mut authorized = HashMap::new();
        
        // --- SEEDING THE FLOOR ---
        // In a real Citadel flow, this would be populated 
        // by listening to a Hedera Topic.
        let mut mock_intent_hash = [0u8; 32];
        // Let's pre-authorize our "Alpha" flow
        // (This would match the hash the Witness generates)
        authorized.insert([0x28, 0x6c, 0xd4, 0x5f, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 
            "Production Alpha Flow".to_string());

        Self { authorized_intents: authorized }
    }

    pub fn check_intent(&self, hash: &[u8; 32]) -> bool {
        // The "Floor" check: Does the ledger recognize this intent?
        self.authorized_intents.contains_key(hash)
    }
}
