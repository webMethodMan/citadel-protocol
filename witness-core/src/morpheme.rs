use crate::types::WitnessError;
use sha3::{Digest, Sha3_256};

pub trait Morpheme: Send + Sync {
    fn identifier(&self) -> &[u8];
    fn generate_auth_hash(&self) -> Result<[u8; 32], WitnessError>;
}

pub struct A2AMorpheme<'a> {
    pub resource: [u8; 32],
    pub identity: [u8; 32],
    pub tool_id:  &'a str, 
}

impl<'a> Morpheme for A2AMorpheme<'a> {
    fn identifier(&self) -> &[u8] {
        self.tool_id.as_bytes()
    }

    fn generate_auth_hash(&self) -> Result<[u8; 32], WitnessError> {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.resource);
        hasher.update(&self.identity);
        hasher.update(self.tool_id.as_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        Ok(hash)
    }
}
