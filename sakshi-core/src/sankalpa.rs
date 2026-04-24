use crate::types::{Error, Mudra};
use sha3::{Digest, Sha3_256};

pub trait Sankalpa: Send + Sync {
    fn identifier(&self) -> &[u8];
    fn generate_auth_hash(&self) -> Result<Mudra, Error>;
}

pub struct SankalpaPayload<'a> {
    pub resource: [u8; 32],
    pub mudra: Mudra,
    pub tool_id:  &'a str, 
}

impl<'a> Sankalpa for SankalpaPayload<'a> {
    fn identifier(&self) -> &[u8] {
        self.tool_id.as_bytes()
    }

    fn generate_auth_hash(&self) -> Result<Mudra, Error> {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.resource);
        hasher.update(&self.mudra);
        hasher.update(self.tool_id.as_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        Ok(hash)
    }
}
