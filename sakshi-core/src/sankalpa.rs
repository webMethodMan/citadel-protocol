use crate::types::{Error, Mudra};
use sha3::{Digest, Sha3_256};

pub trait SankalpaHasher: Send + Sync {
    fn hash(&self, data: &[&[u8]]) -> Mudra;
}

pub struct Sha3_256Hasher;

impl SankalpaHasher for Sha3_256Hasher {
    fn hash(&self, data: &[&[u8]]) -> Mudra {
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

pub trait SankalpaVerifier: Send + Sync {
    fn verify(&self, intent: &dyn Sankalpa, proof: &[u8]) -> Result<(), Error>;
}

pub struct DefaultHashVerifier<'a> {
    pub hasher: &'a dyn SankalpaHasher,
}

impl<'a> SankalpaVerifier for DefaultHashVerifier<'a> {
    fn verify(&self, intent: &dyn Sankalpa, proof: &[u8]) -> Result<(), Error> {
        let actual = intent.generate_auth_hash(self.hasher)?;
        if actual != proof {
            return Err(Error::SecurityViolation);
        }
        Ok(())
    }
}

pub trait Sankalpa: Send + Sync {
    fn identifier(&self) -> &[u8];
    fn generate_auth_hash(&self, hasher: &dyn SankalpaHasher) -> Result<Mudra, Error>;
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

    fn generate_auth_hash(&self, hasher: &dyn SankalpaHasher) -> Result<Mudra, Error> {
        Ok(hasher.hash(&[
            &self.resource,
            &self.mudra,
            self.tool_id.as_bytes(),
        ]))
    }
}
