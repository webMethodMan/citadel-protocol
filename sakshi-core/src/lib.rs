#![cfg_attr(not(feature = "std"), no_std)]

pub mod sankalpa;
pub mod types;
pub mod provider;

pub use types::{Error, Mudra, VerifiableCredential, EnvironmentContext, WorkloadIdentity, ProvenanceBundle, AttestationCollateral};
pub use sankalpa::{
    Sankalpa, SankalpaPayload, SankalpaHasher, Sha3_256Hasher, 
    AirlockPolicyEngine, DeterministicAirlock, InboundContext, IntentTranslator,
    AttestationConnector
};

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
#[global_allocator]
static ALLOC: lol_alloc::AssumeSingleThreaded<lol_alloc::FreeListAllocator> =
    unsafe { lol_alloc::AssumeSingleThreaded::new(lol_alloc::FreeListAllocator::new()) };

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

pub trait SiliconProvider: Send + Sync {
    fn vendor(&self) -> &'static str;
    fn get_report(&self, report_data: [u8; 32]) -> Result<[u8; 1024], Error>;
    fn extract_identity<'a>(&'a self, report: &'a [u8; 1024]) -> Result<WorkloadIdentity<'a>, Error>;
    fn verify_genuineness(&self, report: &[u8; 1024]) -> Result<(), Error>;
    fn generate_bundle(&self, report: &[u8; 1024]) -> Result<ProvenanceBundle, Error>;
}

pub fn verify_and_gate(
    provider: &dyn SiliconProvider,
    policy_engine: &dyn AirlockPolicyEngine,
    hasher: &dyn SankalpaHasher,
    intent: &dyn Sankalpa,
    credential: &VerifiableCredential,
    cert_hash: &[u8; 32],
    env: &EnvironmentContext,
    spiffe_id: Option<&str>,
) -> Result<Mudra, Error> {
    // 1. Perform Granular Admissibility Check (Recommendation 4)
    policy_engine.evaluate_admissibility(intent, credential, env, hasher)?;

    // 2. Weld RIOM (Intent Hash), cert_hash, and SPIFFE ID into the Silicon Truth (TDREPORT)
    // Note: Intent auth hash now includes the 32-byte nonce as per Sovereign Handshake Scope 1
    let proof = intent.generate_auth_hash(hasher)?;
    
    let mut spiffe_hash = [0u8; 32];
    if let Some(id) = spiffe_id {
        spiffe_hash = hasher.hash(&[id.as_bytes()]);
    }

    let mut report_data = [0u8; 32];
    for i in 0..32 {
        report_data[i] = proof[i] ^ cert_hash[i] ^ spiffe_hash[i];
    }

    let report = provider.get_report(report_data)?;
    let bundle = provider.generate_bundle(&report)?;
    
    // 3. Return a Mudra containing the seal and the hardware-signed quote
    let seal = hasher.hash(&[&report]);
    Ok(Mudra {
        seal,
        hardware_quote: bundle.quote,
    })
}
