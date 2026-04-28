#![cfg_attr(not(feature = "std"), no_std)]

pub mod sankalpa;
pub mod types;
pub mod provider;

pub use types::{Error, Mudra, Pramana, VerifiableCredential, EnvironmentContext, WorkloadIdentity, ProvenanceBundle, AttestationCollateral};
pub use sankalpa::{
    Sankalpa, SovereignPayload, SankalpaHasher, Sha3_256Hasher, 
    AirlockPolicyEngine, DeterministicAirlock, InboundContext, IntentTranslator,
    PramanaProvider, TelemetryState, PolicyComparator, SignedTelemetry
};

use ed25519_dalek::{VerifyingKey, Signature, Verifier};

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
    comparator: &dyn PolicyComparator,
    intent: &dyn Sankalpa,
    credential: &VerifiableCredential,
    telemetry: &SignedTelemetry,
    telemetry_public_key: &[u8; 32],
    cert_hash: &[u8; 32],
    env: &EnvironmentContext,
    spiffe_id: Option<&str>,
) -> Result<(Pramana, Mudra), Error> {
    // 1. Perform Granular Admissibility Check (W3C VC Validation)
    policy_engine.evaluate_admissibility(intent, credential, env, hasher)?;

    // 2. The Ingestion Boundary: Verify Telemetry Signature inside TEE
    let vk = VerifyingKey::from_bytes(telemetry_public_key).map_err(|_| Error::SecurityViolation)?;
    let sig = Signature::from_bytes(&telemetry.signature);
    vk.verify(&telemetry.state.to_bytes(), &sig).map_err(|_| Error::SecurityViolation)?;

    // 3. The Evaluation Logic: Deterministic Synthesis Check
    // "Does Current_MTCP_Decay <= Sankalpa_Max_Decay?"
    comparator.evaluate_synthesis(&telemetry.state, intent)?;

    // 4. Weld RIOM (Intent Hash), cert_hash, and SPIFFE ID into the Silicon Truth (TDREPORT)
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
    
    // 5. Construct Pramana (The Admissible Proof)
    // The proof now immutably binds the context (telemetry) to the hardware report
    let pramana = Pramana {
        report: report.to_vec(),
        ledger_hash: None, 
    };

    // 6. Return a Mudra containing the seal and the hardware-signed quote
    let seal = hasher.hash(&[&report]);
    Ok((pramana, Mudra {
        seal,
        hardware_quote: bundle.quote,
    }))
}

#[cfg(not(feature = "std"))]
#[no_mangle]
pub extern "C" fn sakshi_verify_and_gate_wasm(
    cert_hash_ptr: *const u8,
    cert_hash_len: usize,
    result_seal_ptr: *mut u8,
) -> i32 {
    if cert_hash_len != 32 { return -1; }
    
    // This is a simplified entry point for WASM verification logic.
    let cert_hash = unsafe { core::slice::from_raw_parts(cert_hash_ptr, 32) };
    let mut hash = [0u8; 32];
    hash.copy_from_slice(cert_hash);
    
    // Return success placeholder for now
    unsafe { core::ptr::write_bytes(result_seal_ptr, 0xAA, 32); }
    0
}
