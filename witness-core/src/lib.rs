#![cfg_attr(not(feature = "std"), no_std)]

pub mod morpheme;
pub mod types;
pub mod provider;

pub use types::WitnessError;
pub use morpheme::{Morpheme, A2AMorpheme};

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

pub struct AttestationPayload {
    pub report: [u8; 1024],
    pub mrtd: [u8; 48],
}

pub trait SiliconProvider: Send + Sync {
    fn get_report(&self, report_data: [u8; 32]) -> Result<[u8; 1024], WitnessError>;
    fn extract_mrtd(&self, report: &[u8; 1024]) -> [u8; 48];
}

pub fn verify_and_gate(
    _provider: &dyn SiliconProvider,
    intent: &dyn Morpheme,
    ledger_hash: &[u8; 32],
) -> Result<[u8; 32], WitnessError> {
    let hash = intent.generate_auth_hash()?;
    if hash != *ledger_hash {
        return Err(WitnessError::SecurityViolation);
    }
    Ok([0u8; 32])
}

// Our exported reactor entry point for the Sidecar/Proxy
#[no_mangle]
pub extern "C" fn witness_entry() {
    // Citadel Boundary Logic
}
