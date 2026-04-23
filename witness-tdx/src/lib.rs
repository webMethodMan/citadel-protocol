use witness_core::{SiliconProvider, WitnessError, AttestationPayload};

pub struct TdxProvider;

impl SiliconProvider for TdxProvider {
    fn get_report(&self, _data: [u8; 32]) -> Result<AttestationPayload, WitnessError> {
        // Driver logic for /dev/tdx_guest goes here
        Ok(AttestationPayload { data: [0u8; 1024] })
    }

    fn extract_mrtd(&self, _payload: &AttestationPayload) -> [u8; 48] {
        // Extract MRTD from real TDREPORT at offset 384
        [0u8; 48]
    }
}
