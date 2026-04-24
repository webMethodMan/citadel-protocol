use sakshi_core::{SiliconProvider, Error};

pub struct TdxProvider;

impl SiliconProvider for TdxProvider {
    fn get_report(&self, _data: [u8; 32]) -> Result<[u8; 1024], Error> {
        // Driver logic for /dev/tdx_guest goes here
        Ok([0u8; 1024])
    }

    fn extract_mrtd(&self, _report: &[u8; 1024]) -> [u8; 48] {
        // Extract MRTD from real TDREPORT at offset 384
        [0u8; 48]
    }
}
