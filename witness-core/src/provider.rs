use crate::{SiliconProvider, WitnessError};

pub struct MockProvider;

impl SiliconProvider for MockProvider {
    fn get_report(&self, _data: [u8; 32]) -> Result<[u8; 1024], WitnessError> {
        Ok([0u8; 1024])
    }

    fn extract_mrtd(&self, _report: &[u8; 1024]) -> [u8; 48] {
        [0u8; 48]
    }
}
