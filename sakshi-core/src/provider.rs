use crate::{SiliconProvider, Error};

pub struct MockProvider {
    pub expected_mrtd: [u8; 48],
}

impl MockProvider {
    pub fn new(expected_mrtd: [u8; 48]) -> Self {
        Self { expected_mrtd }
    }
}

impl SiliconProvider for MockProvider {
    fn get_report(&self, _data: [u8; 32]) -> Result<[u8; 1024], Error> {
        Ok([0u8; 1024])
    }

    fn extract_mrtd(&self, _report: &[u8; 1024]) -> [u8; 48] {
        self.expected_mrtd
    }
}
