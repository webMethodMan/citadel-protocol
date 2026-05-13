use crate::{SiliconProvider, Error, WorkloadIdentity, types::Mrtd};

#[cfg(not(feature = "std"))]
use alloc::vec;

pub struct MockProvider {
    pub expected_mrtd: Mrtd,
}

impl MockProvider {
    pub fn new(expected_mrtd: [u8; 48]) -> Self {
        Self { expected_mrtd: Mrtd(expected_mrtd) }
    }
}

impl SiliconProvider for MockProvider {
    fn vendor(&self) -> &'static str { "Citadel Simulated Silicon" }

    fn get_report(&self, data: [u8; 32]) -> Result<[u8; 1024], Error> {
        let mut report = [0u8; 1024];
        report[..32].copy_from_slice(&data);
        Ok(report)
    }

    fn extract_identity<'a>(&'a self, _report: &'a [u8; 1024]) -> Result<WorkloadIdentity<'a>, Error> {
        Ok(WorkloadIdentity {
            measurement: self.expected_mrtd,
            tcb_svn: 1,
            hardware_root: [0xaa; 32],
            runtime_claims: [0xbb; 32],
            attestation_cert: None,
        })
    }

    fn verify_genuineness(&self, _report: &[u8; 1024]) -> Result<(), Error> {
        // In a real provider, this would verify the TEE report signature
        Ok(())
    }

    fn generate_bundle(&self, _report: &[u8; 1024]) -> Result<crate::ProvenanceBundle, Error> {
        Ok(crate::ProvenanceBundle {
            quote: vec![0xcc; 512], // Dummy Quote
            collateral: crate::AttestationCollateral {
                pck_certificate: vec![0xdd; 1024],
                tcb_info: b"{\"version\": 3, \"tcb\": \"mock\"}".to_vec(),
                qe_identity: vec![0xee; 256],
            },
        })
    }
}
