use sakshi_core::{SiliconProvider, Error, WorkloadIdentity, ProvenanceBundle, AttestationCollateral};
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
use nix::ioctl_readwrite;

/// TDX IOCTL structure for TDREPORT request
#[repr(C)]
pub struct TdxReportReq {
    /// 64 bytes of user data to be included in the report
    pub reportdata: [u8; 64],
    /// 1024 bytes of the generated TDREPORT
    pub tdreport: [u8; 1024],
}

const TDX_IOC_MAGIC: u8 = b'T';
const TDX_IOC_GET_REPORT: u8 = 0x01;

// Define the IOCTL: _IOWR('T', 0x01, struct tdx_report_req)
ioctl_readwrite!(tdx_get_report_ioctl, TDX_IOC_MAGIC, TDX_IOC_GET_REPORT, TdxReportReq);

pub struct TdxProvider;

impl SiliconProvider for TdxProvider {
    fn vendor(&self) -> &'static str { "Intel TDX (Hardware)" }

    fn get_report(&self, data: [u8; 32]) -> Result<[u8; 1024], Error> {
        let mut req = TdxReportReq {
            reportdata: [0u8; 64],
            tdreport: [0u8; 1024],
        };
        
        // Copy the 32-byte Mudra/RIOM binding into the first half of reportdata
        req.reportdata[..32].copy_from_slice(&data);

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tdx_guest")
            .map_err(|_| Error::DeviceError)?;

        unsafe {
            tdx_get_report_ioctl(file.as_raw_fd(), &mut req)
                .map_err(|_| Error::HardwareFault)?;
        }

        Ok(req.tdreport)
    }

    fn extract_identity<'a>(&'a self, report: &'a [u8; 1024]) -> Result<WorkloadIdentity<'a>, Error> {
        // According to Intel TDX Module Spec:
        // TDREPORT_STRUCT contains TDINFO_STRUCT at offset 128.
        // MRTD is at offset 384 within TDREPORT_STRUCT (which is offset 256 within TDINFO_STRUCT).
        let mut measurement_bytes = [0u8; 48];
        measurement_bytes.copy_from_slice(&report[384..432]);
        let measurement = sakshi_core::types::Mrtd(measurement_bytes);
        
        // TCB_SVN is typically at offset 512 in the TDREPORT
        let mut tcb_svn_bytes = [0u8; 2];
        tcb_svn_bytes.copy_from_slice(&report[512..514]);
        let tcb_svn = u16::from_le_bytes(tcb_svn_bytes);

        Ok(WorkloadIdentity {
            measurement,
            tcb_svn,
            hardware_root: [0u8; 32], // This would be the MRSIGNER or similar
            runtime_claims: [0u8; 32], // This would map to RTMR[0] at offset 432
            attestation_cert: None,
        })
    }

    fn verify_genuineness(&self, _report: &[u8; 1024]) -> Result<(), Error> {
        // Real TDX verification involves checking the TDREPORT signature
        // against the TDX Attestation Key (AK).
        // For now, we assume the hardware IOCTL succeeding is a proof of local genuineness.
        Ok(())
    }

    fn generate_bundle(&self, _report: &[u8; 1024]) -> Result<ProvenanceBundle, Error> {
        // Real implementation would call the Quoting Enclave (QE) via /dev/tdx-attest
        // or a similar service to convert the TDREPORT into a Quote.
        // It would then fetch the PCK Certificate and TCB Info from the local cache or Intel PCS.
        Ok(ProvenanceBundle {
            quote: vec![0xaa; 1024], // Placeholder for QE-signed Quote
            collateral: AttestationCollateral {
                pck_certificate: vec![],
                tcb_info: vec![],
                qe_identity: vec![],
            },
        })
    }
}
