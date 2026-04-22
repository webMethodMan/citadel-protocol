#![no_std]

#[cfg(feature = "std")]
extern crate std;

#[cfg(any(feature = "alloc", feature = "rcgen"))]
extern crate alloc;

#[cfg(feature = "std")]
use std as alloc_crate;
#[cfg(all(not(feature = "std"), any(feature = "alloc", feature = "rcgen")))]
use alloc as alloc_crate;

use sha3::{Digest, Sha3_256};
use heapless::String as HString;

#[cfg(feature = "rcgen")]
use rcgen::{CertificateParams, KeyPair};
#[cfg(feature = "time")]
use time::{Duration, OffsetDateTime};

// --- Definitions ---
pub type SessionKey = [u8; 32];

#[derive(Debug)]
pub enum WitnessError {
    SecurityViolation,
    HardwareFault,
    UnsealingFailed,
    DeviceError,
    ProviderNotFound,
    CertificateError,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct EphemeralIdentity {
    #[cfg(any(feature = "std", feature = "alloc", feature = "rcgen"))]
    pub certificate: alloc_crate::string::String,
    #[cfg(any(feature = "std", feature = "alloc", feature = "rcgen"))]
    pub private_key: alloc_crate::string::String,
    pub subject: HString<128>,
    pub expires_at: HString<64>,
}

// --- The Pluggable Morpheme Trait ---
pub trait Morpheme: Send + Sync {
    /// Returns the unique tool/object identifier
    fn object_name(&self) -> &str;

    /// The "Silicon Weld": Collapses metadata into a 32-byte hash
    fn generate_auth_hash(&self) -> Result<[u8; 32], WitnessError>;
}

// --- A2A Morpheme Implementation ---
pub struct A2AMorpheme<'a> {
    pub tool_id: &'a str,
    pub identity: [u8; 32],
    pub metadata: [u8; 32],
}

impl<'a> Morpheme for A2AMorpheme<'a> {
    fn object_name(&self) -> &str {
        self.tool_id
    }

    fn generate_auth_hash(&self) -> Result<[u8; 32], WitnessError> {
        let mut hasher = Sha3_256::new();
        hasher.update(self.tool_id.as_bytes());
        hasher.update(&self.identity);
        hasher.update(&self.metadata);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        Ok(hash)
    }
}

// --- The Silicon Provider Trait (HAL) ---
pub trait SiliconProvider: Send + Sync {
    fn get_report(&self, report_data: [u8; 32]) -> Result<[u8; 1024], WitnessError>;

    // Validates that the current hardware matches a signed identity from your CI/CD
    fn verify_identity(&self, expected_mrtd: &[u8], signature: &[u8]) -> bool;
}

#[cfg(feature = "std")]
pub use tdx::TdxProvider;

// --- Intel TDX Implementation (OS Dependent) ---
#[cfg(feature = "std")]
pub mod tdx {
    use super::*;
    use std::fs::File;
    use std::os::unix::io::AsRawFd;

    const TDX_IOC_MAGIC: u8 = b'T';
    const TDX_IOC_GET_REPORT: u8 = 1;

    #[repr(C, packed)]
    pub struct TdxReportRequest {
        pub reportdata: [u8; 64],
        pub td_report:  [u8; 1024],
    }

    #[cfg(feature = "nix")]
    nix::ioctl_readwrite!(tdx_get_report, TDX_IOC_MAGIC, TDX_IOC_GET_REPORT, TdxReportRequest);

    pub struct TdxProvider;

    impl SiliconProvider for TdxProvider {
        fn get_report(&self, report_data: [u8; 32]) -> Result<[u8; 1024], WitnessError> {
            let mut request = TdxReportRequest {
                reportdata: [0u8; 64],
                td_report:  [0u8; 1024],
            };
            request.reportdata[..32].copy_from_slice(&report_data);

            let file = File::open("/dev/tdx_guest").map_err(|_| WitnessError::DeviceError)?;
            unsafe {
                #[cfg(feature = "nix")]
                tdx_get_report(file.as_raw_fd(), &mut request)
                    .map_err(|_| WitnessError::HardwareFault)?;
                #[cfg(not(feature = "nix"))]
                let _ = file;
            }
            Ok(request.td_report)
        }

        fn extract_mrtd(&self, report: &[u8; 1024]) -> [u8; 48] {
            let mut mrtd = [0u8; 48];
            mrtd.copy_from_slice(&report[384..432]);
            mrtd
        }
    }
}

pub fn verify_and_gate(
    provider: &dyn SiliconProvider,
    intent: &dyn Morpheme, 
    ledger_hash: &[u8; 32],
    _cert_hash: &[u8; 32],
) -> Result<EphemeralIdentity, WitnessError> {
    
    let riom_hash = intent.generate_auth_hash()?;

    if riom_hash != *ledger_hash {
        return Err(WitnessError::SecurityViolation);
    }

    let report = provider.get_report(riom_hash)?; 
    let _mrtd = provider.extract_mrtd(&report);

    #[cfg(feature = "std")]
    {
        use std::println;
        println!("--------------------------------------------------");
        println!("CITADEL HARDWARE ATTESTATION:");
        println!("  OBJECT:                 {}", intent.object_name());
        println!("  MRTD (Static Identity): {:02x?}", &_mrtd[..12]); 
        println!("  SESSION CERT BOUND:     {:02x?}", &_cert_hash[..8]);
        println!("  RIOM BINDING STATUS:    LOCKED");
        println!("--------------------------------------------------");
    }

    #[cfg(all(feature = "rcgen", feature = "time", any(feature = "std", feature = "alloc")))]
    {
        let mut params = CertificateParams::default();
        let now = OffsetDateTime::now_utc();
        let expiry = now + Duration::seconds(60);
        
        params.not_before = now;
        params.not_after = expiry;
        
        let mut subject_bytes = [0u8; 64];
        hex::encode_to_slice(riom_hash, &mut subject_bytes).map_err(|_| WitnessError::CertificateError)?;
        let subject_hex = core::str::from_utf8(&subject_bytes).map_err(|_| WitnessError::CertificateError)?;
        
        let mut subject_name = HString::<128>::new();
        subject_name.push_str("RIOM:").map_err(|_| WitnessError::CertificateError)?;
        subject_name.push_str(subject_hex).map_err(|_| WitnessError::CertificateError)?;

        let mut expires_at = HString::<64>::new();
        let expires_str = alloc_crate::format!("{}", expiry);
        let _ = expires_at.push_str(&expires_str);
        
        #[cfg(feature = "std")]
        params.distinguished_name.push(rcgen::DnType::CommonName, subject_name.as_str());

        let key_pair = KeyPair::generate().map_err(|_| WitnessError::CertificateError)?;
        let cert = params.self_signed(&key_pair).map_err(|_| WitnessError::CertificateError)?;

        Ok(EphemeralIdentity {
            certificate: cert.pem(),
            private_key: key_pair.serialize_pem(),
            subject: subject_name,
            expires_at,
        })
    }
    
    #[cfg(not(all(feature = "rcgen", feature = "time", any(feature = "std", feature = "alloc"))))]
    {
        Ok(EphemeralIdentity {
            #[cfg(any(feature = "std", feature = "alloc", feature = "rcgen"))]
            certificate: alloc_crate::string::String::new(),
            #[cfg(any(feature = "std", feature = "alloc", feature = "rcgen"))]
            private_key: alloc_crate::string::String::new(),
            subject: HString::new(),
            expires_at: HString::new(),
        })
    }
}

#[cfg(not(feature = "std"))]
mod no_std_bits {
    use core::panic::PanicInfo;
    #[panic_handler]
    fn panic(_info: &PanicInfo) -> ! { loop {} }
}
