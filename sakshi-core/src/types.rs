#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    SecurityViolation,
    HardwareFault,
    DeviceError,
}

pub type Mudra = [u8; 32];
