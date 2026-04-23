#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessError {
    SecurityViolation,
    HardwareFault,
    DeviceError,
}
