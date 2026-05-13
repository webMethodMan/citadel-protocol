pub trait CitadelLanguagePack: Send + Sync {
    // Bootstrap & Lifecycle
    fn bootstrap_commencing(&self) -> String;
    fn bootstrap_integrity_verified(&self) -> String;
    fn bootstrap_failed(&self, reason: &str) -> String;
    fn shutdown_request(&self) -> String;

    // Admissibility & Policy
    fn admissibility_failure_ve(&self, current: f64, threshold: f64) -> String;
    fn policy_refusal_unauthorized(&self, tool: &str) -> String;
    fn telemetry_missing(&self) -> String;

    // Attestation
    fn attestation_passed(&self, mudra_prefix: &str) -> String;
    fn attestation_failed(&self, tool: &str, error: &str) -> String;

    // Notarization (WORM WELD)
    fn notarization_success(&self) -> String;
    fn notarization_timeout(&self, timeout_ms: u64) -> String;
    fn notarization_error(&self, error: &str) -> String;
    fn notarization_fallback_quarantine(&self) -> String;

    // Proxy
    fn proxy_routing(&self, mode: &str, target: &str) -> String;
    fn proxy_success(&self, id: &str) -> String;
    fn proxy_error(&self, error: &str) -> String;
}

pub mod en_us;
