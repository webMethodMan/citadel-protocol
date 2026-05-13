use super::CitadelLanguagePack;

pub struct EnglishLanguagePack;

impl CitadelLanguagePack for EnglishLanguagePack {
    fn bootstrap_commencing(&self) -> String {
        "--- BOOTSTRAP: Commencing Hardware-Rooted Self-Attestation ---".to_string()
    }

    fn bootstrap_integrity_verified(&self) -> String {
        "--- BOOTSTRAP: Integrity Verified | Sovereign Anchor Active ---".to_string()
    }

    fn bootstrap_failed(&self, reason: &str) -> String {
        format!("--- TERMINAL REFUSAL: Bootstrap Integrity Check FAILED — Reason: {} ---", reason)
    }

    fn shutdown_request(&self) -> String {
        "[PROXY] Shutdown Request Notarized — Terminating Server...".to_string()
    }

    fn admissibility_failure_ve(&self, current: f64, threshold: f64) -> String {
        format!("Admissibility Failure — V_e decay {} below threshold {}", current, threshold)
    }

    fn policy_refusal_unauthorized(&self, tool: &str) -> String {
        format!("Policy Refusal: Tool '{}' not authorized", tool)
    }

    fn telemetry_missing(&self) -> String {
        "Telemetry missing — Admissibility failure".to_string()
    }

    fn attestation_passed(&self, mudra_prefix: &str) -> String {
        format!("[PROXY] Sakshi Attestation PASSED: Mudra={}", mudra_prefix)
    }

    fn attestation_failed(&self, tool: &str, error: &str) -> String {
        format!("ATTESTATION_FAILURE: {} | Tool: {} | IntentHash: (omitted)", error, tool)
    }

    fn notarization_success(&self) -> String {
        "[PROXY] WORM_WELD: Pramana successfully notarized to repository.".to_string()
    }

    fn notarization_timeout(&self, timeout_ms: u64) -> String {
        format!("[PROXY] WORM_WELD: Terminal Refusal - Pramana notarization timed out ({}ms).", timeout_ms)
    }

    fn notarization_error(&self, error: &str) -> String {
        format!("[PROXY] WORM_WELD: Repository Error (Pramana): {}", error)
    }

    fn notarization_fallback_quarantine(&self) -> String {
        "[PROXY] POLICY: Falling back to local encrypted quarantine buffer.".to_string()
    }

    fn proxy_routing(&self, mode: &str, target: &str) -> String {
        format!("[PROXY] Routing: {} -> {}", mode, target)
    }

    fn proxy_success(&self, id: &str) -> String {
        format!("[PROXY] Proxy Destination Success (ID: {})", id)
    }

    fn proxy_error(&self, error: &str) -> String {
        format!("[PROXY] Proxy Destination Error: {}", error)
    }
}
