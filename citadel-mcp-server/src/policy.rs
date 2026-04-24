use serde::Deserialize;
use std::fs;

#[derive(Deserialize, Debug, Clone)]
pub struct GatewayConfig {
    pub environment: String, // "development" or "production"
    pub authorized_tools: Vec<String>,
}

#[allow(dead_code)]
pub trait PolicyProvider: Send + Sync {
    fn get_authorized_hashes(&self) -> Vec<String>;
}

pub struct JsonFilePolicy {
    pub config: GatewayConfig,
}

impl JsonFilePolicy {
    // This loads the file at boot. If the file is missing or malformed, 
    // the Gateway panics and refuses to start (Fail-Secure).
    pub fn load_from_disk(path: &str) -> Self {
        let file_content = fs::read_to_string(path)
            .unwrap_or_else(|_| panic!("FATAL: Missing policy file at {}", path));
            
        let config: GatewayConfig = serde_json::from_str(&file_content)
            .expect("FATAL: Policy file contains invalid JSON");
            
        Self { config }
    }
}

impl PolicyProvider for JsonFilePolicy {
    fn get_authorized_hashes(&self) -> Vec<String> {
        self.config.authorized_tools.clone()
    }
}
