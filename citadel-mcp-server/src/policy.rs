use serde::Deserialize;
use std::fs;
use sakshi_core::Error;

use std::collections::HashMap;

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RoutingMode {
    Notary,
    Proxy,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ToolPolicy {
    pub hash: String,
    pub mode: RoutingMode,
    pub target_url: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct GatewayConfig {
    pub environment: String, 
    pub provider: Option<String>,
    pub allowed_mrtds: Vec<String>,
    pub authorized_tools: HashMap<String, ToolPolicy>,
    pub a2a_url: Option<String>,
    pub spiffe_id: Option<String>,
    pub ve_threshold: Option<f64>,
}

#[allow(dead_code)]
pub trait PolicyProvider: Send + Sync {
    fn get_authorized_hashes(&self) -> Vec<String>;
}

pub struct JsonFilePolicy {
    pub config: GatewayConfig,
}

impl JsonFilePolicy {
    /// Loads policy with Fail-Secure Result pattern (Refactor 4)
    pub fn load_from_disk(path: &str) -> Result<Self, Error> {
        let file_content = fs::read_to_string(path)
            .map_err(|_| Error::InitializationError)?;
            
        let config: GatewayConfig = serde_json::from_str(&file_content)
            .map_err(|_| Error::InitializationError)?;
            
        Ok(Self { config })
    }
}

impl PolicyProvider for JsonFilePolicy {
    fn get_authorized_hashes(&self) -> Vec<String> {
        self.config.authorized_tools.values().map(|t| t.hash.clone()).collect()
    }
}
