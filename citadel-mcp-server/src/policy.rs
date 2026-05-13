use serde::{Deserialize, Serialize};
use std::fs;
use sakshi_core::{Error, types::Mrtd};

use std::collections::HashMap;
use clap::ValueEnum;

#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, ValueEnum)]
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
pub struct CitadelConfig {
    pub environment: String, 
    pub provider: Option<String>,
    pub golden_mrtd: Option<String>,
    pub allowed_mrtds: Vec<String>,
    pub authorized_tools: HashMap<String, ToolPolicy>,
    pub a2a_url: Option<String>,
    pub spiffe_id: Option<String>,
    pub ve_threshold: Option<f64>,
    pub hiero_topic_id: Option<String>,
    pub resource_context: Option<String>,
    pub identity_context: Option<String>,
}

impl CitadelConfig {
    pub fn validate(&self) -> Result<(), Error> {
        // Validate all allowed MRTDs
        for mrtd_str in &self.allowed_mrtds {
            Mrtd::from_hex(mrtd_str)?;
        }
        if let Some(ref golden) = self.golden_mrtd {
            Mrtd::from_hex(golden)?;
        }
        Ok(())
    }

    pub fn get_golden_mrtd(&self) -> Option<Mrtd> {
        self.golden_mrtd.as_ref()
            .and_then(|s| Mrtd::from_hex(s).ok())
    }
}

pub struct JsonFilePolicy {
    pub config: CitadelConfig,
}

impl JsonFilePolicy {
    /// Loads policy with Fail-Secure Result pattern
    pub fn load_from_disk(path: &str) -> Result<Self, Error> {
        let file_content = fs::read_to_string(path)
            .map_err(|_| Error::InitializationError)?;
            
        let config: CitadelConfig = if path.ends_with(".toml") {
            toml::from_str(&file_content).map_err(|_| Error::InitializationError)?
        } else {
            serde_json::from_str(&file_content).map_err(|_| Error::InitializationError)?
        };
        
        config.validate()?;
            
        Ok(Self { config })
    }
}
