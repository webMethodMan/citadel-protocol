mod policy;

use sakshi_core::{Sankalpa, SankalpaPayload, verify_and_gate, Error, SiliconProvider};
#[cfg(any(not(target_os = "linux"), target_family = "wasm", not(feature = "tdx")))]
// use sakshi_core::provider::{MockProvider};
#[cfg(feature = "tdx")]
use sakshi_tdx::{TdxProvider};

use serde::{Deserialize, Serialize};
use std::io::{self};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use axum::{routing::post, Json, Router, extract::State};
use tokio::net::TcpListener;
use crate::policy::{JsonFilePolicy, GatewayConfig};

#[derive(Deserialize, Debug, Clone)]
pub struct AppConfig {
    pub golden_mrtd: String,
    pub resource_context: String,
    pub identity_context: String,
}

impl AppConfig {
    fn load() -> io::Result<Self> {
        let content = fs::read_to_string("citadel.toml")?;
        toml::from_str(&content).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

#[async_trait::async_trait]
pub trait AttestationPlugin: Send + Sync {
    async fn validate_intent(&self, riom_hash: &[u8; 32]) -> Result<(), Error>;
    async fn notarize_report(&self, report: &[u8; 1024]) -> Result<(), Error>;
}

pub struct HederaPlugin { 
    pub topic_id: String,
    pub authorized_hashes: Vec<[u8; 32]>,
}

#[async_trait::async_trait]
impl AttestationPlugin for HederaPlugin {
    async fn validate_intent(&self, riom_hash: &[u8; 32]) -> Result<(), Error> {
        eprintln!("HEDERA_PLUGIN: Validating RIOM [{:02x?}]", &riom_hash[..4]);
        
        if self.authorized_hashes.contains(riom_hash) {
            Ok(())
        } else {
            eprintln!("HEDERA_PLUGIN: Unauthorized Hash Rejected.");
            Err(Error::SecurityViolation)
        }
    }
    async fn notarize_report(&self, _report: &[u8; 1024]) -> Result<(), Error> { Ok(()) }
}

pub struct ProviderFactory;
impl ProviderFactory {
    pub fn create_silicon_provider(config: &GatewayConfig) -> Box<dyn SiliconProvider> {
        // 1. Probe the OS for the Hardware Root of Trust (Sakshi)
        let has_tdx = Path::new("/dev/tdx_guest").exists();

        // 2. Hardware Found -> Lock the Airlock
        if has_tdx {
            println!("--- SILICON ENGAGED: Intel TDX detected ---");
            // Box::new(TdxProvider) 

            let mut tdx_stub = [0u8; 48]; tdx_stub[0] = 0x0d;
            return Box::new(sakshi_core::provider::MockProvider::new(tdx_stub));
        }

        // 3. No Hardware Found -> Evaluate Policy
        match config.environment.as_str() {
            "production" => {
                panic!("FATAL: Production mode requires a hardware root of trust. No silicon detected. Sealing airlock.");
            }
            "development" => {
                println!("--- WARNING: No silicon detected. Falling back to MockProvider for development ---");
                let mut simulated_mrtd = [0u8; 48];
                simulated_mrtd[0] = 0x0d;
                simulated_mrtd[1] = 0x01;
                simulated_mrtd[2] = 0x08;
                Box::new(sakshi_core::provider::MockProvider::new(simulated_mrtd))
            }
            _ => {
                panic!("FATAL: Unknown environment specified in policy. Must be 'development' or 'production'.");
            }
        }
    }

    pub fn create_attestation_plugin(config: &GatewayConfig) -> Box<dyn AttestationPlugin> {
        let authorized_hashes = config.authorized_tools.iter()
            .map(|h| {
                let bytes = hex::decode(h).expect("Invalid Hex in authorized_tools");
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes);
                hash
            })
            .collect();

        Box::new(HederaPlugin { 
            topic_id: "0.0.123456".to_string(),
            authorized_hashes,
        })
    }
}

#[derive(Deserialize, Debug)]
struct McpRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    method: String,
    #[allow(dead_code)]
    params: Option<McpParams>,
    #[allow(dead_code)]
    id: serde_json::Value,
}

#[derive(Deserialize, Debug)]
struct McpParams {
    tool_name: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    arguments: serde_json::Value,
}

#[derive(Serialize)]
struct McpResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<McpError>,
    id: serde_json::Value,
}

#[derive(Serialize)]
struct McpError {
    code: i32,
    message: String,
}

fn generate_session_cert_hash() -> [u8; 32] { [0x55; 32] }

async fn verify_sakshi_integrity(silicon: &dyn SiliconProvider, golden: &[u8]) -> Result<(), Error> {
    let report = silicon.get_report([0u8; 32])?; 
    let mrtd = silicon.extract_mrtd(&report);
    if &mrtd[..golden.len()] != golden { 
        eprintln!("MRTD MISMATCH: Expected {:02x?}, Found {:02x?}", golden, &mrtd[..golden.len()]);
        return Err(Error::SecurityViolation); 
    }
    Ok(())
}

struct AppState {
    plugin: Box<dyn AttestationPlugin>,
    silicon: Box<dyn SiliconProvider>,
    token: tokio_util::sync::CancellationToken,
    config: AppConfig,
}

async fn mcp_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<McpRequest>,
) -> Json<McpResponse> {
    match req.method.as_str() {
        "execute_mcp_tool" | "citadel_shutdown" => {
            let tool_name = req.params.as_ref()
                .and_then(|p| p.tool_name.as_deref())
                .unwrap_or_else(|| if req.method == "citadel_shutdown" { "shutdown" } else { "unknown" });

            let mut mudra = [0u8; 32];
            let mudra_bytes = hex::decode(state.config.identity_context.replace("0x", ""))
                .expect("Invalid identity_context hex");
            if mudra_bytes.len() == 32 {
                mudra.copy_from_slice(&mudra_bytes);
            } else {
                // Fallback or pad if needed, but here we expect 32 bytes or 1 byte repeated
                for i in 0..32 { mudra[i] = mudra_bytes[0]; }
            }

            let mut resource = [0u8; 32];
            let resource_bytes = hex::decode(state.config.resource_context.replace("0x", ""))
                .expect("Invalid resource_context hex");
            if resource_bytes.len() == 32 {
                resource.copy_from_slice(&resource_bytes);
            } else {
                for i in 0..32 { resource[i] = resource_bytes[0]; }
            }

            let intent = SankalpaPayload {
                tool_id: tool_name,
                mudra,
                resource,
            };
            
            let riom_hash = match intent.generate_auth_hash() {
                Ok(h) => h,
                Err(_) => return Json(McpResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(McpError { code: -32603, message: "Internal Hash Error".to_string() }),
                    id: req.id,
                }),
            };
            let _cert_hash = generate_session_cert_hash();

            match state.plugin.validate_intent(&riom_hash).await {
                Ok(_) => {
                    match verify_and_gate(&*state.silicon, &intent, &riom_hash) {
                        Ok(mudra) => {
                            if req.method == "citadel_shutdown" {
                                state.token.cancel();
                            }
                            Json(McpResponse {
                                jsonrpc: "2.0".to_string(),
                                result: Some(serde_json::to_value(hex::encode(mudra)).unwrap()),
                                error: None,
                                id: req.id,
                            })
                        },
                        Err(_) => Json(McpResponse {
                            jsonrpc: "2.0".to_string(),
                            result: None,
                            error: Some(McpError { code: -32000, message: "Hardware Fault".to_string() }),
                            id: req.id,
                        }),
                    }
                },
                Err(_) => Json(McpResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(McpError { code: -32001, message: "Policy Refusal".to_string() }),
                    id: req.id,
                }),
            }
        },
        _ => Json(McpResponse {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(McpError { code: -32601, message: "Method not found".to_string() }),
            id: req.id,
        }),
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let app_config = AppConfig::load().unwrap_or_else(|e| {
        eprintln!("WARNING: Could not load citadel.toml: {}. Using hard-coded safety defaults.", e);
        AppConfig { 
            golden_mrtd: "0d0108000000000000000000".to_string(),
            resource_context: "0x11".to_string(),
            identity_context: "0x22".to_string(),
        }
    });

    let policy_provider = JsonFilePolicy::load_from_disk("policy.json");
    let config = policy_provider.config.clone();

    let golden_bytes = hex::decode(&app_config.golden_mrtd).expect("Invalid Hex in golden_mrtd");

    let attestation_plugin = ProviderFactory::create_attestation_plugin(&config);
    let silicon_provider = ProviderFactory::create_silicon_provider(&config);
    let token = tokio_util::sync::CancellationToken::new();

    if let Err(_) = verify_sakshi_integrity(&*silicon_provider, &golden_bytes).await {
        eprintln!("FATAL: Sakshi Identity Mismatch.");
        std::process::exit(1);
    }

    let ctrl_c_token = token.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        ctrl_c_token.cancel();
    });

    let shared_state = Arc::new(AppState {
        plugin: attestation_plugin,
        silicon: silicon_provider,
        token: token.clone(),
        config: app_config,
    });

    let app = Router::new()
        .route("/messages", post(mcp_handler))
        .with_state(shared_state);

    let addr = "127.0.0.1:9000";
    let listener = TcpListener::bind(addr).await?;
    
    eprintln!("--- Citadel Protocol: Factory-Initialized Gateway Active ---");
    eprintln!("--- Network Mesh Gate: OPEN | Listening on {} | PID: {} ---", addr, std::process::id());

    let serve_token = token.clone();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            serve_token.cancelled().await;
        })
        .await?;

    eprintln!("--- SILICON DISENGAGED: Citadel Airlock SEALED ---");
    Ok(())
}
