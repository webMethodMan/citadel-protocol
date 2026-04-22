use witness::{Morpheme, A2AMorpheme, verify_and_gate, WitnessError, SiliconProvider, TdxProvider};
use serde::{Deserialize, Serialize};
use std::io::{self};
use std::fs;
use std::sync::Arc;
use async_trait::async_trait;
use axum::{routing::post, Json, Router, extract::State};
use tokio::net::TcpListener;

#[derive(Deserialize, Debug)]
pub struct ProxyConfig {
    golden_mrtd: String,
    #[serde(default)]
    pub authorized_tools: Vec<String>,
}

impl ProxyConfig {
    fn load() -> io::Result<Self> {
        let content = fs::read_to_string("citadel.toml")?;
        toml::from_str(&content).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

#[async_trait]
pub trait AttestationPlugin: Send + Sync {
    async fn validate_intent(&self, riom_hash: &[u8; 32]) -> Result<(), WitnessError>;
    async fn notarize_report(&self, report: &[u8; 1024]) -> Result<(), WitnessError>;
}

pub struct HederaPlugin { 
    pub topic_id: String,
    pub authorized_hashes: Vec<[u8; 32]>,
}

#[async_trait]
impl AttestationPlugin for HederaPlugin {
    async fn validate_intent(&self, riom_hash: &[u8; 32]) -> Result<(), WitnessError> {
        eprintln!("HEDERA_PLUGIN: Validating RIOM [{:02x?}]", &riom_hash[..4]);
        
        if self.authorized_hashes.contains(riom_hash) {
            Ok(())
        } else {
            eprintln!("HEDERA_PLUGIN: Unauthorized Hash Rejected.");
            Err(WitnessError::SecurityViolation)
        }
    }
    async fn notarize_report(&self, _report: &[u8; 1024]) -> Result<(), WitnessError> { Ok(()) }
}

pub struct SecurityFactory;
impl SecurityFactory {
    pub fn create_silicon_provider() -> Box<dyn SiliconProvider> { Box::new(TdxProvider) }
    pub fn create_attestation_plugin(config: &ProxyConfig) -> Box<dyn AttestationPlugin> {
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

async fn verify_witness_integrity(silicon: &dyn SiliconProvider, golden: &[u8]) -> Result<(), WitnessError> {
    let report = silicon.get_report([0u8; 32])?; 
    let mrtd = silicon.extract_mrtd(&report);
    if &mrtd[..golden.len()] != golden { 
        eprintln!("MRTD MISMATCH: Expected {:02x?}, Found {:02x?}", golden, &mrtd[..golden.len()]);
        return Err(WitnessError::SecurityViolation); 
    }
    Ok(())
}

struct AppState {
    plugin: Box<dyn AttestationPlugin>,
    silicon: Box<dyn SiliconProvider>,
    token: tokio_util::sync::CancellationToken,
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

            let intent = A2AMorpheme {
                tool_id: tool_name,
                identity: [0x22; 32], 
                metadata: [0x11; 32],
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
            let cert_hash = generate_session_cert_hash();

            match state.plugin.validate_intent(&riom_hash).await {
                Ok(_) => {
                    match verify_and_gate(&*state.silicon, &intent, &riom_hash, &cert_hash) {
                        Ok(identity) => {
                            if req.method == "citadel_shutdown" {
                                state.token.cancel();
                            }
                            Json(McpResponse {
                                jsonrpc: "2.0".to_string(),
                                result: Some(serde_json::to_value(identity).unwrap()),
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
    let config = ProxyConfig::load().unwrap_or_else(|e| {
        eprintln!("WARNING: Could not load citadel.toml: {}. Using hard-coded safety defaults.", e);
        ProxyConfig { 
            golden_mrtd: "0d0108000000000000000000".to_string(),
            authorized_tools: vec![]
        }
    });

    let golden_bytes = hex::decode(&config.golden_mrtd).expect("Invalid Hex in golden_mrtd");

    let plugin = SecurityFactory::create_attestation_plugin(&config);
    let silicon = SecurityFactory::create_silicon_provider();
    let token = tokio_util::sync::CancellationToken::new();

    if let Err(_) = verify_witness_integrity(&*silicon, &golden_bytes).await {
        eprintln!("FATAL: Witness Identity Mismatch.");
        std::process::exit(1);
    }

    let ctrl_c_token = token.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        ctrl_c_token.cancel();
    });

    let shared_state = Arc::new(AppState {
        plugin,
        silicon,
        token: token.clone(),
    });

    let app = Router::new()
        .route("/messages", post(mcp_handler))
        .with_state(shared_state);

    let addr = "127.0.0.1:9000";
    let listener = TcpListener::bind(addr).await?;
    
    eprintln!("--- Citadel Protocol: Factory-Initialized Proxy Active ---");
    eprintln!("--- Secure Gate: OPEN | Listening on {} | PID: {} ---", addr, std::process::id());

    let serve_token = token.clone();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            serve_token.cancelled().await;
        })
        .await?;

    eprintln!("--- SILICON DISENGAGED: Citadel Airlock SEALED ---");
    Ok(())
}
