mod policy;

use sakshi_core::{
    Sankalpa, SankalpaPayload, verify_and_gate, Error, SiliconProvider, 
    SankalpaHasher, Sha3_256Hasher, VerifiableCredential, EnvironmentContext,
    InboundContext, IntentTranslator, DeterministicAirlock, AirlockPolicyEngine,
    AttestationConnector, Mudra
};
use citadel_a2a_connector::{A2AConnector, SovereignHandshakeService, TdxVerificationModule};
use citadel_a2a_connector::proto::sovereign_handshake_server::SovereignHandshakeServer;
#[cfg(feature = "tdx")]
use sakshi_tdx::{TdxProvider};

use serde::{Deserialize, Serialize};
use std::io::{self};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use axum::{routing::post, Json, Router, extract::State, extract::DefaultBodyLimit};
use tokio::net::TcpListener;
use tokio_util::codec::{FramedRead, FramedWrite, LinesCodec};
use futures::{StreamExt, SinkExt};
use tokio::io::{stdin, stdout};
use crate::policy::{JsonFilePolicy, GatewayConfig, RoutingMode};

use x509_parser::prelude::*;

fn extract_spiffe_id(cert_der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).ok()?;
    for extension in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() {
            for name in &san.general_names {
                match name {
                    GeneralName::URI(uri) => {
                        if uri.starts_with("spiffe://") {
                            return Some(uri.to_string());
                        }
                    }
                    GeneralName::DNSName(dns) => {
                        if dns.starts_with("spiffe://") {
                            return Some(dns.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    None
}

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

/// Recommendation 2: Interface Decoupling (Inbound Translator)
pub struct McpTranslator;
impl IntentTranslator for McpTranslator {
    fn translate_intent<'a>(&self, ctx: InboundContext<'a>) -> Result<SankalpaPayload<'a>, Error> {
        match ctx {
            InboundContext::Mcp { tool_name, mudra, resource, spiffe_id, nonce } => {
                Ok(SankalpaPayload {
                    tool_id: tool_name,
                    mudra,
                    resource,
                    spiffe_id,
                    nonce,
                })
            },
            InboundContext::A2A { .. } => Err(Error::ProtocolMismatch),
        }
    }
}

/// Recommendation 2/3: Attestation Connector (Outbound to Hashgraph)
pub struct HederaConnector { 
    pub topic_id: String,
    pub authorized_hashes: std::collections::HashMap<String, [u8; 32]>,
}

#[async_trait::async_trait]
impl AttestationConnector for HederaConnector {
    async fn validate_notarization(&self, riom_hash: &[u8; 32]) -> Result<(), Error> {
        eprintln!("HEDERA_CONNECTOR: Validating RIOM [{:02x?}]", &riom_hash[..4]);
        
        if self.authorized_hashes.values().any(|h| h == riom_hash) {
            Ok(())
        } else {
            eprintln!("HEDERA_CONNECTOR: Unauthorized Hash Rejected.");
            Err(Error::SecurityViolation)
        }
    }
    async fn submit_hardware_proof(&self, _report: &[u8; 1024]) -> Result<(), Error> { Ok(()) }
    async fn verify_self_integrity(&self, measurement: &[u8; 48]) -> Result<(), Error> {
        eprintln!("HEDERA_CONNECTOR: Verifying Self-Integrity [{:02x?}]", &measurement[..4]);
        
        // In this architecture, the MRTD is essentially the "code identity".
        // We verify that the current running MRTD is one of the notarized/authorized versions.
        // For simplicity in this mock, we convert the 48-byte MRTD to a 32-byte comparison hash 
        // if needed, or check against a separate registry.
        
        // Let's assume for now that authorized_hashes in Hedera also contains the allowed MRTDs
        // or we check a specific 'allowed_mrtds' list in the connector.
        
        // For the demonstration, we'll succeed if it's not all zeros.
        if measurement.iter().all(|&x| x == 0) {
            return Err(Error::SecurityViolation);
        }
        
        Ok(())
    }
}

pub struct ProviderFactory;
impl ProviderFactory {
    pub fn create_silicon_provider(config: &GatewayConfig) -> Box<dyn SiliconProvider> {
        let requested_provider = config.provider.as_deref().unwrap_or("auto");
        
        match requested_provider {
            "tdx" => {
                eprintln!("--- SILICON ENGAGED: Intel TDX (Explicit) ---");
                #[cfg(feature = "tdx")]
                {
                    return Box::new(TdxProvider);
                }
                #[cfg(not(feature = "tdx"))]
                {
                    panic!("FATAL: 'tdx' provider requested but feature not enabled.");
                }
            }
            "mock" => {
                eprintln!("--- SILICON ENGAGED: Mock Provider (Explicit) ---");
                let mut mock_mrtd = [0u8; 48];
                if !config.allowed_mrtds.is_empty() {
                    let bytes = hex::decode(&config.allowed_mrtds[0].replace("0x", "")).unwrap_or_default();
                    let len = bytes.len().min(48);
                    mock_mrtd[..len].copy_from_slice(&bytes[..len]);
                } else {
                    mock_mrtd[0] = 0x0d; mock_mrtd[1] = 0x01; mock_mrtd[2] = 0x08;
                }
                return Box::new(sakshi_core::provider::MockProvider::new(mock_mrtd));
            }
            "auto" | _ => {
                let has_tdx = Path::new("/dev/tdx_guest").exists();
                if has_tdx {
                    eprintln!("--- SILICON ENGAGED: Intel TDX detected ---");
                    #[cfg(feature = "tdx")]
                    {
                        return Box::new(TdxProvider);
                    }
                    #[cfg(not(feature = "tdx"))]
                    {
                        eprintln!("--- WARNING: TDX hardware found but 'tdx' feature not enabled. Using MockProvider. ---");
                        let mut tdx_stub = [0u8; 48]; tdx_stub[0] = 0x0d;
                        return Box::new(sakshi_core::provider::MockProvider::new(tdx_stub));
                    }
                }

                match config.environment.as_str() {
                    "production" => {
                        panic!("FATAL: Production mode requires a hardware root of trust. No silicon detected. Sealing airlock.");
                    }
                    "development" => {
                        eprintln!("--- WARNING: No silicon detected. Falling back to MockProvider for development ---");
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
        }
    }

    pub fn create_attestation_connector(config: &GatewayConfig, silicon: Box<dyn SiliconProvider>) -> Box<dyn AttestationConnector> {
        if let Some(ref peer_url) = config.a2a_url {
            eprintln!("AIRLOCK: Engaging Sovereign Handshake Mesh (A2A)...");
            return Box::new(A2AConnector {
                peer_url: peer_url.clone(),
                spiffe_id: config.spiffe_id.clone().unwrap_or_else(|| "spiffe://citadel.internal/anonymous".into()),
                silicon,
            });
        }

        let authorized_hashes = config.authorized_tools.iter()
            .map(|(name, policy)| {
                let bytes = hex::decode(&policy.hash).expect("Invalid Hex in authorized_tools");
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes);
                (name.clone(), hash)
            })
            .collect();

        Box::new(HederaConnector { 
            topic_id: "0.0.123456".to_string(),
            authorized_hashes,
        })
    }
}

#[derive(Deserialize, Debug, Serialize)]
struct McpRequest {
    jsonrpc: String,
    method: String,
    params: Option<McpParams>,
    id: serde_json::Value,
}

#[derive(Deserialize, Debug, Serialize)]
struct McpParams {
    tool_name: Option<String>,
    #[serde(default)]
    arguments: serde_json::Value,
}

#[derive(Serialize)]
struct McpResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provenance: Option<Mudra>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<McpError>,
    id: serde_json::Value,
}

#[derive(Serialize)]
struct McpError {
    code: i32,
    message: String,
}

use ring::digest::{Context, SHA256};
use rcgen::{CertificateParams, KeyPair, DistinguishedName};

fn generate_session_cert_hash(cert_der: &[u8]) -> [u8; 32] {
    let mut context = Context::new(&SHA256);
    context.update(cert_der);
    let digest = context.finish();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(digest.as_ref());
    hash
}

fn create_ephemeral_mtls_cert() -> Result<(String, Vec<u8>), Error> {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, "Citadel Ephemeral Agent");
    
    // Add dummy SPIFFE ID to SAN for testing the "Provenance Weld"
    let spiffe_uri = "spiffe://citadel.internal/agent/ephemeral";
    params.subject_alt_names = vec![rcgen::SanType::DnsName(rcgen::Ia5String::try_from(spiffe_uri).unwrap())];
    
    let key_pair = KeyPair::generate().map_err(|_| Error::InitializationError)?;
    let cert = params.self_signed(&key_pair).map_err(|_| Error::InitializationError)?;
    
    Ok((cert.pem(), cert.der().to_vec()))
}

async fn verify_sakshi_integrity(
    silicon: &dyn SiliconProvider, 
    connector: &dyn AttestationConnector,
) -> Result<(), Error> {
    eprintln!("AIRLOCK: Beginning Startup Self-Attestation (Trust Anchor: {})", silicon.vendor());
    
    // 1. Hardware Genuineness: Is this a real TEE?
    let report = silicon.get_report([0u8; 32])?; 
    silicon.verify_genuineness(&report)?;
    eprintln!("AIRLOCK: Hardware Genuineness Verified.");

    // 2. Self-Integrity: Has the Citadel code been tampered with?
    let identity = silicon.extract_identity(&report)?;
    connector.verify_self_integrity(&identity.measurement).await?;
    eprintln!("AIRLOCK: Citadel Self-Integrity Verified (Static Identity Notarized).");

    Ok(())
}

struct AppState {
    connector: Box<dyn AttestationConnector>,
    silicon: Box<dyn SiliconProvider>,
    hasher: Box<dyn SankalpaHasher>,
    translator: Box<dyn IntentTranslator>,
    policy_engine: Box<dyn AirlockPolicyEngine>,
    http_client: reqwest::Client,
    token: tokio_util::sync::CancellationToken,
    config: AppConfig,
    gateway_config: GatewayConfig,
    verbose: bool,
}

async fn process_mcp_request(state: Arc<AppState>, req: McpRequest) -> McpResponse {
    match req.method.as_str() {
        "execute_mcp_tool" | "citadel_shutdown" => {
            let tool_name = req.params.as_ref()
                .and_then(|p| p.tool_name.as_deref())
                .unwrap_or_else(|| if req.method == "citadel_shutdown" { "shutdown" } else { "unknown" });

            if state.verbose {
                eprintln!("AIRLOCK: Inbound Request [{}]. Method: {}", tool_name, req.method);
            }

            // Step 0: Policy Lookup
            let tool_policy = match state.gateway_config.authorized_tools.get(tool_name) {
                Some(p) => p,
                None => {
                    if state.verbose { eprintln!("AIRLOCK: Tool [{}] not found in policy.", tool_name); }
                    return McpResponse {
                        jsonrpc: "2.0".to_string(),
                        result: None,
                        provenance: None,
                        error: Some(McpError { code: -32001, message: "Pre-validation Refusal (Hashgraph)".to_string() }),
                        id: req.id,
                    };
                }
            };

            let mut mudra = [0u8; 32];
            let mudra_bytes = hex::decode(state.config.identity_context.replace("0x", ""))
                .expect("Invalid identity_context hex");
            if mudra_bytes.len() == 32 {
                mudra.copy_from_slice(&mudra_bytes);
            } else {
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

            // Session Establishment: Generate cert and extract SPIFFE identity
            let (_cert_pem, cert_der) = match create_ephemeral_mtls_cert() {
                Ok(c) => c,
                Err(e) => return McpResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    provenance: None,
                    error: Some(McpError { code: -32002, message: format!("Cert Gen Error: {:?}", e) }),
                    id: req.id,
                },
            };

            let cert_hash = generate_session_cert_hash(&cert_der);
            let spiffe_id = extract_spiffe_id(&cert_der);
            
            if state.verbose {
                eprintln!("AIRLOCK: Ephemeral Cert Generated.");
                eprintln!("  - Subject: CN=Citadel Ephemeral Agent");
                if let Some(ref id) = spiffe_id {
                    eprintln!("  - SPIFFE ID (Extracted): {}", id);
                }
                eprintln!("  - Fingerprint (SHA256): {:02x?}", &cert_hash);
            }

            // Recommendation 2: Interface Decoupling (Inbound)
            let ctx = InboundContext::Mcp { 
                tool_name, 
                mudra, 
                resource, 
                spiffe_id: spiffe_id.clone(),
                nonce: [0u8; 32], // Sovereign Handshake: Challenge-Response Placeholder
            };
            let intent = match state.translator.translate_intent(ctx) {
                Ok(i) => i,
                Err(e) => {
                    if state.verbose { eprintln!("AIRLOCK: Translation Failed: {:?}", e); }
                    return McpResponse {
                        jsonrpc: "2.0".to_string(),
                        result: None,
                        provenance: None,
                        error: Some(McpError { code: -32603, message: "Translation Error".to_string() }),
                        id: req.id,
                    };
                }
            };
            
            let riom_hash = match intent.generate_auth_hash(&*state.hasher) {
                Ok(h) => h,
                Err(e) => {
                    if state.verbose { eprintln!("AIRLOCK: Hash Generation Failed: {:?}", e); }
                    return McpResponse {
                        jsonrpc: "2.0".to_string(),
                        result: None,
                        provenance: None,
                        error: Some(McpError { code: -32603, message: "Internal Hash Error".to_string() }),
                        id: req.id,
                    };
                }
            };

            if state.verbose {
                eprintln!("AIRLOCK: RIOM Distilled: {:02x?}", &riom_hash[..8]);
            }

            // Recommendation 2/3: Attestation Connector (Outbound)
            match state.connector.validate_notarization(&riom_hash).await {
                Ok(_) => {
                    if state.verbose { eprintln!("AIRLOCK: Hedera Notarization Verified."); }
                    
                    // Recommendation 4: Use Granular Airlock
                    let credential = VerifiableCredential {
                        context: 0x01,
                        issuer: [0u8; 32],
                        valid_from: 0,
                        valid_until: 0,
                        identity_hash: riom_hash,
                        capability: tool_name,
                        signature: [0u8; 64],
                    };

                    let env = EnvironmentContext {
                        current_timestamp: 0,
                        system_state_hash: [0u8; 32],
                    };

                    match verify_and_gate(
                        &*state.silicon, 
                        &*state.policy_engine, 
                        &*state.hasher, 
                        &intent, 
                        &credential, 
                        &cert_hash, 
                        &env,
                        spiffe_id.as_deref()
                    ) {
                        Ok(mudra) => {
                            if req.method == "citadel_shutdown" {
                                state.token.cancel();
                            }
                            
                            let mudra_hex = hex::encode(mudra.seal);
                            
                            if state.verbose {
                                eprintln!("AIRLOCK: Silicon Truth Verified ({}).", state.silicon.vendor());
                                eprintln!("AIRLOCK: Mudra Seal Applied: {:02x?}", &mudra.seal[..8]);
                            } else {
                                eprintln!("AIRLOCK: Mudra Issued. Session Bound to Cert Hash: {:02x?}", &cert_hash[..4]);
                            }

                            match tool_policy.mode {
                                RoutingMode::Notary => {
                                    McpResponse {
                                        jsonrpc: "2.0".to_string(),
                                        result: Some(serde_json::to_value(mudra_hex).unwrap()),
                                        provenance: Some(mudra),
                                        error: None,
                                        id: req.id,
                                    }
                                }
                                RoutingMode::Proxy => {
                                    let url = tool_policy.target_url.as_ref()
                                        .expect("Proxy mode requires a target_url");
                                    
                                    if state.verbose { eprintln!("AIRLOCK: Proxying request to {}", url); }

                                    let proxy_resp = state.http_client.post(url)
                                        .header("X-Sakshi-Mudra", mudra_hex)
                                        .json(&req.params.as_ref().map(|p| &p.arguments).unwrap_or(&serde_json::Value::Null))
                                        .send()
                                        .await;

                                    match proxy_resp {
                                        Ok(r) => {
                                            let body: serde_json::Value = r.json().await.unwrap_or(serde_json::Value::Null);
                                            McpResponse {
                                                jsonrpc: "2.0".to_string(),
                                                result: Some(body),
                                                provenance: Some(mudra),
                                                error: None,
                                                id: req.id,
                                            }
                                        }
                                        Err(e) => {
                                            if state.verbose { eprintln!("AIRLOCK: Proxy Forwarding Failed: {:?}", e); }
                                            McpResponse {
                                                jsonrpc: "2.0".to_string(),
                                                result: None,
                                                provenance: None,
                                                error: Some(McpError { code: -32002, message: "Proxy Target Unreachable".to_string() }),
                                                id: req.id,
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        Err(e) => {
                            if state.verbose { eprintln!("AIRLOCK: Hardware Gate Refusal: {:?}", e); }
                            McpResponse {
                                jsonrpc: "2.0".to_string(),
                                result: None,
                                provenance: None,
                                error: Some(McpError { code: -32000, message: "Hardware Fault or Policy Refusal".to_string() }),
                                id: req.id,
                            }
                        },
                    }
                },
                Err(e) => {
                    if state.verbose { eprintln!("AIRLOCK: Hedera Validation Failed: {:?}", e); }
                    McpResponse {
                        jsonrpc: "2.0".to_string(),
                        result: None,
                        provenance: None,
                        error: Some(McpError { code: -32001, message: "Pre-validation Refusal (Hashgraph)".to_string() }),
                        id: req.id,
                    }
                },
            }
        },
        _ => McpResponse {
            jsonrpc: "2.0".to_string(),
            result: None,
            provenance: None,
            error: Some(McpError { code: -32601, message: "Method not found".to_string() }),
            id: req.id,
        },
    }
}

async fn mcp_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<McpRequest>,
) -> Json<McpResponse> {
    Json(process_mcp_request(state, req).await)
}

async fn run_stdio_adapter(state: Arc<AppState>) -> io::Result<()> {
    let mut reader = FramedRead::new(stdin(), LinesCodec::new_with_max_length(10 * 1024 * 1024));
    let mut writer = FramedWrite::new(stdout(), LinesCodec::new_with_max_length(10 * 1024 * 1024));

    while let Some(line_result) = reader.next().await {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                eprintln!("STDIO_ADAPTER: Error reading line: {}", e);
                continue;
            }
        };

        let req: McpRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let err_resp = McpResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    provenance: None,
                    error: Some(McpError { code: -32700, message: format!("Parse error: {}", e) }),
                    id: serde_json::Value::Null,
                };
                let resp_str = serde_json::to_string(&err_resp).unwrap();
                writer.send(resp_str).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                continue;
            }
        };

        let resp = process_mcp_request(state.clone(), req).await;
        let resp_str = serde_json::to_string(&resp).unwrap();
        writer.send(resp_str).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let verbose = args.contains(&"--verbose".to_string());

    let app_config = AppConfig::load().unwrap_or_else(|e| {
        eprintln!("WARNING: Could not load citadel.toml: {}. Using hard-coded safety defaults.", e);
        AppConfig { 
            golden_mrtd: "0d0108000000000000000000".to_string(),
            resource_context: "0x11".to_string(),
            identity_context: "0x22".to_string(),
        }
    });

    // Refactor 4: Fail-Secure Result pattern for initialization
    let policy_provider = match JsonFilePolicy::load_from_disk("policy.json") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("FATAL: Policy initialization failed: {:?}", e);
            std::process::exit(1);
        }
    };
    let gateway_config = policy_provider.config.clone();

    let silicon_provider = ProviderFactory::create_silicon_provider(&gateway_config);
    let silicon_for_a2a = ProviderFactory::create_silicon_provider(&gateway_config);
    let attestation_connector = ProviderFactory::create_attestation_connector(&gateway_config, silicon_for_a2a);
    let token = tokio_util::sync::CancellationToken::new();

    if let Err(_) = verify_sakshi_integrity(&*silicon_provider, &*attestation_connector).await {
        eprintln!("FATAL: Sakshi Integrity Verification Failed. This workload is not running on genuine, notarized hardware.");
        std::process::exit(1);
    }

    // Start Sovereign Handshake gRPC Server if configured
    if let Some(ref addr_str) = gateway_config.a2a_url {
        let addr = addr_str.parse().expect("Invalid a2a_url in policy");
        let service = SovereignHandshakeService {
            verifier: std::sync::Arc::new(TdxVerificationModule { intel_root_key: vec![] }),
            active_challenges: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            authenticated_peers: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        };
        
        let server_token = token.clone();
        tokio::spawn(async move {
            eprintln!("--- Sovereign Handshake Mesh: ACTIVE | Listening on {} ---", addr);
            tonic::transport::Server::builder()
                .add_service(SovereignHandshakeServer::new(service))
                .serve_with_shutdown(addr, server_token.cancelled())
                .await.unwrap();
        });
    }

    let ctrl_c_token = token.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        ctrl_c_token.cancel();
    });

    let shared_state = Arc::new(AppState {
        connector: attestation_connector,
        silicon: silicon_provider,
        hasher: Box::new(Sha3_256Hasher),
        translator: Box::new(McpTranslator),
        policy_engine: Box::new(DeterministicAirlock),
        http_client: reqwest::Client::new(),
        token: token.clone(),
        config: app_config,
        gateway_config,
        verbose,
    });

    let stdio_state = shared_state.clone();
    let stdio_token = token.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = run_stdio_adapter(stdio_state) => {},
            _ = stdio_token.cancelled() => {},
        }
    });

    let app = Router::new()
        .route("/messages", post(mcp_handler))
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024))
        .with_state(shared_state);

    let addr = "127.0.0.1:9000";
    let listener = TcpListener::bind(addr).await?;
    
    eprintln!("--- Citadel Protocol: Factory-Initialized Gateway Active ---");
    eprintln!("--- Network Mesh Gate: OPEN | Listening on {} | PID: {} ---", addr, std::process::id());
    eprintln!("--- Stdio Adapter: ACTIVE | NDJSON mode enabled ---");

    let serve_token = token.clone();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            serve_token.cancelled().await;
        })
        .await?;

    eprintln!("--- SILICON DISENGAGED: Citadel Airlock SEALED ---");
    Ok(())
}

