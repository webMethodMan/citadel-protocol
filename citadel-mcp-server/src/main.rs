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
use crate::policy::{JsonFilePolicy, GatewayConfig};
use clap::{Parser, ValueEnum};

use x509_parser::prelude::*;

fn extract_spiffe_id(cert_der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).ok()?;
    for extension in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() {
            for name in &san.general_names {
                match name {
                    GeneralName::URI(uri) => { if uri.starts_with("spiffe://") { return Some(uri.to_string()); } }
                    GeneralName::DNSName(dns) => { if dns.starts_with("spiffe://") { return Some(dns.to_string()); } }
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

pub struct McpTranslator;
impl IntentTranslator for McpTranslator {
    fn translate_intent<'a>(&self, ctx: InboundContext<'a>) -> Result<SankalpaPayload<'a>, Error> {
        match ctx {
            InboundContext::Mcp { tool_name, mudra, resource, spiffe_id, nonce } => {
                Ok(SankalpaPayload { tool_id: tool_name, mudra, resource, spiffe_id, nonce })
            },
            InboundContext::A2A { .. } => Err(Error::ProtocolMismatch),
        }
    }
}

pub struct HederaConnector { 
    pub topic_id: String,
    pub authorized_hashes: std::collections::HashMap<String, [u8; 32]>,
}

#[async_trait::async_trait]
impl AttestationConnector for HederaConnector {
    async fn validate_notarization(&self, riom_hash: &[u8; 32]) -> Result<(), Error> {
        if self.authorized_hashes.values().any(|h| h == riom_hash) { Ok(()) }
        else { Err(Error::SecurityViolation) }
    }
    async fn submit_hardware_proof(&self, _report: &[u8; 1024]) -> Result<(), Error> { Ok(()) }
    async fn verify_self_integrity(&self, measurement: &[u8; 48]) -> Result<(), Error> {
        if measurement.iter().all(|&x| x == 0) { return Err(Error::SecurityViolation); }
        Ok(())
    }
}

pub struct ProviderFactory;
impl ProviderFactory {
    pub fn create_silicon_provider(config: &GatewayConfig) -> Box<dyn SiliconProvider> {
        let requested = config.provider.as_deref().unwrap_or("auto");
        match requested {
            "tdx" => {
                #[cfg(feature = "tdx")] { return Box::new(TdxProvider); }
                #[cfg(not(feature = "tdx"))] { panic!("TDX feature not enabled"); }
            }
            "mock" => {
                let mut mock_mrtd = [0u8; 48];
                if !config.allowed_mrtds.is_empty() {
                    let bytes = hex::decode(&config.allowed_mrtds[0].replace("0x", "")).unwrap_or_default();
                    let len = bytes.len().min(48);
                    mock_mrtd[..len].copy_from_slice(&bytes[..len]);
                } else { mock_mrtd[0] = 0x0d; }
                return Box::new(sakshi_core::provider::MockProvider::new(mock_mrtd));
            }
            _ => {
                if Path::new("/dev/tdx_guest").exists() {
                    #[cfg(feature = "tdx")] { return Box::new(TdxProvider); }
                }
                Box::new(sakshi_core::provider::MockProvider::new([0x0d; 48]))
            }
        }
    }

    pub fn create_attestation_connector(config: &GatewayConfig, silicon: Box<dyn SiliconProvider>) -> Box<dyn AttestationConnector> {
        if let Some(ref peer_url) = config.a2a_url {
            return Box::new(A2AConnector {
                peer_url: peer_url.clone(),
                spiffe_id: config.spiffe_id.clone().unwrap_or_else(|| "spiffe://citadel.internal/anonymous".into()),
                silicon,
            });
        }
        let authorized_hashes = config.authorized_tools.iter()
            .map(|(name, policy)| {
                let bytes = hex::decode(&policy.hash).expect("Invalid Hex");
                let mut hash = [0u8; 32]; hash.copy_from_slice(&bytes);
                (name.clone(), hash)
            }).collect();
        Box::new(HederaConnector { topic_id: "0.0.123456".to_string(), authorized_hashes })
    }
}

#[derive(Deserialize, Debug, Serialize)]
pub struct McpRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<McpParams>,
    pub id: serde_json::Value,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct McpParams {
    pub tool_name: Option<String>,
    #[serde(default)]
    pub arguments: serde_json::Value,
}

#[derive(Serialize)]
pub struct McpResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Mudra>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<McpError>,
    pub id: serde_json::Value,
}

#[derive(Serialize)]
pub struct McpError { pub code: i32, pub message: String }

#[derive(Deserialize)]
struct SankalpaInput {
    tool_name: String,
    mudra: String,
    resource: String,
    spiffe_id: Option<String>,
    nonce: String,
}

use ring::digest::{Context, SHA256};
use rcgen::{CertificateParams, KeyPair, DistinguishedName};

fn generate_session_cert_hash(cert_der: &[u8]) -> [u8; 32] {
    let mut context = Context::new(&SHA256);
    context.update(cert_der);
    let digest = context.finish();
    let mut hash = [0u8; 32]; hash.copy_from_slice(digest.as_ref());
    hash
}

fn create_ephemeral_mtls_cert() -> Result<(Vec<u8>, [u8; 32], Option<String>), Error> {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, "Citadel Ephemeral Agent");
    let spiffe_uri = "spiffe://citadel.internal/agent/ephemeral";
    params.subject_alt_names = vec![rcgen::SanType::DnsName(rcgen::Ia5String::try_from(spiffe_uri).unwrap())];
    
    let key_pair = KeyPair::generate().map_err(|_| Error::InitializationError)?;
    let cert = params.self_signed(&key_pair).map_err(|_| Error::InitializationError)?;
    
    let cert_der = cert.der().to_vec();
    let cert_hash = generate_session_cert_hash(&cert_der);
    
    // Create a combined PEM for reqwest::Identity
    let mut identity_pem = cert.pem().into_bytes();
    identity_pem.extend_from_slice(key_pair.serialize_pem().as_bytes());
    
    Ok((identity_pem, cert_hash, Some(spiffe_uri.to_string())))
}

async fn verify_sakshi_integrity(silicon: &dyn SiliconProvider, connector: &dyn AttestationConnector) -> Result<(), Error> {
    let report = silicon.get_report([0u8; 32])?; 
    silicon.verify_genuineness(&report)?;
    let identity = silicon.extract_identity(&report)?;
    connector.verify_self_integrity(&identity.measurement).await?;
    Ok(())
}

pub struct AppState {
    pub connector: Box<dyn AttestationConnector>,
    pub silicon: Box<dyn SiliconProvider>,
    pub hasher: Box<dyn SankalpaHasher>,
    pub translator: Box<dyn IntentTranslator>,
    pub policy_engine: Box<dyn AirlockPolicyEngine>,
    pub http_client: reqwest::Client,
    pub token: tokio_util::sync::CancellationToken,
    pub config: AppConfig,
    pub gateway_config: GatewayConfig,
    pub logic_mode: LogicMode,
    pub verbose: bool,
}

/// Standalone Core Logic: Sakshi Attestation
pub async fn perform_sakshi_attestation(
    state: &AppState,
    tool_name: &str,
    mudra_val: [u8; 32],
    resource_val: [u8; 32],
    spiffe_id: Option<String>,
    nonce: [u8; 32],
    cert_hash: [u8; 32],
) -> Result<Mudra, Error> {
    let ctx = InboundContext::Mcp { tool_name, mudra: mudra_val, resource: resource_val, spiffe_id, nonce };
    let intent = state.translator.translate_intent(ctx)?;
    let riom_hash = intent.generate_auth_hash(&*state.hasher)?;
    state.connector.validate_notarization(&riom_hash).await?;
    let credential = VerifiableCredential {
        context: 0x01, issuer: [0u8; 32], valid_from: 0, valid_until: 0,
        identity_hash: riom_hash, capability: tool_name, signature: [0u8; 64],
    };
    let env = EnvironmentContext { current_timestamp: 0, system_state_hash: [0u8; 32] };
    verify_and_gate(&*state.silicon, &*state.policy_engine, &*state.hasher, &intent, &credential, &cert_hash, &env, None)
}

/// Structural Skeleton: Proxy Handler
async fn handle_proxy_destination(
    state: &AppState,
    mudra: Mudra,
    target_url: &str,
    req: McpRequest,
    identity_pem: Vec<u8>,
) -> Result<McpResponse, Error> {
    // --- PROVENANCE-BOUND MTLS FORWARDING logic ---
    // 1. Establish Identity from the ephemeral certificate and key
    let identity = reqwest::Identity::from_pem(&identity_pem)
        .map_err(|_| Error::InitializationError)?;

    // 2. Build a client bound to this specific hardware-notarized session
    let client = reqwest::Client::builder()
        .identity(identity)
        .use_rustls_tls()
        .build()
        .map_err(|_| Error::InitializationError)?;
    
    let mudra_hex = hex::encode(mudra.seal);
    let resp = client.post(target_url)
        .header("X-Sakshi-Mudra", mudra_hex)
        .header("X-Sakshi-Quote", hex::encode(&mudra.hardware_quote))
        .json(&req.params.as_ref().map(|p| &p.arguments).unwrap_or(&serde_json::Value::Null))
        .send().await.map_err(|_| Error::ProtocolMismatch)?;

    let body = resp.json().await.map_err(|_| Error::ProtocolMismatch)?;
    Ok(McpResponse {
        jsonrpc: "2.0".to_string(), result: Some(body),
        provenance: Some(mudra), error: None, id: req.id,
    })
}

async fn process_request_matrix(state: Arc<AppState>, req: McpRequest) -> McpResponse {
    let req_id = req.id.clone();
    let tool_name = req.params.as_ref().and_then(|p| p.tool_name.as_deref()).unwrap_or("unknown");
    let tool_policy = match state.gateway_config.authorized_tools.get(tool_name) {
        Some(p) => p,
        None => return McpResponse {
            jsonrpc: "2.0".to_string(), result: None, provenance: None,
            error: Some(McpError { code: -32001, message: "Policy refusal".to_string() }), id: req_id,
        },
    };

    // Restore Config-Based Values
    let mut mudra_val = [0u8; 32];
    if let Ok(bytes) = hex::decode(state.config.identity_context.replace("0x", "")) {
        if bytes.len() >= 32 { mudra_val.copy_from_slice(&bytes[..32]); }
    }

    let mut resource_val = [0u8; 32];
    if let Ok(bytes) = hex::decode(state.config.resource_context.replace("0x", "")) {
        if bytes.len() >= 32 { resource_val.copy_from_slice(&bytes[..32]); }
    }

    let (identity_pem, cert_hash, spiffe_id) = create_ephemeral_mtls_cert().unwrap();
    
    // Resolve matrix behavior with real SPIFFE ID and Nonce (placeholder)
    match perform_sakshi_attestation(&*state, tool_name, mudra_val, resource_val, spiffe_id, [0u8; 32], cert_hash).await {
        Ok(mudra) => {
            match state.logic_mode {
                LogicMode::Notary => McpResponse {
                    jsonrpc: "2.0".to_string(), result: Some(serde_json::to_value(hex::encode(mudra.seal)).unwrap()),
                    provenance: Some(mudra), error: None, id: req_id,
                },
                LogicMode::Proxy => {
                    let target = tool_policy.target_url.as_deref().unwrap_or("http://localhost:8080");
                    match handle_proxy_destination(&*state, mudra, target, req, identity_pem).await {
                        Ok(r) => r,
                        Err(e) => McpResponse {
                            jsonrpc: "2.0".to_string(), result: None, provenance: None,
                            error: Some(McpError { code: -32002, message: format!("Proxy Error: {:?}", e) }), id: req_id,
                        }
                    }
                }
            }
        },
        Err(e) => McpResponse {
            jsonrpc: "2.0".to_string(), result: None, provenance: None,
            error: Some(McpError { code: -32000, message: format!("Sakshi Attestation Failed: {:?}", e) }), id: req_id,
        }
    }
}

async fn mcp_handler(State(state): State<Arc<AppState>>, Json(req): Json<McpRequest>) -> Json<McpResponse> {
    Json(process_request_matrix(state, req).await)
}

#[derive(Parser, Debug)]
#[clap(name = "citadel-gate", version = "0.1.0")]
struct Args {
    #[clap(long, value_enum, default_value = "notary")]
    logic: LogicMode,
    #[clap(long, value_enum, default_value = "mcp-stdio")]
    transport: TransportMode,
    #[clap(long, value_enum, default_value = "persistent")]
    lifecycle: LifecycleMode,
    #[clap(long, default_value = "50051")]
    port: u16,
    #[clap(long)]
    verbose: bool,
}

#[derive(ValueEnum, Copy, Clone, Debug, PartialEq)]
pub enum LogicMode { Notary, Proxy }
#[derive(ValueEnum, Copy, Clone, Debug, PartialEq)]
pub enum TransportMode { #[clap(name = "mcp-stdio")] McpStdio, #[clap(name = "mcp-sse")] McpSse, Grpc }
#[derive(ValueEnum, Copy, Clone, Debug, PartialEq)]
pub enum LifecycleMode { Ephemeral, Persistent }

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    let app_config = AppConfig::load().unwrap_or(AppConfig { golden_mrtd: "".into(), resource_context: "".into(), identity_context: "".into() });
    let gateway_config = JsonFilePolicy::load_from_disk("policy.json").expect("Policy fail").config;
    let silicon = ProviderFactory::create_silicon_provider(&gateway_config);
    let connector = ProviderFactory::create_attestation_connector(&gateway_config, ProviderFactory::create_silicon_provider(&gateway_config));
    let token = tokio_util::sync::CancellationToken::new();

    verify_sakshi_integrity(&*silicon, &*connector).await.expect("Integrity check fail");

    let state = Arc::new(AppState {
        connector, silicon, hasher: Box::new(Sha3_256Hasher), translator: Box::new(McpTranslator),
        policy_engine: Box::new(DeterministicAirlock), http_client: reqwest::Client::new(),
        token: token.clone(), config: app_config, gateway_config, logic_mode: args.logic, verbose: args.verbose,
    });

    // Resolve Lifecycle Dimension
    if args.lifecycle == LifecycleMode::Ephemeral {
        match args.transport {
            TransportMode::McpStdio => {
                let mut buffer = String::new(); io::stdin().read_line(&mut buffer)?;
                let req: McpRequest = serde_json::from_str(&buffer).expect("Invalid JSON");
                let resp = process_request_matrix(state, req).await;
                println!("{}", serde_json::to_string(&resp).unwrap());
            }
            _ => { eprintln!("Ephemeral mode for SSE/gRPC requires server spin-up; bypassing listeners for latency optimization."); }
        }
        return Ok(());
    }

    // Persistent Mode: Resolve Transport Dimensions
    let mut tasks = Vec::new();
    if args.transport == TransportMode::McpSse || args.transport == TransportMode::McpStdio {
        let addr = format!("127.0.0.1:{}", args.port);
        let app = Router::new().route("/messages", post(mcp_handler)).layer(DefaultBodyLimit::max(10 * 1024 * 1024)).with_state(state.clone());
        let t = token.clone();
        if args.transport == TransportMode::McpSse {
            let listener = TcpListener::bind(&addr).await?;
            tasks.push(tokio::spawn(async move {
                eprintln!("--- Citadel SSE Gateway: ACTIVE | Port {} ---", addr);
                axum::serve(listener, app).with_graceful_shutdown(async move { t.cancelled().await; }).await.unwrap();
            }));
        } else {
            let s = state.clone();
            tasks.push(tokio::spawn(async move {
                eprintln!("--- Citadel Stdio Adapter: ACTIVE ---");
                let mut reader = FramedRead::new(stdin(), LinesCodec::new_with_max_length(10 * 1024 * 1024));
                let mut writer = FramedWrite::new(stdout(), LinesCodec::new_with_max_length(10 * 1024 * 1024));
                while let Some(Ok(line)) = reader.next().await {
                    let req = serde_json::from_str(&line).unwrap();
                    let resp = process_request_matrix(s.clone(), req).await;
                    writer.send(serde_json::to_string(&resp).unwrap()).await.unwrap();
                }
            }));
        }
    }

    if args.transport == TransportMode::Grpc || args.logic == LogicMode::Proxy {
        let addr: std::net::SocketAddr = format!("127.0.0.1:{}", args.port + 1).parse().unwrap();
        let service = SovereignHandshakeService {
            verifier: Arc::new(TdxVerificationModule { intel_root_key: vec![] }),
            active_challenges: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            authenticated_peers: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        };
        let t = token.clone();
        tasks.push(tokio::spawn(async move {
            eprintln!("--- Sovereign Spine gRPC: ACTIVE | Port {} ---", addr.port());
            tonic::transport::Server::builder().add_service(SovereignHandshakeServer::new(service)).serve_with_shutdown(addr, t.cancelled()).await.unwrap();
        }));
    }

    tokio::select! {
        _ = tokio::signal::ctrl_c() => { token.cancel(); },
        _ = token.cancelled() => {},
        _ = futures::future::select_all(tasks) => {}
    }
    Ok(())
}
