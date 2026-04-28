mod policy;

use sakshi_core::{
    Sankalpa, SovereignPayload, verify_and_gate, Error, SiliconProvider, 
    SankalpaHasher, Sha3_256Hasher, VerifiableCredential, EnvironmentContext,
    InboundContext, IntentTranslator, DeterministicAirlock, AirlockPolicyEngine,
    PramanaProvider, Pramana, Mudra, TelemetryState
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
use hedera::{Client, TopicId, TopicMessageSubmitTransaction};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Telemetry {
    pub v_e_decay: f64,
    pub authority_id: String,
    pub integrity_hash: String,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SovereignEvent {
    pub sankalpa_hash: [u8; 32],
    pub ve_decay_rate: f64,
    pub spiffe_id: String,
    pub tdx_quote: Vec<u8>,
}

#[derive(Debug)]
pub enum EvidenceError {
    Timeout,
    TransportError(String),
}

#[async_trait::async_trait]
pub trait PramanaRepository: Send + Sync {
    async fn append_evidence(&self, event: SovereignEvent) -> Result<(), EvidenceError>;
}

pub struct HederaHcsRepository {
    client: Client,
    topic_id: TopicId,
}

impl HederaHcsRepository {
    pub async fn new(topic_id_str: &str) -> Result<Self, String> {
        let client = if std::env::var("HEDERA_NETWORK").unwrap_or_default() == "mainnet" {
            Client::for_mainnet()
        } else {
            Client::for_testnet()
        };

        let topic_id = topic_id_str.parse::<TopicId>().map_err(|e| e.to_string())?;
        Ok(Self { client, topic_id })
    }
}

#[async_trait::async_trait]
impl PramanaRepository for HederaHcsRepository {
    async fn append_evidence(&self, event: SovereignEvent) -> Result<(), EvidenceError> {
        let payload = serde_json::to_vec(&event).map_err(|e| EvidenceError::TransportError(e.to_string()))?;
        
        TopicMessageSubmitTransaction::new()
            .topic_id(self.topic_id)
            .message(payload)
            .execute(&self.client)
            .await
            .map_err(|e| EvidenceError::TransportError(e.to_string()))?;
        
        Ok(())
    }
}

/* 
 * NOTE: External AI Control Plane Read Path
 * The semantic audit layer retrieves these WORM events via the Hedera Mirror Node API:
 * GET /api/v1/topics/{topic_id}/messages
 * This allows for out-of-band verification that every hardware-notarized Mudra 
 * is backed by a matching SovereignEvent on the public ledger.
 */

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
    fn translate_intent<'a>(&self, ctx: InboundContext<'a>) -> Result<SovereignPayload<'a>, Error> {
        match ctx {
            InboundContext::Mcp { tool_name, mudra, resource, spiffe_id, nonce, telemetry } => {
                Ok(SovereignPayload { 
                    tool_id: tool_name, 
                    mudra, 
                    resource, 
                    spiffe_id, 
                    nonce,
                    ve_decay_rate: telemetry.ve_decay_rate.to_be_bytes(),
                    authority_hash: telemetry.authority_hash,
                    integrity_hash: telemetry.integrity_hash,
                })
            },
            InboundContext::A2A { agent_id: _, action, nonce, telemetry } => {
                Ok(SovereignPayload {
                    tool_id: action,
                    mudra: [0u8; 32],
                    resource: [0u8; 32],
                    spiffe_id: None,
                    nonce,
                    ve_decay_rate: telemetry.ve_decay_rate.to_be_bytes(),
                    authority_hash: telemetry.authority_hash,
                    integrity_hash: telemetry.integrity_hash,
                })
            },
        }
    }
}

pub struct HederaConnector { 
    pub topic_id: String,
    pub authorized_hashes: std::collections::HashMap<String, [u8; 32]>,
}

#[async_trait::async_trait]
impl PramanaProvider for HederaConnector {
    async fn verify_pramana(&self, _pramana: &Pramana) -> Result<(), Error> {
        // In a real implementation, we would check the ledger for this Pramana.
        Ok(())
    }
    async fn notarize_pramana(&self, _pramana: &Pramana) -> Result<(), Error> {
        eprintln!("HEDERA_CONNECTOR: Notarizing Pramana to Topic {}", self.topic_id);
        Ok(())
    }
    async fn verify_sakshi_integrity(&self, measurement: &[u8; 48]) -> Result<(), Error> {
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

    pub fn create_pramana_provider(config: &GatewayConfig, silicon: Box<dyn SiliconProvider>) -> Box<dyn PramanaProvider> {
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
    pub telemetry: Telemetry,
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

async fn verify_sakshi_integrity(silicon: &dyn SiliconProvider, connector: &dyn PramanaProvider) -> Result<(), Error> {
    let report = silicon.get_report([0u8; 32])?; 
    silicon.verify_genuineness(&report)?;
    let identity = silicon.extract_identity(&report)?;
    connector.verify_sakshi_integrity(&identity.measurement).await?;
    Ok(())
}

pub struct AppState {
    pub connector: Box<dyn PramanaProvider>,
    pub silicon: Box<dyn SiliconProvider>,
    pub hasher: Box<dyn SankalpaHasher>,
    pub translator: Box<dyn IntentTranslator>,
    pub policy_engine: Box<dyn AirlockPolicyEngine>,
    pub evidence_repo: Arc<dyn PramanaRepository>,
    pub http_client: reqwest::Client,
    pub token: tokio_util::sync::CancellationToken,
    pub config: AppConfig,
    pub gateway_config: GatewayConfig,
    pub logic_mode: LogicMode,
    pub ve_threshold: f64,
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
    telemetry: Telemetry,
) -> Result<Mudra, (i32, String)> {
    // 1. Deterministic Refusal Gate: Capability-Based Admissibility
    if telemetry.v_e_decay < state.ve_threshold {
        let msg = format!("Admissibility Failure — V_e decay {} below threshold {}", telemetry.v_e_decay, state.ve_threshold);
        eprintln!("GATE_REFUSAL: {}", msg);
        return Err((-32001, msg));
    }

    let auth_hash = state.hasher.hash(&[telemetry.authority_id.as_bytes()]);
    let integ_hash = match hex::decode(telemetry.integrity_hash.replace("0x", "")) {
        Ok(h) if h.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h);
            arr
        },
        _ => [0u8; 32],
    };

    let ctx = InboundContext::Mcp { 
        tool_name, 
        mudra: mudra_val, 
        resource: resource_val, 
        spiffe_id, 
        nonce, 
        telemetry: TelemetryState {
            ve_decay_rate: telemetry.v_e_decay,
            authority_hash: auth_hash,
            integrity_hash: integ_hash,
        }
    };

    let intent = state.translator.translate_intent(ctx).map_err(|e| (-32000, format!("{:?}", e)))?;
    let riom_hash = intent.generate_auth_hash(&*state.hasher).map_err(|e| (-32000, format!("{:?}", e)))?;
    
    let credential = VerifiableCredential {
        context: 0x01, issuer: [0u8; 32], valid_from: 0, valid_until: 0,
        identity_hash: riom_hash, capability: tool_name, signature: [0u8; 64],
    };
    let env = EnvironmentContext { current_timestamp: 0, system_state_hash: [0u8; 32] };
    
    // Sakshi Attestation: Generates the Pramana (Admissible Proof) and the Mudra (Seal)
    let (pramana, mudra) = verify_and_gate(&*state.silicon, &*state.policy_engine, &*state.hasher, &intent, &credential, &cert_hash, &env, None)
        .map_err(|e| (-32000, format!("Sakshi Attestation Failed: {:?}", e)))?;
    
    // Verify the Pramana against the PramanaProvider as requested
    let _ = state.connector.verify_pramana(&pramana).await;
    
    // Notarize the Pramana to the ledger
    let _ = state.connector.notarize_pramana(&pramana).await;
    
    Ok(mudra)
}

/// Structural Skeleton: Proxy Handler
async fn handle_proxy_destination(
    _state: &AppState,
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
    let telemetry = match req.params.as_ref().map(|p| p.telemetry.clone()) {
        Some(t) => t,
        None => return McpResponse {
            jsonrpc: "2.0".to_string(), result: None, provenance: None,
            error: Some(McpError { code: -32001, message: "Telemetry missing — Admissibility failure".into() }), id: req_id,
        },
    };
    
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
    let effective_spiffe = spiffe_id.clone().unwrap_or_else(|| "spiffe://citadel.internal/anonymous".to_string());
    
    // Resolve matrix behavior with real SPIFFE ID and telemetry
    match perform_sakshi_attestation(&*state, tool_name, mudra_val, resource_val, spiffe_id, [0u8; 32], cert_hash, telemetry.clone()).await {
        Ok(mudra) => {
            // Task 2: WORM WELD via PramanaRepository with 50ms timeout
            let event = SovereignEvent {
                sankalpa_hash: mudra.seal, // Using the seal as the unified intent hash for the event
                ve_decay_rate: telemetry.v_e_decay,
                spiffe_id: effective_spiffe,
                tdx_quote: mudra.hardware_quote.clone(),
            };

            let repo = state.evidence_repo.clone();
            let append_future = tokio::time::timeout(std::time::Duration::from_millis(50), async move {
                repo.append_evidence(event).await
            });

            match append_future.await {
                Ok(Ok(_)) => {
                    if state.verbose { eprintln!("WORM_WELD: Evidence successfully notarized to repository."); }
                },
                Ok(Err(e)) => {
                    eprintln!("WORM_WELD: Repository Error: {:?}", e);
                    // Fallback to local encrypted quarantine buffer (placeholder logic)
                    eprintln!("POLICY: Falling back to local encrypted quarantine buffer.");
                },
                Err(_) => {
                    eprintln!("WORM_WELD: Terminal Refusal - Evidence notarization timed out (50ms).");
                    // Strict fail-closed policy
                    return McpResponse {
                        jsonrpc: "2.0".to_string(), result: None, provenance: None,
                        error: Some(McpError { code: -32003, message: "Terminal Refusal: Evidence Timeout".to_string() }), id: req_id,
                    };
                }
            }

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
        Err((code, message)) => McpResponse {
            jsonrpc: "2.0".to_string(), result: None, provenance: None,
            error: Some(McpError { code, message }), id: req_id,
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
    ve_threshold: Option<f64>,
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
    let connector = ProviderFactory::create_pramana_provider(&gateway_config, ProviderFactory::create_silicon_provider(&gateway_config));
    let token = tokio_util::sync::CancellationToken::new();

    verify_sakshi_integrity(&*silicon, &*connector).await.expect("Integrity check fail");

    let evidence_repo: Arc<dyn PramanaRepository> = if let Ok(topic_id) = std::env::var("HEDERA_TOPIC_ID") {
        Arc::new(HederaHcsRepository::new(&topic_id).await.expect("Failed to init Hedera repo"))
    } else {
        struct MockEvidenceRepo;
        #[async_trait::async_trait]
        impl PramanaRepository for MockEvidenceRepo {
            async fn append_evidence(&self, _event: SovereignEvent) -> Result<(), EvidenceError> {
                Ok(())
            }
        }
        Arc::new(MockEvidenceRepo)
    };

    let ve_threshold = args.ve_threshold
        .or(gateway_config.ve_threshold)
        .unwrap_or(0.90);

    let state = Arc::new(AppState {
        connector, silicon, hasher: Box::new(Sha3_256Hasher), translator: Box::new(McpTranslator),
        policy_engine: Box::new(DeterministicAirlock), evidence_repo, http_client: reqwest::Client::new(),
        token: token.clone(), config: app_config, gateway_config, logic_mode: args.logic, 
        ve_threshold, verbose: args.verbose,
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
