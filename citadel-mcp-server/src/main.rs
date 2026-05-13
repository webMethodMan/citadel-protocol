mod policy;
mod mcp;
mod transport;
mod lang;

use sakshi_core::{
    Sankalpa, Error, SiliconProvider, 
    SankalpaHasher, Sha3_256Hasher, 
    IntentTranslator, DeterministicAirlock, AirlockPolicyEngine,
    PramanaProvider, TelemetryState, PolicyComparator,
    PramanaRepository, SovereignEvent, EvidenceError
};

use citadel_a2a_connector::{A2AConnector};
#[cfg(feature = "tdx")]
use sakshi_tdx::{TdxProvider};

use std::io;
use std::path::Path;
use std::sync::Arc;
use crate::policy::{JsonFilePolicy, CitadelConfig, RoutingMode};
use crate::mcp::{McpTranslator};
use crate::transport::InboundTransport;
use crate::transport::stdio::McpStdioTransport;
use crate::transport::sse::McpSseTransport;
use crate::transport::grpc::GrpcTransport;
use crate::lang::{CitadelLanguagePack, en_us::EnglishLanguagePack};
use clap::{Parser, ValueEnum};
use tracing::{info, error};

pub struct ThresholdComparator;
impl PolicyComparator for ThresholdComparator {
    fn evaluate_synthesis(&self, telemetry: &TelemetryState, mandate: &dyn Sankalpa) -> Result<(), Error> {
        // High-Integrity Comparison: telemetry.ve_decay_rate must be ABOVE or EQUAL to mandate.max_decay()
        if telemetry.ve_decay_rate < mandate.max_decay() {
            return Err(Error::PolicyViolation);
        }
        Ok(())
    }
}

pub struct ProviderFactory;
impl ProviderFactory {
    pub fn create_silicon_provider(config: &CitadelConfig) -> Box<dyn SiliconProvider> {
        let requested = config.provider.as_deref().unwrap_or("auto");
        match requested {
            "tdx" => {
                #[cfg(feature = "tdx")] { return Box::new(TdxProvider); }
                #[cfg(not(feature = "tdx"))] { panic!("TDX feature not enabled"); }
            }
            "mock" => {
                #[cfg(feature = "mock-hardware")]
                {
                    let mrtd = config.get_golden_mrtd().unwrap_or(sakshi_core::types::Mrtd([0x0d; 48]));
                    return Box::new(sakshi_core::provider::MockProvider::new(*mrtd.as_ref()));
                }
                #[cfg(not(feature = "mock-hardware"))]
                {
                    panic!("FATAL: Mock provider requested in production build. Technical Integrity Violation.");
                }
            }
            _ => {
                if Path::new("/dev/tdx_guest").exists() {
                    #[cfg(feature = "tdx")] { return Box::new(TdxProvider); }
                }
                #[cfg(feature = "mock-hardware")]
                {
                    Box::new(sakshi_core::provider::MockProvider::new([0x0d; 48]))
                }
                #[cfg(not(feature = "mock-hardware"))]
                {
                    panic!("FATAL: No hardware provider found and mock-hardware feature disabled.");
                }
            }
        }
    }

    pub async fn create_pramana_provider(config: &CitadelConfig, silicon: Box<dyn SiliconProvider>) -> Box<dyn PramanaProvider> {
        if let Some(ref peer_url) = config.a2a_url {
            return Box::new(A2AConnector {
                peer_url: peer_url.clone(),
                spiffe_id: config.spiffe_id.clone().unwrap_or_else(|| "spiffe://citadel.internal/anonymous".into()),
                silicon,
            });
        }

        #[cfg(feature = "hiero")] {
            let topic_id = config.hiero_topic_id.as_deref().unwrap_or("0.0.123456").to_string();
            return Box::new(citadel_adapter_hiero::HieroProvider::new(&topic_id).await.expect("Failed to create HieroProvider"));
        }

        #[cfg(not(feature = "hiero"))] {
            struct MockPramanaProvider;
            #[async_trait::async_trait]
            impl PramanaProvider for MockPramanaProvider {
                async fn verify_pramana(&self, _p: &Pramana) -> Result<(), Error> { Ok(()) }
                async fn notarize_pramana(&self, _p: &Pramana) -> Result<(), Error> { Ok(()) }
                async fn verify_sakshi_integrity(&self, _m: &[u8; 48]) -> Result<(), Error> { Ok(()) }
            }
            Box::new(MockPramanaProvider)
        }
    }
}

async fn perform_sovereign_bootstrap(state: &AppState) -> Result<(), Error> {
    info!("{}", state.lang_pack.bootstrap_commencing());
    
    // 1. Extract the Silicon Truth (Current Measurement)
    let report = state.silicon.get_report([0u8; 32])?;
    state.silicon.verify_genuineness(&report)?;
    let identity = state.silicon.extract_identity(&report)?;
    
    // 2. Ledger Pulse
    // Verify current measurement against the Sovereign Anchor on Hiero
    state.connector.verify_sakshi_integrity(identity.measurement.as_ref()).await?;
    
    info!("{}", state.lang_pack.bootstrap_integrity_verified());
    Ok(())
}

pub struct AppState {
    pub connector: Box<dyn PramanaProvider>,
    pub silicon: Box<dyn SiliconProvider>,
    pub hasher: Box<dyn SankalpaHasher>,
    pub translator: Box<dyn IntentTranslator>,
    pub policy_engine: Box<dyn AirlockPolicyEngine>,
    pub comparator: Box<dyn PolicyComparator>,
    pub evidence_repo: Arc<dyn PramanaRepository>,
    pub lang_pack: Arc<dyn CitadelLanguagePack>,
    pub http_client: reqwest::Client,
    pub token: tokio_util::sync::CancellationToken,
    pub config: CitadelConfig,
    pub logic_mode: RoutingMode,
    pub ve_threshold: f64,
    pub telemetry_public_key: [u8; 32],
    pub verbose: bool,
}

#[derive(Parser, Debug)]
#[clap(name = "citadel-gate", version = "0.1.0")]
struct Args {
    #[clap(long, value_enum, default_value = "notary")]
    logic: RoutingMode,
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
pub enum TransportMode { #[clap(name = "mcp-stdio")] McpStdio, #[clap(name = "mcp-sse")] McpSse, Grpc }
#[derive(ValueEnum, Copy, Clone, Debug, PartialEq)]
pub enum LifecycleMode { Ephemeral, Persistent }

#[tokio::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt::init();
    dotenvy::dotenv().ok();
    let args = Args::parse();
    
    // Attempt to load consolidated config from citadel.toml first, then policy.json
    let config = JsonFilePolicy::load_from_disk("citadel.toml")
        .or_else(|_| JsonFilePolicy::load_from_disk("policy.json"))
        .expect("Failed to load Citadel configuration from citadel.toml or policy.json")
        .config;

    let silicon = ProviderFactory::create_silicon_provider(&config);
    let connector = ProviderFactory::create_pramana_provider(&config, ProviderFactory::create_silicon_provider(&config)).await;
    let token = tokio_util::sync::CancellationToken::new();
    let lang_pack: Arc<dyn CitadelLanguagePack> = Arc::new(EnglishLanguagePack);

    let evidence_repo: Arc<dyn PramanaRepository> = if let Some(topic_id) = config.hiero_topic_id.as_ref() {
        #[cfg(feature = "hiero")] {
            Arc::new(citadel_adapter_hiero::HieroProvider::new(topic_id).await.expect("Failed to init Hiero repo"))
        }
        #[cfg(not(feature = "hiero"))] {
            let _ = topic_id;
            struct MockEvidenceRepo;
            #[async_trait::async_trait]
            impl PramanaRepository for MockEvidenceRepo {
                async fn append_evidence(&self, _event: SovereignEvent) -> Result<(), EvidenceError> { Ok(()) }
            }
            Arc::new(MockEvidenceRepo)
        }
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
        .or(config.ve_threshold)
        .unwrap_or(0.90);

    let mut telemetry_public_key = [0u8; 32];
    if let Ok(pk_hex) = std::env::var("CITADEL_TELEMETRY_PUBLIC_KEY") {
        if let Ok(pk_bytes) = hex::decode(pk_hex.strip_prefix("0x").unwrap_or(&pk_hex)) {
            if pk_bytes.len() == 32 { 
                telemetry_public_key.copy_from_slice(&pk_bytes); 
                info!("IDENTITY: Telemetry verification key loaded (CITADEL_TELEMETRY_PUBLIC_KEY)");
            }
        }
    } else {
        warn!("IDENTITY: No CITADEL_TELEMETRY_PUBLIC_KEY found. Telemetry verification will fail in production.");
    }

    let state = Arc::new(AppState {
        connector, silicon, hasher: Box::new(Sha3_256Hasher), translator: Box::new(McpTranslator),
        policy_engine: Box::new(DeterministicAirlock), comparator: Box::new(ThresholdComparator),
        evidence_repo, lang_pack, http_client: reqwest::Client::new(),
        token: token.clone(), config: config.clone(), logic_mode: args.logic, 
        ve_threshold, telemetry_public_key, verbose: args.verbose,
    });

    perform_sovereign_bootstrap(&state).await.expect("Bootstrap fail — Technical Integrity Violation");

    let mut tasks = Vec::new();

    // Inbound Adapters (Transports)
    let mut transports: Vec<Box<dyn InboundTransport>> = match args.transport {
        TransportMode::McpStdio => {
            #[cfg(feature = "stdio")] { vec![Box::new(McpStdioTransport)] }
            #[cfg(not(feature = "stdio"))] { vec![] }
        },
        TransportMode::McpSse => {
            #[cfg(feature = "sse")] { vec![Box::new(McpSseTransport { port: args.port })] }
            #[cfg(not(feature = "sse"))] { vec![] }
        },
        TransportMode::Grpc => vec![Box::new(GrpcTransport { port: args.port })],
    };

    // If in Proxy mode, always enable the Sovereign Spine (gRPC) for A2A handshakes
    if args.logic == RoutingMode::Proxy && args.transport != TransportMode::Grpc {
        transports.push(Box::new(GrpcTransport { port: args.port + 1 }));
    }

    if args.lifecycle == LifecycleMode::Ephemeral {
        for transport in transports {
            transport.listen(state.clone()).await.unwrap();
        }
        return Ok(());
    }

    for transport in transports {
        let s = state.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = transport.listen(s).await {
                error!("Transport error: {:?}", e);
            }
        }));
    }

    tokio::select! {
        _ = tokio::signal::ctrl_c() => { token.cancel(); },
        _ = token.cancelled() => {},
        _ = futures::future::select_all(tasks) => {}
    }
    Ok(())
}
