use citadel_adapter_hiero::HieroProvider;
use sakshi_core::repository::{SovereignEvent, LifecycleStage, PramanaRepository};
use citadel_secrets::KeyringSecretStore;
use clap::Parser;
use tracing::info;

#[derive(Parser, Debug)]
#[clap(name = "citadel-anchor", version = "0.1.0", about = "Anchors a golden MRTD measurement to a Hedera HCS topic.")]
struct Args {
    /// The hex-encoded 48-byte MRTD measurement to anchor.
    #[clap(short, long)]
    mrtd: String,

    /// Optional SPIFFE ID for the anchoring authority.
    #[clap(short, long, default_value = "spiffe://citadel.internal/governance/anchor-authority")]
    spiffe_id: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let topic_id = std::env::var("HIERO_TOPIC_ID")
        .expect("HIERO_TOPIC_ID must be set in .env or environment");

    // 1. Initialize SecretStore
    let secret_store = KeyringSecretStore::new("citadel-protocol");

    // 2. Validate and decode MRTD
    let clean_mrtd = args.mrtd.strip_prefix("0x").unwrap_or(&args.mrtd);
    let mrtd_bytes = hex::decode(clean_mrtd)
        .map_err(|e| format!("Invalid MRTD hex: {}", e))?;
    
    if mrtd_bytes.len() != 48 {
        return Err(format!("MRTD must be exactly 48 bytes (got {})", mrtd_bytes.len()).into());
    }

    info!("🚀 Initializing Sovereign Anchor for Topic {}...", topic_id);
    info!("Golden MRTD: {}", args.mrtd);

    let provider = HieroProvider::new_with_prefix(&topic_id, Some(&secret_store), "hiero-governance").await?;

    // 3. Construct the SovereignAnchor event
    let event = SovereignEvent {
        stage: LifecycleStage::SovereignAnchor,
        sankalpa_hash: [0u8; 32], // Anchor events are identity-centric, not intent-centric
        ve_decay_rate: 1.0,        // Absolute stability for the anchor
        spiffe_id: args.spiffe_id,
        tdx_quote: Some(mrtd_bytes), // The golden measurement is stored in the tdx_quote field
        response_hash: None,
        error_message: None,
    };

    // 4. Notarize to HCS
    info!("📥 Submitting Sovereign Anchor to Hedera Consensus Service...");
    provider.append_evidence(event).await?;
    
    info!("✅ SUCCESS: Technical Integrity anchored. Citadel Gateways can now bootstrap using this topic.");

    Ok(())
}
