use citadel_adapter_hiero::HieroProvider;
use sakshi_core::repository::{SovereignEvent, LifecycleStage, PramanaRepository};
use citadel_secrets::KeyringSecretStore;
use clap::Parser;
use tracing::info;

#[derive(Parser, Debug)]
#[clap(name = "citadel-policy", version = "0.1.0", about = "Notarizes a tool policy hash to a Hedera HCS topic.")]
struct Args {
    /// The Tool/Rule ID (e.g., sphere://demo/light/green-blue-cyan)
    #[clap(short, long)]
    tool_id: String,

    /// The hex-encoded 32-byte logic hash (engineCodeHash) to notarize.
    #[clap(long)]
    hash: String,

    /// Optional SPIFFE ID for the authority.
    #[clap(short, long, default_value = "spiffe://citadel.internal/governance/policy-authority")]
    spiffe_id: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let topic_id = std::env::var("HIERO_TOPIC_ID")
        .expect("HIERO_TOPIC_ID must be set in .env or environment");

    // 1. Validate and decode Hash
    let clean_hash = args.hash.strip_prefix("0x").unwrap_or(&args.hash);
    let hash_bytes = hex::decode(clean_hash)
        .map_err(|e| format!("Invalid Hash hex: {}", e))?;
    
    if hash_bytes.len() != 32 {
        return Err(format!("Hash must be exactly 32 bytes (got {})", hash_bytes.len()).into());
    }

    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(&hash_bytes);

    info!("🚀 Notarizing Policy Update for {} on Topic {}...", args.tool_id, topic_id);
    info!("Policy Hash: {}", args.hash);

    let secret_store = KeyringSecretStore::new("citadel-protocol");
    let provider = HieroProvider::new_with_prefix(&topic_id, Some(&secret_store), "hiero-governance").await?;

    // 2. Construct the PolicyUpdate event
    let event = SovereignEvent {
        stage: LifecycleStage::PolicyUpdate,
        sankalpa_hash: hash_arr, // We use the sankalpa_hash field to store the Rule Hash
        ve_decay_rate: 1.0,
        spiffe_id: args.spiffe_id,
        tdx_quote: Some(args.tool_id.as_bytes().to_vec()), // Use tdx_quote to store tool_id for lookup
        response_hash: None,
        error_message: None,
    };

    // 3. Notarize to HCS
    info!("📥 Submitting Policy Update to Hedera Consensus Service...");
    provider.append_evidence(event).await?;
    
    info!("✅ SUCCESS: Policy for {} notarized.", args.tool_id);

    Ok(())
}
