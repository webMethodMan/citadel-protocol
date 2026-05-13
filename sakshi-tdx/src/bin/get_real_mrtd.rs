use sakshi_tdx::TdxProvider;
use sakshi_core::SiliconProvider;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = TdxProvider;
    println!("🔍 Fetching real Intel TDX report...");
    let report = provider.get_report([0u8; 32])?;
    let identity = provider.extract_identity(&report)?;
    
    let mrtd_hex = hex::encode(identity.measurement.as_ref());
    println!("\n✅ REAL HARDWARE MRTD IDENTIFIED:");
    println!("{}", mrtd_hex);
    println!("\nUse this value for your Sovereign Anchor.");
    
    Ok(())
}
