use citadel_secrets::LocalVaultSecretStore;
use sakshi_core::SecretStore;
use clap::{Parser, Subcommand};


#[derive(Parser)]
#[clap(name = "citadel-secrets-mgr", version = "0.1.0", about = "Manages Citadel secrets in the encrypted enclave vault")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generates a new master key to bootstrap the vault
    Init,
    /// Sets a secret in the encrypted vault
    Set {
        /// The name of the secret
        key: String,
        /// The secret value
        value: String,
    },
    /// Gets a secret from the encrypted vault
    Get {
        /// The name of the secret
        key: String,
    },
    /// Deletes a secret from the encrypted vault
    Delete {
        /// The name of the secret
        key: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    // Handle Init independently since it doesn't require an existing master key
    if let Commands::Init = cli.command {
        let new_key = EncryptedVaultSecretStore::generate_master_key();
        println!("✅ Generated new Citadel Master Key!");
        println!("export CITADEL_MASTER_KEY=\"{}\"", new_key);
        println!("⚠️ Save this key in your secure environment. If lost, the vault cannot be decrypted.");
        return Ok(());
    }

    // Enforce the Deterministic Physics of the master key
    let master_key = std::env::var("CITADEL_MASTER_KEY")
        .expect("FATAL: CITADEL_MASTER_KEY environment variable is missing");

    // Resolve the strict enclave path for the vault
    let mut vault_path = dirs_next::home_dir().expect("Could not find home directory");
    vault_path.push(".citadel");
    vault_path.push("pramana_vault.enc");

    let store = EncryptedVaultSecretStore::new(vault_path.clone(), &master_key)?;

    match cli.command {
        Commands::Init => unreachable!(), // Handled above
        Commands::Set { key, value } => {
            store.set_secret(&key, &value).await?;
            println!("✅ Secret '{}' encrypted and saved to vault at {:?}", key, vault_path);
        }
        Commands::Get { key } => {
            let value = store.get_secret(&key).await?;
            println!("🔑 Secret '{}' value: {}", key, value);
        }
        Commands::Delete { key } => {
            store.delete_secret(&key).await?;
            println!("🗑️ Secret '{}' deleted from vault", key);
        }
    }

    Ok(())
}
