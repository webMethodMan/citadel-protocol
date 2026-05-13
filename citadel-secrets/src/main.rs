use citadel_secrets::KeyringSecretStore;
use sakshi_core::SecretStore;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[clap(name = "citadel-secrets-mgr", version = "0.1.0", about = "Manages Citadel secrets in the system keyring")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,

    /// Keyring service name
    #[clap(short, long, default_value = "citadel-protocol")]
    service: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Sets a secret in the keyring
    Set {
        /// The name of the secret
        key: String,
        /// The secret value
        value: String,
    },
    /// Gets a secret from the keyring
    Get {
        /// The name of the secret
        key: String,
    },
    /// Deletes a secret from the keyring
    Delete {
        /// The name of the secret
        key: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    let store = KeyringSecretStore::new(&cli.service);

    match cli.command {
        Commands::Set { key, value } => {
            store.set_secret(&key, &value).await?;
            println!("✅ Secret '{}' set successfully in keyring '{}'", key, cli.service);
        }
        Commands::Get { key } => {
            let value = store.get_secret(&key).await?;
            println!("🔑 Secret '{}' value: {}", key, value);
        }
        Commands::Delete { key } => {
            store.delete_secret(&key).await?;
            println!("🗑️ Secret '{}' deleted from keyring '{}'", key, cli.service);
        }
    }

    Ok(())
}
