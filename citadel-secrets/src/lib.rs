use async_trait::async_trait;
use sakshi_core::{Error, SecretStore};
use std::collections::HashMap;
use std::path::PathBuf;
use thiserror::Error as ThisError;
use tokio::fs;

#[derive(Debug, ThisError)]
pub enum SecretsError {
    #[error("IO error {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error {0}")]
    Json(#[from] serde_json::Error),
    #[error("Secret not found {0}")]
    NotFound(String),
}

impl From<SecretsError> for Error {
    fn from(err: SecretsError) -> Self {
        match err {
            SecretsError::NotFound(_) => Error::SecurityViolation,
            _ => Error::DeviceError,
        }
    }
}

pub struct LocalVaultSecretStore {
    vault_path: PathBuf,
}

impl LocalVaultSecretStore {
    pub fn new(vault_path: PathBuf) -> Self {
        Self { vault_path }
    }

    async fn read_vault(&self) -> Result<HashMap<String, String>, SecretsError> {
        if !self.vault_path.exists() {
            return Ok(HashMap::new());
        }
        let data = fs::read_to_string(&self.vault_path).await?;
        let map = serde_json::from_str(&data)?;
        Ok(map)
    }

    async fn write_vault(&self, map: &HashMap<String, String>) -> Result<(), SecretsError> {
        if let Some(parent) = self.vault_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let data = serde_json::to_string_pretty(map)?;
        fs::write(&self.vault_path, data).await?;
        Ok(())
    }
}

#[async_trait]
impl SecretStore for LocalVaultSecretStore {
    async fn get_secret(&self, key: &str) -> Result<String, Error> {
        let map = self.read_vault().await.map_err(SecretsError::from)?;
        map.get(key)
            .cloned()
            .ok_or_else(|| {
                tracing::error!("Vault get_secret failed for key '{}'", key);
                SecretsError::NotFound(key.to_string()).into()
            })
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<(), Error> {
        let mut map = self.read_vault().await.map_err(SecretsError::from)?;
        map.insert(key.to_string(), value.to_string());
        self.write_vault(&map).await.map_err(SecretsError::from)?;
        Ok(())
    }

    async fn delete_secret(&self, key: &str) -> Result<(), Error> {
        let mut map = self.read_vault().await.map_err(SecretsError::from)?;
        if map.remove(key).is_some() {
            self.write_vault(&map).await.map_err(SecretsError::from)?;
        }
        Ok(())
    }
}
