use async_trait::async_trait;
use keyring::Entry;
use sakshi_core::{Error, SecretStore};
use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum SecretsError {
    #[error("Keyring error: {0}")]
    Keyring(#[from] keyring::Error),
    #[error("Secret not found: {0}")]
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

pub struct KeyringSecretStore {
    service: String,
}

impl KeyringSecretStore {
    pub fn new(service: &str) -> Self {
        Self {
            service: service.to_string(),
        }
    }
}

#[async_trait]
impl SecretStore for KeyringSecretStore {
    async fn get_secret(&self, key: &str) -> Result<String, Error> {
        let entry = Entry::new(&self.service, key).map_err(SecretsError::from)?;
        entry.get_password().map_err(|e| {
            tracing::error!("Keyring get_password failed for key '{}': {:?}", key, e);
            match e {
                keyring::Error::NoEntry => SecretsError::NotFound(key.to_string()).into(),
                _ => SecretsError::from(e).into(),
            }
        })
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<(), Error> {
        let entry = Entry::new(&self.service, key).map_err(SecretsError::from)?;
        entry.set_password(value).map_err(|e| SecretsError::from(e).into())
    }

    async fn delete_secret(&self, key: &str) -> Result<(), Error> {
        let entry = Entry::new(&self.service, key).map_err(SecretsError::from)?;
        match entry.delete_credential() {
            Ok(_) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()), // Already gone
            Err(e) => Err(SecretsError::from(e).into()),
        }
    }
}
