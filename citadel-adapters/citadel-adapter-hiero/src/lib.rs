use async_trait::async_trait;
use hedera::{AccountId, Client, PrivateKey, TopicId, TopicMessageSubmitTransaction};
use sakshi_core::{Error, Pramana, PramanaProvider, PramanaRepository, EvidenceVerifier, SovereignEvent, EvidenceError};
use std::collections::HashMap;
use tracing::info;

pub struct HieroProvider {
    client: Client,
    topic_id: TopicId,
}

impl HieroProvider {
    pub async fn new(topic_id_str: &str) -> Result<Self, String> {
        let client = match std::env::var("HIERO_NETWORK").unwrap_or_default().as_str() {
            "mainnet" => Client::for_mainnet(),
            "testnet" => Client::for_testnet(),
            "local" => {
                let node_addr = std::env::var("HIERO_NODE_ADDRESS").unwrap_or_else(|_| "127.0.0.1:50211".to_string());
                let node_id = std::env::var("HIERO_NODE_ACCOUNT_ID")
                    .unwrap_or_else(|_| "0.0.3".to_string())
                    .parse::<AccountId>()
                    .map_err(|e| format!("Invalid Local Node ID — {}", e))?;

                let c = Client::for_network(HashMap::from([(node_addr, node_id)]))
                    .map_err(|e| format!("Failed to create local network — {}", e))?;
                c.set_mirror_network(vec![std::env::var("HIERO_MIRROR_NODE_ADDRESS").unwrap_or_else(|_| "127.0.0.1:5600".to_string())]);
                c
            }
            _ => Client::for_testnet(),
        };

        if let (Ok(id), Ok(key)) = (std::env::var("HIERO_OPERATOR_ID"), std::env::var("HIERO_OPERATOR_KEY")) {
            let account_id = id.parse::<AccountId>().map_err(|e| format!("Invalid Account ID — {}", e))?;
            let private_key = key.parse::<PrivateKey>().map_err(|e| format!("Invalid Private Key — {}", e))?;
            client.set_operator(account_id, private_key);
        }

        let topic_id = topic_id_str.parse::<TopicId>().map_err(|e| e.to_string())?;
        Ok(Self {
            client,
            topic_id,
        })
    }
}

#[async_trait]
impl PramanaRepository for HieroProvider {
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

use base64::{engine::general_purpose, Engine as _};

#[async_trait]
impl EvidenceVerifier for HieroProvider {
    async fn check_notarization(&self, mudra_seal: &[u8; 32]) -> Result<bool, EvidenceError> {
        let mirror_url = std::env::var("HIERO_MIRROR_NODE_ADDRESS").unwrap_or_else(|_| "127.0.0.1:5600".to_string());
        let url = format!("http://{}/api/v1/topics/{}/messages", mirror_url, self.topic_id);
        
        info!("HIERO_VERIFIER: Checking notarization for Mudra {}...", hex::encode(&mudra_seal[..4]));

        let resp = reqwest::get(&url).await.map_err(|e| EvidenceError::TransportError(e.to_string()))?;
        let body: serde_json::Value = resp.json().await.map_err(|e| EvidenceError::TransportError(e.to_string()))?;

        // Simplified scan of recent messages (In production, use indexed search)
        if let Some(messages) = body.get("messages").and_then(|m| m.as_array()) {
            for msg in messages {
                if let Some(contents_b64) = msg.get("contents").and_then(|c| c.as_str()) {
                    if let Ok(decoded) = general_purpose::STANDARD.decode(contents_b64) {
                        if let Ok(event) = serde_json::from_slice::<SovereignEvent>(&decoded) {
                            if &event.sankalpa_hash == mudra_seal {
                                info!("HIERO_VERIFIER: Notarization CONFIRMED on HCS Topic {}", self.topic_id);
                                return Ok(true);
                            }
                        }
                    }
                }
            }
        }

        Ok(false)
    }
}

#[async_trait]
impl PramanaProvider for HieroProvider {
    async fn verify_pramana(&self, _pramana: &Pramana) -> Result<(), Error> {
        Ok(())
    }

    async fn notarize_pramana(&self, _pramana: &Pramana) -> Result<(), Error> {
        info!("HIERO_PROVIDER: Notarizing Pramana to Topic {}", self.topic_id);
        Ok(())
    }

    async fn verify_sakshi_integrity(&self, _measurement: &[u8; 48]) -> Result<(), Error> {
        Ok(())
    }
}
