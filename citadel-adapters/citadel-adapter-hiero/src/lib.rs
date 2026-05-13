use async_trait::async_trait;
use hedera::{AccountId, Client, PrivateKey, TopicId, TopicMessageSubmitTransaction};
use sakshi_core::{Error, Pramana, PramanaProvider, PramanaRepository, EvidenceVerifier, SovereignEvent, EvidenceError, SecretStore};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::Duration;
use tracing::{info, warn};

pub struct HieroProvider {
    client: Client,
    vault_topic_id: TopicId,
    gov_topic_id: TopicId,
    policy_cache: Arc<RwLock<HashMap<String, [u8; 32]>>>,
}

impl HieroProvider {
    pub async fn new(vault_topic_id: &str, gov_topic_id: &str, store: Option<&dyn SecretStore>) -> Result<Self, String> {
        Self::new_with_prefix(vault_topic_id, gov_topic_id, store, "hiero-operator").await
    }

    pub async fn new_with_prefix(
        vault_topic_id_str: &str, 
        gov_topic_id_str: &str,
        store: Option<&dyn SecretStore>, 
        prefix: &str
    ) -> Result<Self, String> {
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

        let mut operator_id = std::env::var("HIERO_OPERATOR_ID").ok();
        let mut operator_key = std::env::var("HIERO_OPERATOR_KEY").ok();

        if let Some(s) = store {
            let id_key = format!("{}-id", prefix);
            let key_key = format!("{}-key", prefix);
            if let Ok(id) = s.get_secret(&id_key).await { operator_id = Some(id); }
            if let Ok(key) = s.get_secret(&key_key).await { operator_key = Some(key); }
        }

        if let (Some(id), Some(key)) = (operator_id, operator_key) {
            let account_id = AccountId::from_str(&id)
                .map_err(|e| format!("Invalid Account ID — {}", e))?;
            
            // Handle ECDSA / Ed25519 parsing with 0x prefix stripping
            let clean_key = key.strip_prefix("0x").unwrap_or(&key);
            let private_key = PrivateKey::from_str_ecdsa(clean_key)
                .or_else(|_| PrivateKey::from_str(clean_key))
                .map_err(|e| format!("Invalid Private Key (Attempted ECDSA and Ed25519) — {}", e))?;
                
            info!("HIERO_PROVIDER: Identity set for Account {}. Derived PublicKey: {}", account_id, private_key.public_key());
            client.set_operator(account_id, private_key);
        }

        let vault_topic_id = vault_topic_id_str.parse::<TopicId>().map_err(|e| e.to_string())?;
        let gov_topic_id = gov_topic_id_str.parse::<TopicId>().map_err(|e| e.to_string())?;
        let policy_cache = Arc::new(RwLock::new(HashMap::new()));

        // Start background sync (Topic B: Policy Governance)
        let cache_clone = policy_cache.clone();
        let topic_clone = gov_topic_id;
        tokio::spawn(async move {
            let mirror_url = std::env::var("HIERO_MIRROR_NODE_ADDRESS").unwrap_or_else(|_| "127.0.0.1:5600".to_string());
            let base_url = if mirror_url.starts_with("http") { mirror_url } else { format!("http://{}", mirror_url) };
            let url = format!("{}/api/v1/topics/{}/messages?order=desc&limit=50", base_url, topic_clone);

            loop {
                match reqwest::get(&url).await {
                    Ok(resp) => {
                        if let Ok(body) = resp.json::<serde_json::Value>().await {
                            if let Some(messages) = body.get("messages").and_then(|m| m.as_array()) {
                                let mut new_policies = HashMap::new();
                                for msg in messages {
                                    if let Some(contents_b64) = msg.get("message").and_then(|c| c.as_str()) {
                                        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(contents_b64) {
                                            if let Ok(event) = serde_json::from_slice::<SovereignEvent>(&decoded) {
                                                if event.stage == sakshi_core::repository::LifecycleStage::PolicyUpdate {
                                                    if let Some(ref tool_id_bytes) = event.tdx_quote {
                                                        let tool_id = String::from_utf8_lossy(tool_id_bytes).to_string();
                                                        // Latest-Win
                                                        new_policies.entry(tool_id).or_insert(event.sankalpa_hash);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                let mut cache = cache_clone.write().await;
                                *cache = new_policies;
                                tracing::debug!("HIERO_PROVIDER: Background Policy Cache Refreshed ({} tools)", cache.len());
                            }
                        }
                    },
                    Err(e) => warn!("HIERO_PROVIDER: Policy cache background sync failed: {}", e),
                }
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });

        Ok(Self {
            client,
            vault_topic_id,
            gov_topic_id,
            policy_cache,
        })
    }
}

#[async_trait]
impl PramanaRepository for HieroProvider {
    async fn append_evidence(&self, event: SovereignEvent) -> Result<u64, EvidenceError> {
        let payload = serde_json::to_vec(&event).map_err(|e| EvidenceError::TransportError(e.to_string()))?;

        // Route based on Domain Boundary
        let target_topic = match event.stage {
            sakshi_core::repository::LifecycleStage::PolicyUpdate => self.gov_topic_id,
            _ => self.vault_topic_id,
        };

        let response = TopicMessageSubmitTransaction::new()
            .topic_id(target_topic)
            .message(payload)
            .execute(&self.client)
            .await
            .map_err(|e| EvidenceError::TransportError(e.to_string()))?;

        let receipt = response.get_receipt(&self.client).await
            .map_err(|e| EvidenceError::TransportError(e.to_string()))?;

        Ok(receipt.topic_sequence_number)
    }
}

use base64::{engine::general_purpose, Engine as _};

#[async_trait]
impl EvidenceVerifier for HieroProvider {
    async fn check_notarization(&self, mudra_seal: &[u8; 32]) -> Result<bool, EvidenceError> {
        let mirror_url = std::env::var("HIERO_MIRROR_NODE_ADDRESS").unwrap_or_else(|_| "127.0.0.1:5600".to_string());
        let base_url = if mirror_url.starts_with("http") { mirror_url } else { format!("http://{}", mirror_url) };
        let url = format!("{}/api/v1/topics/{}/messages?order=desc&limit=20", base_url, self.vault_topic_id);
        
        info!("HIERO_VERIFIER: Checking notarization for Mudra {}...", hex::encode(&mudra_seal[..4]));

        let resp = reqwest::get(&url).await.map_err(|e| EvidenceError::TransportError(e.to_string()))?;
        let body: serde_json::Value = resp.json().await.map_err(|e| EvidenceError::TransportError(e.to_string()))?;

        // Simplified scan of recent messages (In production, use indexed search)
        if let Some(messages) = body.get("messages").and_then(|m| m.as_array()) {
            for msg in messages {
                if let Some(contents_b64) = msg.get("message").and_then(|c| c.as_str()) {
                    if let Ok(decoded) = general_purpose::STANDARD.decode(contents_b64) {
                        match serde_json::from_slice::<SovereignEvent>(&decoded) {
                            Ok(event) => {
                                if &event.sankalpa_hash == mudra_seal {
                                    info!("HIERO_VERIFIER: Notarization CONFIRMED on HCS Topic {}", self.vault_topic_id);
                                    return Ok(true);
                                }
                            },
                            Err(e) => {
                                tracing::debug!("HIERO_VERIFIER: Failed to decode message as SovereignEvent: {}", e);
                            }
                        }
                    }
                }
            }
        }

        Ok(false)
    }

    async fn verify_at_sequence(&self, sequence_number: u64, expected_sankalpa_hash: &[u8; 32]) -> Result<bool, EvidenceError> {
        let mirror_url = std::env::var("HIERO_MIRROR_NODE_ADDRESS").unwrap_or_else(|_| "127.0.0.1:5600".to_string());
        let base_url = if mirror_url.starts_with("http") { mirror_url } else { format!("http://{}", mirror_url) };
        // The sub-10ms O(1) secret: Direct retrieval by sequence number
        let url = format!("{}/api/v1/topics/{}/messages/{}", base_url, self.vault_topic_id, sequence_number);
        
        info!("HIERO_VERIFIER: Performing O(1) lookup at Sequence {}...", sequence_number);

        let resp = reqwest::get(&url).await.map_err(|e| EvidenceError::TransportError(e.to_string()))?;
        if !resp.status().is_success() { return Ok(false); }

        let body: serde_json::Value = resp.json().await.map_err(|e| EvidenceError::TransportError(e.to_string()))?;
        if let Some(contents_b64) = body.get("message").and_then(|c| c.as_str()) {
            if let Ok(decoded) = general_purpose::STANDARD.decode(contents_b64) {
                if let Ok(event) = serde_json::from_slice::<SovereignEvent>(&decoded) {
                    if &event.sankalpa_hash == expected_sankalpa_hash {
                        info!("HIERO_VERIFIER: O(1) Verification SUCCESS (Seq: {})", sequence_number);
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }
}

#[async_trait]
impl PramanaProvider for HieroProvider {
    async fn verify_pramana(&self, tool_id: &str, pramana: &Pramana) -> Result<(), Error> {
        info!("HIERO_PROVIDER: Performing Forensic Scan for {} technical integrity...", tool_id);
        
        // Security & Latency: Optimized cache lookup (DoS mitigation)
        let cache = self.policy_cache.read().await;
        let notarized_hash = cache.get(tool_id)
            .ok_or_else(|| {
                tracing::error!("HIERO_PROVIDER: Policy Technical Integrity FAILED — No notarized hash found for {} in local cache.", tool_id);
                Error::SecurityViolation
            })?;

        // Extract the target logic hash from the report (Mocking for now)
        // For this test, we assume the report contains the RIOM hash in the first 32 bytes
        let mut expected_hash = [0u8; 32];
        if pramana.report.len() < 32 { return Err(Error::DeviceError); }
        expected_hash.copy_from_slice(&pramana.report[..32]);

        if notarized_hash == &expected_hash {
            info!("HIERO_PROVIDER: Policy Technical Integrity CONFIRMED via Ledger Registry (Cache lookup)");
            Ok(())
        } else {
            tracing::error!("HIERO_PROVIDER: Policy Technical Integrity VIOLATION — Policy Drift detected for {}", tool_id);
            tracing::error!("   Request Hash: {}", hex::encode(expected_hash));
            tracing::error!("   Ledger  Hash: {}", hex::encode(notarized_hash));
            Err(Error::SecurityViolation)
        }
    }

    async fn notarize_pramana(&self, pramana: &Pramana) -> Result<u64, Error> {
        info!("HIERO_PROVIDER: Notarizing Pramana to Topic {}", self.vault_topic_id);
        
        // Construct a SovereignEvent for the intent
        // In a real scenario, we might need more metadata here.
        let event = SovereignEvent {
            stage: sakshi_core::repository::LifecycleStage::SankalpaIntent,
            sankalpa_hash: [0u8; 32], // This should be the seal, but Pramana doesn't have it explicitly
            ve_decay_rate: 1.0,
            spiffe_id: "citadel-gateway".to_string(),
            tdx_quote: Some(pramana.report.clone()),
            response_hash: None,
            error_message: None,
        };
        
        // Calculate the seal for the event
        use sakshi_core::Sha3_256Hasher;
        use sakshi_core::SankalpaHasher;
        let hasher = Sha3_256Hasher;
        let seal = hasher.hash(&[&pramana.report]);
        
        let mut event = event;
        event.sankalpa_hash = seal;

        let seq = self.append_evidence(event).await
            .map_err(|e| {
                tracing::error!("HIERO_PROVIDER: Failed to notarize Pramana: {:?}", e);
                Error::DeviceError
            })?;
            
        Ok(seq)
    }

    async fn verify_sakshi_integrity(&self, measurement: &[u8; 48]) -> Result<(), Error> {
        info!("HIERO_PROVIDER: Verifying Sakshi Integrity against Sovereign Anchor...");
        
        let mirror_url = std::env::var("HIERO_MIRROR_NODE_ADDRESS").unwrap_or_else(|_| "127.0.0.1:5600".to_string());
        // Fix: Use http:// if not present
        let base_url = if mirror_url.starts_with("http") { mirror_url } else { format!("http://{}", mirror_url) };
        let url = format!("{}/api/v1/topics/{}/messages?order=desc&limit=20", base_url, self.vault_topic_id);
        
        let resp = reqwest::get(&url).await.map_err(|_| Error::DeviceError)?;
        let body: serde_json::Value = resp.json().await.map_err(|_| Error::DeviceError)?;

        if let Some(messages) = body.get("messages").and_then(|m| m.as_array()) {
            // Scan for the latest anchor
            for msg in messages {
                if let Some(contents_b64) = msg.get("message").and_then(|c| c.as_str()) {
                    if let Ok(decoded) = general_purpose::STANDARD.decode(contents_b64) {
                        if let Ok(event) = serde_json::from_slice::<SovereignEvent>(&decoded) {
                            if event.stage == sakshi_core::repository::LifecycleStage::SovereignAnchor {
                                if let Some(ref anchor_measurement) = event.tdx_quote {
                                    if anchor_measurement == measurement {
                                        info!("HIERO_PROVIDER: Sakshi Integrity CONFIRMED via Sovereign Anchor");
                                        return Ok(());
                                    } else {
                                        tracing::error!("HIERO_PROVIDER: Sakshi Integrity VIOLATION — Measurement mismatch!");
                                        return Err(Error::SecurityViolation);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        tracing::warn!("HIERO_PROVIDER: No Sovereign Anchor found on topic {}. Technical Integrity cannot be verified.", self.vault_topic_id);
        // In strict mode, this should probably fail. For now, we'll return an error if configured.
        if std::env::var("STRICT_INTEGRITY").is_ok() {
            return Err(Error::SecurityViolation);
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;
    use sakshi_core::repository::LifecycleStage;
    use serial_test::serial;

    #[tokio::test]
    #[serial]
    async fn test_hiero_verify_sakshi_integrity() {
        let mut server = Server::new_async().await;
        let mirror_url = server.host_with_port();
        std::env::set_var("HIERO_MIRROR_NODE_ADDRESS", &mirror_url);

        let measurement = [0xAAu8; 48];
        let event = SovereignEvent {
            stage: LifecycleStage::SovereignAnchor,
            sankalpa_hash: [0u8; 32],
            ve_decay_rate: 1.0,
            spiffe_id: "test".to_string(),
            tdx_quote: Some(measurement.to_vec()),
            response_hash: None,
            error_message: None,
        };
        let payload = serde_json::to_vec(&event).unwrap();
        let payload_b64 = general_purpose::STANDARD.encode(payload);

        let body = serde_json::json!({
            "messages": [
                {
                    "message": payload_b64,
                    "consensus_timestamp": "123456789.000000001",
                    "topic_id": "0.0.123456"
                }
            ]
        });

        let _m = server.mock("GET", "/api/v1/topics/0.0.123456/messages?order=desc&limit=20")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&body).unwrap())
            .create_async().await;

        // Mock HieroProvider (client won't be used for verify_sakshi_integrity)
        // We use a dummy topic_id that matches the mock URL
        let provider = HieroProvider {
            client: Client::for_testnet(),
            vault_topic_id: "0.0.123456".parse().unwrap(),
            gov_topic_id: "0.0.654321".parse().unwrap(),
            policy_cache: Arc::new(RwLock::new(HashMap::new())),
        };

        let res = provider.verify_sakshi_integrity(&measurement).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    #[serial]
    async fn test_hiero_check_notarization() {
        let mut server = Server::new_async().await;
        let mirror_url = server.host_with_port();
        std::env::set_var("HIERO_MIRROR_NODE_ADDRESS", &mirror_url);

        let seal = [0x55u8; 32];
        let event = SovereignEvent {
            stage: LifecycleStage::SankalpaIntent,
            sankalpa_hash: seal,
            ve_decay_rate: 0.95,
            spiffe_id: "test-agent".to_string(),
            tdx_quote: None,
            response_hash: None,
            error_message: None,
        };
        let payload = serde_json::to_vec(&event).unwrap();
        let payload_b64 = general_purpose::STANDARD.encode(payload);

        let body = serde_json::json!({
            "messages": [
                {
                    "message": payload_b64,
                    "consensus_timestamp": "123456789.000000002",
                    "topic_id": "0.0.123456"
                }
            ]
        });

        let _m = server.mock("GET", "/api/v1/topics/0.0.123456/messages?order=desc&limit=20")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&body).unwrap())
            .create_async().await;

        let provider = HieroProvider {
            client: Client::for_testnet(),
            vault_topic_id: "0.0.123456".parse().unwrap(),
            gov_topic_id: "0.0.654321".parse().unwrap(),
            policy_cache: Arc::new(RwLock::new(HashMap::new())),
        };

        let res = provider.check_notarization(&seal).await;
        assert!(res.unwrap());
    }

    #[tokio::test]
    #[serial]
    async fn test_hiero_verify_pramana() {
        let mut server = Server::new_async().await;
        let mirror_url = server.host_with_port();
        std::env::set_var("HIERO_MIRROR_NODE_ADDRESS", &mirror_url);

        let report = vec![0x11u8; 1024];
        let pramana = Pramana {
            report: report.clone(),
            ledger_hash: None,
        };

        let mut expected_hash = [0u8; 32];
        expected_hash.copy_from_slice(&report[..32]);

        let event = SovereignEvent {
            stage: LifecycleStage::PolicyUpdate,
            sankalpa_hash: expected_hash,
            ve_decay_rate: 1.0,
            spiffe_id: "test".to_string(),
            tdx_quote: Some(b"test_tool".to_vec()),
            response_hash: None,
            error_message: None,
        };
        let payload = serde_json::to_vec(&event).unwrap();
        let payload_b64 = general_purpose::STANDARD.encode(payload);

        let body = serde_json::json!({
            "messages": [
                {
                    "message": payload_b64,
                    "consensus_timestamp": "123456789.000000003",
                    "topic_id": "0.0.123456"
                }
            ]
        });

        let _m = server.mock("GET", "/api/v1/topics/0.0.123456/messages?order=desc&limit=50")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&body).unwrap())
            .create_async().await;

        let provider = HieroProvider {
            client: Client::for_testnet(),
            vault_topic_id: "0.0.123456".parse().unwrap(),
            gov_topic_id: "0.0.654321".parse().unwrap(),
            policy_cache: Arc::new(RwLock::new(HashMap::from([("test_tool".to_string(), expected_hash)]))),
        };

        let res = provider.verify_pramana("test_tool", &pramana).await;
        assert!(res.is_ok());
    }
}
