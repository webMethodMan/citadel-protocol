use serde::{Deserialize, Serialize};
use sakshi_core::{
    Sankalpa, SovereignPayload, verify_and_gate, Error, 
    VerifiableCredential, EnvironmentContext,
    InboundContext, IntentTranslator,
    Mudra, TelemetryState, SignedTelemetry,
    SovereignEvent, LifecycleStage
};
use crate::AppState;
use crate::policy::RoutingMode;
use std::sync::Arc;
use tracing::{info, error, warn};
use ring::digest::{Context, SHA256};
use rcgen::{CertificateParams, KeyPair, DistinguishedName};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Telemetry {
    pub v_e_decay: f64,
    pub authority_id: String,
    pub integrity_hash: String,
    pub signature: String, // Hex-encoded ed25519 signature
}

#[derive(Deserialize, Debug, Serialize)]
pub struct McpRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<McpParams>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct McpParams {
    pub tool_name: Option<String>,
    pub telemetry: Option<Telemetry>,
    #[serde(default)]
    pub arguments: serde_json::Value,
}

#[derive(Serialize)]
pub struct McpResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Mudra>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<McpError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub struct McpError {
    pub code: i32,
    pub message: String,
}

pub struct McpTranslator;
impl IntentTranslator for McpTranslator {
    fn translate_intent<'a>(&self, ctx: InboundContext<'a>) -> Result<SovereignPayload<'a>, Error> {
        match ctx {
            InboundContext::Mcp { tool_name, mudra, resource, spiffe_id, nonce, telemetry, max_decay } => {
                Ok(SovereignPayload { 
                    tool_id: tool_name, 
                    mudra, 
                    resource, 
                    spiffe_id, 
                    nonce,
                    max_decay,
                    authority_hash: telemetry.state.authority_hash,
                    integrity_hash: telemetry.state.integrity_hash,
                })
            },
            InboundContext::A2A { agent_id: _, action, nonce, telemetry, max_decay } => {
                Ok(SovereignPayload {
                    tool_id: action,
                    mudra: [0u8; 32],
                    resource: [0u8; 32],
                    spiffe_id: None,
                    nonce,
                    max_decay,
                    authority_hash: telemetry.state.authority_hash,
                    integrity_hash: telemetry.state.integrity_hash,
                })
            },
        }
    }
}

pub fn generate_session_cert_hash(cert_der: &[u8]) -> [u8; 32] {
    let mut context = Context::new(&SHA256);
    context.update(cert_der);
    let digest = context.finish();
    let mut hash = [0u8; 32]; hash.copy_from_slice(digest.as_ref());
    hash
}

pub fn create_ephemeral_mtls_cert() -> Result<(Vec<u8>, [u8; 32], Option<String>), Error> {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, "Citadel Ephemeral Agent");
    let spiffe_uri = "spiffe://citadel.internal/agent/ephemeral";
    params.subject_alt_names = vec![rcgen::SanType::DnsName(rcgen::Ia5String::try_from(spiffe_uri).unwrap())];
    
    let key_pair = KeyPair::generate().map_err(|_| Error::InitializationError)?;
    let cert = params.self_signed(&key_pair).map_err(|_| Error::InitializationError)?;
    
    let cert_der = cert.der().to_vec();
    let cert_hash = generate_session_cert_hash(&cert_der);
    
    // Create a combined PEM for reqwest::Identity
    let mut identity_pem = cert.pem().into_bytes();
    identity_pem.extend_from_slice(key_pair.serialize_pem().as_bytes());
    
    Ok((identity_pem, cert_hash, Some(spiffe_uri.to_string())))
}

pub async fn perform_sakshi_attestation(
    state: &AppState,
    tool_name: &str,
    mudra_val: [u8; 32],
    resource_val: [u8; 32],
    spiffe_id: Option<String>,
    nonce: [u8; 32],
    cert_hash: [u8; 32],
    telemetry: Telemetry,
) -> Result<Mudra, Error> {
    let auth_hash = state.hasher.hash(&[telemetry.authority_id.as_bytes()]);
    let integ_hash = match hex::decode(telemetry.integrity_hash.replace("0x", "")) {
        Ok(h) if h.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h);
            arr
        },
        _ => [0u8; 32],
    };

    let sig_bytes = hex::decode(telemetry.signature).map_err(|_| Error::SecurityViolation)?;
    if sig_bytes.len() != 64 { return Err(Error::SecurityViolation); }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_bytes);

    let signed_telemetry = SignedTelemetry {
        state: TelemetryState {
            ve_decay_rate: telemetry.v_e_decay,
            authority_hash: auth_hash,
            integrity_hash: integ_hash,
        },
        signature: sig,
    };

    let ctx = InboundContext::Mcp { 
        tool_name, 
        mudra: mudra_val, 
        resource: resource_val, 
        spiffe_id: spiffe_id.clone(), 
        nonce, 
        telemetry: signed_telemetry.clone(),
        max_decay: state.ve_threshold,
    };

    let intent = state.translator.translate_intent(ctx)?;
    let intent_hash = intent.generate_auth_hash(&*state.hasher)?;
    
    let credential = VerifiableCredential {
        context: 0x01, issuer: [0u8; 32], valid_from: 0, valid_until: 0,
        identity_hash: intent_hash,
        capability: tool_name, signature: [0u8; 64],
    };
    let env = EnvironmentContext { current_timestamp: 0, system_state_hash: [0u8; 32] };
    
    // Sakshi Attestation: Enforces Cryptographic Binding + Policy Comparison inside TEE
    let attestation_result = if state.telemetry_public_key == [0u8; 32] {
        // Bypass signature check in Dev/Mock mode if no public key is provided
        verify_and_gate(
            &*state.silicon, 
            &*state.policy_engine, 
            &*state.hasher, 
            &*state.comparator,
            &intent, 
            &credential, 
            &signed_telemetry,
            &[0u8; 32],
            &cert_hash, 
            &env, 
            spiffe_id.as_deref(),
            true // bypass_signature
        )
    } else {
        verify_and_gate(
            &*state.silicon, 
            &*state.policy_engine, 
            &*state.hasher, 
            &*state.comparator,
            &intent, 
            &credential, 
            &signed_telemetry,
            &state.telemetry_public_key,
            &cert_hash, 
            &env, 
            spiffe_id.as_deref(),
            false // bypass_signature
        )
    };

    let (pramana, mudra) = match attestation_result {
        Ok(res) => res,
        Err(e) => {
            error!("{}", state.lang_pack.attestation_failed(tool_name, &format!("{:?}", e)));
            return Err(e);
        }
    };
    
    // Verify the Pramana against the PramanaProvider (Forensic Scan of Ledger)
    state.connector.verify_pramana(tool_name, &pramana).await.map_err(|e| {
        error!("TECHNICAL INTEGRITY VIOLATION: Policy verification failed for {}: {:?}", tool_name, e);
        e
    })?;
    
    // Notarize the Pramana to the ledger (WORM WELD)
    let _ = state.connector.notarize_pramana(&pramana).await;
    
    Ok(mudra)
}

pub async fn handle_proxy_destination(
    state: &AppState,
    mudra: Mudra,
    target_url: &str,
    req: McpRequest,
    identity_pem: Vec<u8>,
    telemetry: Telemetry,
    effective_spiffe: String,
) -> Result<McpResponse, Error> {
    // --- PROVENANCE-BOUND MTLS FORWARDING logic ---
    // 1. Establish Identity from the ephemeral certificate and key
    let identity = reqwest::Identity::from_pem(&identity_pem)
        .map_err(|_| Error::InitializationError)?;

    // 2. Build a client bound to this specific hardware-notarized session
    let client = reqwest::Client::builder()
        .identity(identity)
        .use_rustls_tls()
        .build()
        .map_err(|_| Error::InitializationError)?;
    
    let mudra_hex = hex::encode(mudra.seal);
    let resp = client.post(target_url)
        .header("X-Sakshi-Mudra", mudra_hex)
        .header("X-Sakshi-Quote", hex::encode(&mudra.hardware_quote))
        .json(&req.params.as_ref().map(|p| &p.arguments).unwrap_or(&serde_json::Value::Null))
        .send().await.map_err(|_| Error::ProtocolMismatch)?;

    let body = resp.json().await.map_err(|_| Error::ProtocolMismatch)?;
    
    // 3. Final State Push: Record Execution Completion
    let body_bytes = serde_json::to_vec(&body).unwrap_or_default();
    let response_hash = state.hasher.hash(&[&body_bytes]);
    
    let event = SovereignEvent {
        stage: LifecycleStage::ExecutionCompletion,
        sankalpa_hash: mudra.seal,
        ve_decay_rate: telemetry.v_e_decay,
        spiffe_id: effective_spiffe,
        tdx_quote: None, // Quote already logged in Intent stage
        response_hash: Some(response_hash),
        error_message: None,
    };
    
    let _ = state.evidence_repo.append_evidence(event).await;

    Ok(McpResponse {
        jsonrpc: "2.0".to_string(), result: Some(body),
        provenance: Some(mudra), error: None, id: req.id,
    })
}

pub async fn process_request_matrix(state: Arc<AppState>, req: McpRequest) -> McpResponse {
    let req_id = req.id.clone();
    
    if state.verbose {
        info!("[PROXY] Incoming Request: method={}, id={:?}", req.method, req_id);
    }

    // Handle standard MCP initialization
    if req.method == "initialize" {
        return McpResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "citadel-mcp-server",
                    "version": "0.1.0"
                }
            })),
            provenance: None,
            error: None,
            id: req_id,
        };
    }

    let tool_name = req.params.as_ref().and_then(|p| p.tool_name.as_deref())
        .or_else(|| req.params.as_ref().and_then(|p| p.arguments.get("tool_name").and_then(|v| v.as_str())))
        .or_else(|| req.params.as_ref().and_then(|p| p.arguments.get("name").and_then(|v| v.as_str())))
        .unwrap_or("unknown");

    if state.verbose {
        info!("[PROXY] Tool Call: {} (ID: {:?})", tool_name, req_id);
    }

    let telemetry = match req.params.as_ref().and_then(|p| p.telemetry.clone())
        .or_else(|| req.params.as_ref().and_then(|p| serde_json::from_value(p.arguments.get("telemetry")?.clone()).ok())) {
        Some(t) => t,
        None => {
            let msg = state.lang_pack.telemetry_missing();
            info!("GATE_REFUSAL: {}", msg);
            let event = SovereignEvent {
                stage: LifecycleStage::AdmissibilityRefusal,
                sankalpa_hash: [0u8; 32],
                ve_decay_rate: 0.0,
                spiffe_id: "unknown".into(),
                tdx_quote: None,
                response_hash: None,
                error_message: Some(msg.clone()),
            };
            let _ = state.evidence_repo.append_evidence(event).await;

            return McpResponse {
                jsonrpc: "2.0".to_string(), result: None, provenance: None,
                error: Some(McpError { code: -32001, message: msg }), id: req_id,
            };
        }
    };
    
    // 1. Admissibility Gate Check
    if telemetry.v_e_decay < state.ve_threshold {
        let msg = state.lang_pack.admissibility_failure_ve(telemetry.v_e_decay, state.ve_threshold);
        info!("GATE_REFUSAL: {}", msg);
        
        let event = SovereignEvent {
            stage: LifecycleStage::AdmissibilityRefusal,
            sankalpa_hash: [0u8; 32], // Hash not yet generated
            ve_decay_rate: telemetry.v_e_decay,
            spiffe_id: "unknown".into(),
            tdx_quote: None,
            response_hash: None,
            error_message: Some(msg.clone()),
        };
        let repo = state.evidence_repo.clone();
        let _ = repo.append_evidence(event).await; // Best-effort refusal record

        return McpResponse {
            jsonrpc: "2.0".to_string(), result: None, provenance: None,
            error: Some(McpError { code: -32001, message: msg }), id: req_id,
        };
    }

    let tool_policy = match state.config.authorized_tools.get(tool_name) {
        Some(p) => p,
        None => {
            let msg = state.lang_pack.policy_refusal_unauthorized(tool_name);
            info!("GATE_REFUSAL: {}", msg);
            let event = SovereignEvent {
                stage: LifecycleStage::AdmissibilityRefusal, // Standardizing pre-attestation gate failures
                sankalpa_hash: [0u8; 32],
                ve_decay_rate: telemetry.v_e_decay,
                spiffe_id: "unknown".into(),
                tdx_quote: None,
                response_hash: None,
                error_message: Some(msg.clone()),
            };
            let _ = state.evidence_repo.append_evidence(event).await;

            return McpResponse {
                jsonrpc: "2.0".to_string(), result: None, provenance: None,
                error: Some(McpError { code: -32001, message: msg }), id: req_id,
            };
        }
    };

    if state.verbose {
        info!("[PROXY] Policy Authorized: Mode={:?}", tool_policy.mode);
    }


    // Restore Config-Based Values
    let mut mudra_val = [0u8; 32];
    if let Some(ref ctx) = state.config.identity_context {
        if let Ok(bytes) = hex::decode(ctx.replace("0x", "")) {
            if bytes.len() >= 32 { mudra_val.copy_from_slice(&bytes[..32]); }
        }
    }

    let mut resource_val = [0u8; 32];
    if let Some(ref ctx) = state.config.resource_context {
        if let Ok(bytes) = hex::decode(ctx.replace("0x", "")) {
            if bytes.len() >= 32 { resource_val.copy_from_slice(&bytes[..32]); }
        }
    }

    let (identity_pem, cert_hash, spiffe_id) = create_ephemeral_mtls_cert().unwrap();
    let effective_spiffe = spiffe_id.clone().unwrap_or_else(|| "spiffe://citadel.internal/anonymous".to_string());
    
    // Resolve matrix behavior with real SPIFFE ID and telemetry
    match perform_sakshi_attestation(&*state, tool_name, mudra_val, resource_val, spiffe_id, [0u8; 32], cert_hash, telemetry.clone()).await {
        Ok(mudra) => {
            info!("{}", state.lang_pack.attestation_passed(&hex::encode(&mudra.seal[..8])));
            // Task 2: WORM WELD via PramanaRepository (Intent Stage)
            let event = SovereignEvent {
                stage: LifecycleStage::SankalpaIntent,
                sankalpa_hash: mudra.seal,
                ve_decay_rate: telemetry.v_e_decay,
                spiffe_id: effective_spiffe.clone(),
                tdx_quote: Some(mudra.hardware_quote.clone()),
                response_hash: None,
                error_message: None,
            };

            let repo = state.evidence_repo.clone();
            let append_future = tokio::time::timeout(std::time::Duration::from_millis(50), async move {
                repo.append_evidence(event).await
            });

            match append_future.await {
                Ok(Ok(_)) => {
                    info!("{}", state.lang_pack.notarization_success());
                },
                Ok(Err(e)) => {
                    error!("{}", state.lang_pack.notarization_error(&format!("{:?}", e)));
                    // Fallback to local encrypted quarantine buffer (placeholder logic)
                    warn!("{}", state.lang_pack.notarization_fallback_quarantine());
                },
                Err(_) => {
                    error!("{}", state.lang_pack.notarization_timeout(50));
                    // Strict fail-closed policy
                    return McpResponse {
                        jsonrpc: "2.0".to_string(), result: None, provenance: None,
                        error: Some(McpError { code: -32003, message: state.lang_pack.notarization_timeout(50) }), id: req_id,
                    };
                }
            }

            if req.method == "citadel_shutdown" || tool_name == "shutdown" {
                info!("{}", state.lang_pack.shutdown_request());
                state.token.cancel();
            }

            match tool_policy.mode {
                RoutingMode::Notary => {
                    info!("{}", state.lang_pack.proxy_routing("NOTARY", "Direct Mudra Return"));
                    McpResponse {
                        jsonrpc: "2.0".to_string(), result: Some(serde_json::to_value(hex::encode(mudra.seal)).unwrap()),
                        provenance: Some(mudra), error: None, id: req_id,
                    }
                },
                RoutingMode::Proxy => {
                    let target = tool_policy.target_url.as_deref().unwrap_or("http://localhost:8080");
                    info!("{}", state.lang_pack.proxy_routing("PROXY", target));
                    match handle_proxy_destination(&*state, mudra.clone(), target, req, identity_pem, telemetry.clone(), effective_spiffe.clone()).await {
                        Ok(r) => {
                            info!("{}", state.lang_pack.proxy_success(&format!("{:?}", req_id)));
                            r
                        },
                        Err(e) => {
                            error!("{}", state.lang_pack.proxy_error(&format!("{:?}", e)));
                            let event = SovereignEvent {
                                stage: LifecycleStage::SystemFailure,
                                sankalpa_hash: mudra.seal,
                                ve_decay_rate: telemetry.v_e_decay,
                                spiffe_id: effective_spiffe,
                                tdx_quote: None,
                                response_hash: None,
                                error_message: Some(format!("Proxy Error: {:?}", e)),
                            };
                            let _ = state.evidence_repo.append_evidence(event).await;

                            McpResponse {
                                jsonrpc: "2.0".to_string(), result: None, provenance: None,
                                error: Some(McpError { code: -32002, message: format!("Proxy Error: {:?}", e) }), id: req_id,
                            }
                        }
                    }
                }
            }
        },
        Err(e) => {
            error!("{}", state.lang_pack.attestation_failed("unknown", &format!("{:?}", e)));
            let event = SovereignEvent {
                stage: LifecycleStage::SystemFailure,
                sankalpa_hash: [0u8; 32],
                ve_decay_rate: telemetry.v_e_decay,
                spiffe_id: effective_spiffe,
                tdx_quote: None,
                response_hash: None,
                error_message: Some(format!("Sakshi Attestation Failed: {:?}", e)),
            };
            let _ = state.evidence_repo.append_evidence(event).await;

            McpResponse {
                jsonrpc: "2.0".to_string(), result: None, provenance: None,
                error: Some(McpError { code: -32000, message: format!("Sakshi Attestation Failed: {:?}", e) }), id: req_id,
            }
        }
    }
}
