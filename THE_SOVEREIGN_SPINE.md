# The Sovereign Spine — Technical Architecture of the Citadel Protocol

The Citadel Protocol is a hardware — enforced validation layer designed to resolve the structural fragility of probabilistic AI governance. It provides a **Silicon Airlock** for autonomous agents, ensuring that every reasoning chain and subsequent action is notarized by a Trusted Execution Environment (TEE) before reaching legacy infrastructure.

## 1. The Mission — From Probability to Determinism

Legacy security models rely on identity and static permissions. AI agents, however, require a governance model that understands **intent** and **stability**. Citadel shifts the burden of trust from the software stack to the silicon itself, using Intel TDX to witness the reasoning process and issue a cryptographic **Mudra** only when the agent remains within mandated bounds.

## 2. Core Architectural Components

The protocol is composed of three specialized layers that work in concert to maintain technical integrity.

### A. The Sakshi (The Hardware Witness)
The Witness resides at the core of the system. It is a `no_std` Rust implementation that operates inside an Intel TDX enclave. Its sole purpose is to observe the **Sankalpa** — the agent's intent — and the associated telemetry.
*   **Hardware Isolation**: Because it is hardware — isolated, it cannot be subverted by the host operating system or the agent itself.
*   **The Pramana**: It produces a hardware — signed proof that the admissible state was maintained during the reasoning phase.
*   **Cryptographic Binding**: It welds the intent hash, session mTLS certificate hash, and authority identity into a single 32 — byte report data field.

### B. The Mudra Gate (The Application Gateway)
The Gateway acts as the primary ingestion boundary. It intercepts Model Context Protocol (MCP) JSON — RPC calls and enforces the **Admissibility Gate**. It performs three critical checks before allowing a request to proceed:
*   **Identity Verification**: Confirms the agent's session credentials via long — lived mTLS identities generated at bootstrap.
*   **Telemetry Validation**: Verifies the signature of 3rd — party telemetry to ensure the model's Execution Velocity ($V_e$) decay is within the authorized threshold.
*   **Policy Governance**: Performs an $O(1)$ memory lookup against a cached version of the ledger — backed ruleset to ensure the requested tool and logic hash are authorized.

### C. The Sovereign Registry (The Ledger Adapter)
Citadel utilizes the Hedera Consensus Service (HCS) as its Write — Once — Read — Many (WORM) repository. To satisfy high — frequency agentic requirements, the registry is split into two domain boundaries:
*   **Topic A: The Pramana Vault (High Throughput)**: Stores every fused hardware witness and execution event. Messages are indexed by a globally unique **Sequence Number**.
*   **Topic B: Policy Governance (High Security)**: Stores the cryptographic hashes of active rulesets. The Gateway maintains a background sync task to keep its local policy cache current.

---

## 3. Integration & 3rd — Party Requirements

To function as a universal "Airlock," Citadel imposes specific requirements on the surrounding agentic ecosystem.

### A. Telemetry Providers (MTCP Measurement Nodes)
Citadel does not perform model analysis. It requires a 3rd — party **MTCP (Model Technical Constraint Protocol)** provider to generate signed telemetry.
*   **Sign-at-Source**: Telemetry must be signed by an Ed25519 private key known to the Citadel TEE.
*   **Payload Requirements**: Must include the `v_e_decay` (Execution Velocity), `authority_id`, and `integrity_hash`.
*   **Verification**: Citadel verifies this signature **inside the TEE** to ensure the telemetry has not been tampered with by the host machine (Airgap Integrity).

### B. The Citadel Attestation Plugin (Target Verification)
Target systems (legacy servers, databases, or other agents) must be "Citadel — Aware" to complete the trust loop. This is achieved via the **Citadel Attestation Plugin**, provided as a library or middleware:

1.  **`citadel-axum-adapter` (The Target Plugin)**:
    *   A drop — in middleware for Axum / Hyper servers.
    *   It intercepts incoming requests and extracts the **Mudra seal** and **Sequence Number**.
    *   It performs a sub — 10ms **Forensic Lookup** against the Hedera Mirror Node at the provided sequence number to confirm the action was notarized by a valid Citadel Witness.
    *   It rejects any request that lacks a valid, ledger — confirmed hardware coordinate.

2.  **`citadel-a2a-connector` (The P2P Bridge)**:
    *   Enables agent — to — agent (A2A) workflows via gRPC.
    *   Enforces a **Sovereign Handshake**: Peers must exchange hardware quotes and verify each other's MRTD against the Sovereign Anchor before a session is established.
    *   Reuses long — lived session identities to maintain high throughput during distributed reasoning.

### C. The Sovereign Anchor (Ledger Anchoring)
Before a Gateway can process requests, its golden measurement (MRTD) must be anchored to the Hiero topic using the `anchor_mrtd` utility. This acts as the "Sovereign Root of Trust" that all plugins use to verify the Gateway's own integrity.

---

## 4. The Workflow Lifecycle — Enabling Secure Autonomy

1.  **Intent Binding**: The agent submits an intent (Sankalpa) along with signed telemetry.
2.  **Hardware Attestation**: The Sakshi witness verifies the telemetry signature inside the TEE and binds it to the intent.
3.  **WORM Weld**: The Gateway notarizes the attestation to the Hiero ledger.
4.  **Coordinate Handoff**: The agent receives a **Mudra seal** containing the **Topic Sequence Number**.
5.  **Target Execution**: The agent presents this seal to the target server (protected by the Citadel Plugin).
6.  **Forensic Verification**: The Plugin performs an $O(1)$ lookup at the provided sequence number, granting access only upon hardware — rooted confirmation.

## 5. Maintaining Necessary Check

Citadel does not control the model; it validates the model's output against a rigid technical integrity framework. By decoupling telemetry generation from validation and utilizing $O(1)$ ledger coordinates, Citadel ensures that agents can operate with high autonomy while remaining under the absolute check of the **Sovereign Spine**.

---

## 6. Roadmap & Future Evolution (Milestone v0.3+)

The Citadel Protocol is evolving to support enterprise — scale agentic meshes and deep integration with global governance frameworks.

### A. Centralized Enterprise Identity (HashiCorp Vault / Azure Key Vault)
Currently, Citadel utilizing a local, file — based encrypted vault (`vault.json`). To support cloud — native elastic scaling, the **SecretStore** abstraction will be expanded to support centralized providers.
*   **Dynamic Identity Injection**: Gateway identities and telemetry verification keys will be fetched at runtime from secure KMS providers.
*   **Hardware — Bound Secrets**: Integration with TEE — based secret sealing to ensure that even if the KMS is compromised, the keys can only be decrypted inside a valid Intel TDX environment.

### B. Governance Engine Plugins (IBM watsonx Integration)
To bridge the gap between high — level policy definition and hardware enforcement, Citadel will develop specialized plugins for leading AI governance platforms.
*   **watsonx Policy Sync**: A background adapter that monitors **watsonx.governance** for policy updates and automatically notarizes the resulting logic hashes to the Hiero Governance Topic.
*   **Direct Telemetry Extraction**: Developing plugins to pull model health and bias metrics directly from governance engines, transforming them into signed MTCP telemetry blocks for the Sakshi witness.

### C. Advanced Forensic Visualization
A web — based "Forensic Dashboard" that allows auditors to input a Mudra Sequence Number and instantly visualize the entire reasoning chain, the hardware witness quote, and the consensus state on the ledger.
