# The Citadel Protocol — Hardware-Enforced Agentic Strangler

In an era of autonomous agents, the Citadel Protocol acts as a deterministic gatekeeper — a Silicon Airlock for AI agents to interact with legacy systems only after intent has been cryptographically notarized by a Trusted Execution Environment (TEE).

## Executive Vision: The Sovereign Spine
The Citadel Protocol resolves the inherent instability of "software hope" (probabilistic, non-deterministic AI) by enforcing a deterministic governance framework anchored in hardware. By fusing ledger-based proof of reasoning with hardware roots of trust, Citadel provides a forensic-grade audit trail and an instantaneous admissibility gate for agentic workloads.

---

## Quick Start
Developers can simulate the environment without requiring specialized hardware by utilizing the `MockProvider`.

### Prerequisites
* Rust 1.75+
* Intel TDX enabled hardware (or `MockProvider` for development)
* A valid Hedera Account (Testnet or Mainnet) for evidence notarization.

### Build & Run
```bash
# Build
./release.sh

# Run (Ephemeral Notary)
echo '{...}' | ./target/debug/citadel-mcp-server --logic notary --transport mcp-stdio --lifecycle ephemeral --ve-threshold 0.95
```

### Environment Configuration (.env & vault.json)

Credential management is decoupled from policy. While `.env` can be used for basic configuration, Citadel prefers the encrypted **vault.json** for sensitive identity management.

**Example vault.json (Identities for Hiero and Telemetry):**

```json
{
  "hiero-governance-id": "0.0.00000000",
  "hiero-governance-key": "xxxxx71684d9c60eb28898de0e1448104df62f604867110db1d6250c6f9cbf191",
  "hiero-operator-id": "0.0.00000000",
  "hiero-operator-key": "xxxxx71684d9c60eb28898de0e1448104df62f604867110db1d6250c6f9cbf191",
  "telemetry-public-key": "yyyybff6b88616a06e7ebff6b886226bff6b88604a8bbff6b886cdadcbff6b886"
}

```

* **`telemetry-public-key`**: The Ed25519 public key used to verify telemetry signatures inside the TEE.

### CLI Usage Examples

**CI Notary with specific Admissibility threshold override**:

```bash
echo '{...}' | ./target/debug/citadel-mcp-server --logic notary --transport mcp-stdio --lifecycle ephemeral --ve-threshold 0.95

```

**Production Proxy (Persistent SSE Gateway using policy threshold)**:

```bash
./target/debug/citadel-mcp-server --logic proxy --transport mcp-sse --lifecycle persistent --port 9000

```
## Architectural Foundations (The Dual-Topic Model)

To achieve sub-10ms verification latency on public ledgers without a local database, Citadel employs a **Dual-Topic Domain Boundary** architecture on the Hedera Consensus Service (HCS):

* **Topic A — The Pramana Vault (High Throughput)**: Stores every fused Pramana (MTCP Evidence + TEE Hardware Witness). Messages are indexed by a globally unique Sequence Number.
* **Topic B — Policy Governance (High Security)**: Stores cryptographic hashes of authorized rulesets. The Gateway maintains a background-polling cache of this topic for near-instant memory lookups.

### The Sub-10ms $O(1)$ Verification Secret

Instead of linear ledger scans, Citadel leverages the Hedera **Topic Sequence Number**. When a Pramana is notarized, the Gateway receives a unique coordinate (e.g., Sequence #62). This coordinate is handed back to the agent in the **Mudra** seal. Subsequent verification is an $O(1)$ direct REST call to the Mirror Node, meeting strict performance budgets for real-time agentic interactions.

## Separation of Concerns — Telemetry & Validation

The Citadel Protocol operates as a specialized **Validation Layer**. It does not perform model analysis or generate telemetry; these are the purview of 3rd-party MTCP Measurement Nodes. Citadel strictly **reads and verifies** signed telemetry at the ingestion boundary, ensuring that only "admissible" intents are notarized by the hardware.

## The Lexicon of Citadel (The Sovereign Spine)

To resolve the structural fragility of probabilistic governance, we employ a deterministic ontology anchored in Sanskrit:

* **Sankalpa**: The "Intention" — A cryptographic vow binding identity and intent to the immediate moment of execution.
* **Sakshi**: The "Witness" — A decoupled, hardware-isolated observer (Intel TDX) that monitors the reasoning chain without possessing the authority to execute.
* **Pramana**: The "Admissible Proof" — The unforgeable, verifiable artifact proving the model maintained its constraint state throughout generation.
* **Mudra**: The "Single-Use Key / Seal" — The deterministic bridge connecting logical proof (Pramana) to physical hardware execution via the Iron Floor.

## The Admissibility Gate (Capability-Based Security)

Citadel enforces a **Capability-Based Admissibility Gate** to prevent the execution of unstable or unauthorized AI decisions. Every **Sankalpa** (intent bundle) must include structural telemetry:

* **Execution Velocity ($V_e$) Decay**: A telemetry metric measuring model stability.
* **Source-Signed Telemetry (Airgap Integrity)**: Telemetry is signed at the source (MTCP Measurement Node). The host machine acts as a dumb pipe; the signature is verified **inside the TEE** to prevent Layer 2 spoofing.
* **Deterministic Synthesis**: The system enforces a strictly deterministic check ($\text{Current\_MTCP\_Decay} \ge \text{Sankalpa\_Max\_Decay}$). This comparison is abstracted into the `PolicyComparator` trait and executed in the `no_std` core.
* **Cryptographic Binding**: The $V_e$ decay, authority identity, and workload integrity hash are structurally bound to the intent payload and hashed together inside the TEE.

## The WORM WELD (Evidence Notarization)

Citadel enforces a **Fail-Closed** security posture via the `PramanaRepository`. Every transaction is notarized across multiple lifecycle stages to ensure a complete forensic audit trail:

* **SovereignEvent**: A protobuf-compatible structure containing the stage, sankalpa_hash, ve_decay_rate, spiffe_id, and stage-specific data (quotes, response hashes, or error messages).
* **Lifecycle Stages**: Includes `AdmissibilityRefusal` (recorded if the intent fails the pre-hardware threshold check), `SankalpaIntent` (recorded upon successful hardware attestation), `ExecutionCompletion` (recorded after proxy execution), and `SystemFailure` (recorded if an unexpected error occurs).
* **Hiero Consensus Service (HCS)**: The default production repository. It routes events to the **Pramana Vault** or **Policy Governance** topic based on the event stage.
* **Sequence-Based Provenance**: Every notarized event returns a `u64` sequence number, enabling $O(1)$ instantaneous verification.
* **Terminal Refusal**: The gateway applies a strict **50ms timeout** on evidence submission. Failure to notarize triggers a Terminal Refusal.

## Core Architecture & Modularization

The Citadel Protocol is structured into specialized crates and modules to ensure a clear separation between hardware-rooted trust and application-level gateway logic:

* **`sakshi-core`**: The "no_std" core defining the foundational traits (**Sankalpa**, **Mudra**, **SiliconProvider**) and the primary `verify_and_gate` orchestration logic.
* **`citadel-verifier`**: A new specialized crate for TEE-signed Pramana verification and identity extraction.
* **`citadel-mcp-server`**: The Gateway implementation, now optimized for high-frequency interactions. It orchestrates logic using long-lived session identities (`src/main.rs`), utilizes a unified configuration supporting both Hiero topics (`src/policy.rs`), and manages decoupled JSON-RPC protocol structures (`src/mcp.rs`).
* **`citadel-a2a-connector`**: The Peer-to-Peer (Agent-to-Agent) gRPC bridge for decentralized attestation.

## The Sovereign Spine — Configuration Matrix

### Policy Configuration (`policy.json`)

The `policy.json` file serves as the primary source of truth for the gateway's governance behavior.

```json
{
  "environment": "development",
  "ve_threshold": 0.90,
  "hiero_vault_topic_id": "0.0.8941781",
  "hiero_gov_topic_id": "0.0.8941781",
  "authorized_tools": {
    "webMethods_Flow_Alpha": {
      "hash": "a8dd1f8b061dc276403a9b2a6c354f672958071d72d6d088ca6397b59e665f27",
      "mode": "proxy",
      "target_url": "http://127.0.0.1:8080/invoke/alpha"
    }
  }
}

```

* **`ve_threshold`**: The default $V_e$ stability threshold for the admissibility gate.
* **`hiero_vault_topic_id`**: High-throughput topic for technical integrity evidence (Pramana Vault).
* **`hiero_gov_topic_id`**: High-security topic for authorized ruleset hashes (Policy Governance).
* **`authorized_tools`**: Mapping of tool names to their cryptographic hashes and routing modes.

### Dimensions of Operation

The Citadel Gateway operates on a three-dimensional matrix to support diverse deployment environments:

* **Logic Mode (`--logic`)**: Can be configured as `notary` (returns a **Mudra** hardware seal to the caller) or `proxy` (intercepts, notarizes, and forwards via a **Provenance-Bound mTLS tunnel**).
* **Transport Mode (`--transport`)**: Supports `mcp-stdio` (JSON-RPC over standard input/output), `mcp-sse` (JSON-RPC over Server-Sent Events), or `grpc` (high-performance binary mesh).
* **Lifecycle Mode (`--lifecycle`)**: Operates as `ephemeral` (one transaction and exit) or `persistent` (long-running gateway listening for subsequent requests).

## How it Works (The Gateway)

1. **Bootstrap**: On startup, Citadel generates a **long-lived session identity** and performs hardware-rooted self-attestation against the Sovereign Anchor on the Hiero ledger.
2. **Intercept**: The Gateway receives an MCP request containing **3rd-party signed telemetry**.
3. **Admissibility Check**: The system verifies the telemetry signature and validates the $V_e$ decay against the mandated threshold.
4. **Governance**: The system performs a near-instant cache lookup to verify the **Sankalpa** hash against the Governance Topic.
5. **Hardware Observation (Sakshi)**: The TEE immutably binds the intent, telemetry, and session certificate into a **Pramana**.
6. **Notarization & Handoff**: The Pramana is notarized to the Vault Topic. The resulting **Sequence Number** is returned in the **Mudra** seal, providing the client with precise ledger coordinates for $O(1)$ verification.

## Verification & Validation

The Citadel Protocol undergoes rigorous validation to ensure the technical integrity of the Sovereign Spine:

* **Native Rust Unit Tests**: All core crates (`sakshi-core`, `citadel-adapter-hiero`, etc.) are covered by native Rust unit tests. Recent runs show 100% pass rate across the workspace.
* **Comprehensive E2E Test Suite**: A Python-based integration harness (`tests/e2e_master_suite.py`) verifies the entire lifecycle from policy notarization to MCP request execution.

### Successful E2E Run (Scenario 1)

The system has been successfully verified using scenario 1 ("SUCCESS - Integrated RIOM"). This confirms:

1. **Hardware-Rooted Self-Attestation**: The Gateway successfully bootstrapped against the Sovereign Anchor on the Hiero ledger.
2. **Policy Integrity**: The `anchor_policy` tool successfully notarized a policy update for `sphere://demo/light/green-blue-cyan`.
3. **Admissibility & Attestation**: The Gateway correctly verified the telemetry signature and $V_e$ decay, issuing a valid **Mudra** seal.

## Security

This project is in Milestone v0.1.0. All sensitive tool calls MUST be notarized via the `verify_and_gate` function to ensure technical integrity and hardware-rooted trust.

## Research & Academic Citations

The Citadel Protocol is the formal reference implementation of a dual-stack architecture for hardware-enforced agentic governance. For the deep-dive theoretical models, ontologies, and cryptographic foundations, refer to the following published research:

*   **A Forensic Lexicon for the Agentic Era — Architectural Primitives of the Sovereign Spine**  
    *Digital Object Identifier:* [https://doi.org/10.5281/zenodo.19775766](https://doi.org/10.5281/zenodo.19775766)
*   **The Citadel Protocol — A Reference Architecture for Hardware-Enforced Agentic Governance**  
    *Digital Object Identifier:* [https://doi.org/10.5281/zenodo.18472859](https://doi.org/10.5281/zenodo.18472859)
*   **Fusing Ledger-Based Proof of Reasoning with Hardware Roots of Trust**  
    *Digital Object Identifier:* [https://doi.org/10.5281/zenodo.19431105](https://doi.org/10.5281/zenodo.19431105)

If you are leveraging this framework or its deterministic ontology in an academic or corporate research setting, please cite the blueprints above.
