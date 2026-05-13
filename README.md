# The Citadel Protocol: Hardware — Enforced Agentic Strangler

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-green.svg)]()

In an era of autonomous agents, the Citadel Protocol acts as a deterministic gatekeeper — a Silicon Airlock for AI agents to interact with legacy systems only after intent has been cryptographically notarized by a Trusted Execution Environment (TEE).

## The Lexicon of Citadel (The Sovereign Spine)

To resolve the structural fragility of probabilistic governance, we employ a deterministic ontology anchored in Sanskrit:

*   **Sankalpa**: The "Intention" — A cryptographic vow binding identity and intent to the immediate moment of execution.
*   **Sakshi**: The "Witness" — A decoupled, hardware-isolated observer (Intel TDX) that monitors the reasoning chain without possessing the authority to execute.
*   **Pramana**: The "Admissible Proof" — The unforgeable, verifiable artifact proving the model maintained its constraint state throughout generation.
*   **Mudra**: The "Single-Use Key / Seal" — The deterministic bridge connecting logical proof (Pramana) to physical hardware execution via the Iron Floor.

## The Admissibility Gate (Capability — Based Security)

Citadel enforces a **Capability — Based Admissibility Gate** to prevent the execution of unstable or unauthorized AI decisions. Every **Sankalpa** (intent bundle) must include structural telemetry:

*   **Execution Velocity ($V_e$) Decay**: A telemetry metric measuring model stability. 
*   **Source — Signed Telemetry (Airgap Integrity)**: Telemetry is signed at the source (MTCP Measurement Node). The host machine acts as a dumb pipe; the signature is verified **inside the TEE** to prevent Layer 2 spoofing.
*   **Deterministic Synthesis**: The system enforces a strictly deterministic check: `Current_MTCP_Decay >= Sankalpa_Max_Decay`. This comparison is abstracted into the `PolicyComparator` trait and executed in the `no_std` core.
*   **Cryptographic Binding**: The $V_e$ decay, authority identity, and workload integrity hash are structurally bound to the intent payload and hashed together inside the TEE.

## The WORM WELD (Evidence Notarization)

Citadel enforces a **Fail — Closed** security posture via the `PramanaRepository`. Every transaction is notarized across multiple lifecycle stages to ensure a complete forensic audit trail:

*   **SovereignEvent**: A protobuf — compatible structure containing the `stage`, `sankalpa_hash`, `ve_decay_rate`, `spiffe_id`, and stage — specific data (quotes, response hashes, or error messages).
*   **Lifecycle Stages**:
    *   **`AdmissibilityRefusal`**: Recorded if the intent fails the pre — hardware $V_e$ threshold check.
    *   **`SankalpaIntent`**: Recorded upon successful hardware attestation, binding the quote to the intent.
    *   **`ExecutionCompletion`**: Recorded after proxy execution, binding the response hash to the original intent.
    *   **`SystemFailure`**: Recorded if an unexpected error occurs during attestation or proxying.
*   **Hiero Consensus Service (HCS)**: The default production repository. It submits `SovereignEvents` to a public HCS Topic.
*   **Terminal Refusal**: The gateway applies a strict **50ms timeout** on evidence submission during the Intent stage. Failure to notarize triggers a Terminal Refusal.

## Core Architecture & Modularization

The Citadel Protocol is structured into specialized crates and modules to ensure a clear separation between hardware-rooted trust and application-level gateway logic:

*   **`sakshi-core`**: The "no_std" core defining the foundational traits (**Sankalpa**, **Mudra**, **SiliconProvider**) and the primary `verify_and_gate` orchestration logic.
*   **`citadel-verifier`**: A new specialized crate for TEE-signed Pramana verification and identity extraction.
*   **`citadel-mcp-server`**: The Gateway implementation, now refactored for high maintainability:
    *   `src/main.rs`: High-level orchestration, now using consolidated configuration.
    *   `src/policy.rs`: Unified **CitadelConfig** schema for both environment and tool policies.
    *   `src/mcp.rs`: Decoupled JSON-RPC protocol structures and MCP handling logic.
*   **`citadel-a2a-connector`**: The Peer-to-Peer (Agent-to-Agent) gRPC bridge for decentralized attestation.

## Core Architectural Improvements (v0.2)

To ensure the technical integrity and maintainability of the Sovereign Spine, the following structural improvements have been implemented:

*   **Centralized Dependency Management**: All common dependencies (Tokio, Serde, Tracing, etc.) are managed at the workspace root via `[workspace.dependencies]`, ensuring version consistency across all crates.
*   **Strict Type Validation**: Introduced a specialized `Mrtd` type with built-in hex validation and length enforcement to prevent malformed measurements from reaching the attestation layer.
*   **Unified Configuration Layer**: Merged the fragmented `citadel.toml` and `policy.json` into a single, cohesive `CitadelConfig` schema. The system now supports both TOML and JSON formats for environment and policy definitions.
*   **Feature-Gated Mock Logic**: All non-production mock hardware logic is strictly gated behind the `mock-hardware` feature flag, ensuring that hardcoded test measurements are definitively stripped from production builds.
*   **Native Rust Testing**: Complemented the Python integration harness with native Rust unit tests in `sakshi-core` to verify the core `verify_and_gate` logic.

## Observability & Technical Integrity

To support the auditing requirements of a "Silicon Airlock," Citadel employs a structured observability stack:

*   **Structured Logging**: Powered by the `tracing` crate. All security-critical events (Attestation results, Policy refusals, WORM welds) are emitted as structured logs.
*   **Log Level Control**: Fine-grained visibility across the gateway and A2A connector using standard log levels (`info`, `warn`, `error`).
*   **Deterministic Failure Analysis**: Detailed error context for attestation failures, including intent hashes and hardware quote verification errors.

## The Sovereign Spine: Configuration Matrix

### Policy Configuration (`policy.json`)
The `policy.json` file serves as the primary source of truth for the gateway's governance behavior.

```json
{
  "environment": "development",
  "ve_threshold": 0.90,
  "hiero_topic_id": "0.0.123456",
  "authorized_tools": {
    "webMethods_Flow_Alpha": {
      "hash": "a8dd1f8b061dc276403a9b2a6c354f672958071d72d6d088ca6397b59e665f27",
      "mode": "proxy",
      "target_url": "http://127.0.0.1:8080/invoke/alpha"
    }
  }
}
```

*   **`ve_threshold`**: The default $V_e$ stability threshold for the admissibility gate.
*   **`hiero_topic_id`**: The public HCS topic for evidence notarization.
*   **`authorized_tools`**: Mapping of tool names to their cryptographic hashes and routing modes.

### Dimensions of Operation

The Citadel Gateway operates on a three-dimensional matrix to support diverse deployment environments:

1. **Logic Mode (`--logic`)**:
    *   **`notary`**: Returns a **Mudra** (hardware seal) to the caller.
    *   **`proxy`**: Intercepts, notarizes, and forwards via a **Provenance-Bound mTLS tunnel**.
2. **Transport Mode (`--transport`)**:
    *   **`mcp-stdio`**: JSON-RPC over standard input/output.
    *   **`mcp-sse`**: JSON-RPC over Server-Sent Events.
    *   **`grpc`**: High-performance binary mesh.
3. **Lifecycle Mode (`--lifecycle`)**:
    *   **`ephemeral`**: One transaction and exit.
    *   **`persistent`**: Long-running gateway listening for subsequent requests.

## How it Works (The Gateway)

1.  **Bootstrap**: On startup, Citadel performs a **Hardware-Rooted Self-Attestation**. It extracts its silicon measurement (MRTD) and verifies it against the **Sovereign Anchor** on the Hiero ledger. If the measurements differ or the ledger is unreachable, the system enters **Terminal Refusal** and exits.
2.  **Intercept**: The **Gateway** receives an MCP request.
3.  **Admissibility Check**: The system validates the telemetry block. If $V_e$ decay < `--ve-threshold` (or the policy value), it returns an **Admissibility Failure** (-32001).
3.  **Governance**: The system checks the **Sankalpa** against the authorized `policy.json`.
4.  **Hardware Observation (Sakshi)**: If authorized, the `sakshi-core` layer **welds** the intent and telemetry into the Silicon Truth, triggering Intel TDX to generate a **Pramana**.
5.  **Verification & Notarization**: The **Pramana** is verified against a `PramanaProvider` and notarized to a WORM ledger.
6.  **Seal Issuance (Mudra)**: Upon success, the Sakshi issues a **Mudra** — a cryptographic seal notarizing the bound state of the intent, telemetry, and identity.

## Getting Started

### Prerequisites
*   Rust 1.75+
*   Intel TDX enabled hardware (or `MockProvider` for development)

### Build
```bash
./release.sh
```

### Environment Configuration (.env)
Credential management is decoupled from policy. Create a `.env` file to configure the Hiero repository:

```bash
# Hiero Network (testnet, mainnet, or local)
HIERO_NETWORK=testnet
HIERO_TOPIC_ID=0.0.xxxxxx

# Local Node Configuration (Required if HIERO_NETWORK=local)
HIERO_NODE_ADDRESS=127.0.0.1:50211
HIERO_NODE_ACCOUNT_ID=0.0.3
HIERO_MIRROR_NODE_ADDRESS=127.0.0.1:5600

# Hiero Operator (Secrets — Stored out-of-band)
HIERO_OPERATOR_ID=0.0.xxxxxx
HIERO_OPERATOR_KEY=302e0201...
HIERO_OPERATOR_PUBLIC_KEY=89abcdef...
```

### CLI Usage Examples

**CI Notary with specific Admissibility threshold override**:
```bash
echo '{...}' | ./target/debug/citadel-mcp-server --logic notary --transport mcp-stdio --lifecycle ephemeral --ve-threshold 0.95
```

**Production Proxy (Persistent SSE Gateway using policy threshold)**:
```bash
./target/debug/citadel-mcp-server --logic proxy --transport mcp-sse --lifecycle persistent --port 9000
```

## Milestone v0.1 Changes
*   **Capability — Based Admissibility Gate**: Transitioned to a formal governance framework enforcing $V_e$ decay thresholds.
*   **Structural Telemetry Binding**: Telemetry state is now cryptographically bound to the hardware-notarized intent.
*   **Deterministic Refusal**: Hardened refusal logic for unstable or unauthorized AI intents.
*   **Sovereign Spine Primitives**: Full alignment with "A Forensic Lexicon for the Agentic Era."

## Security
This project is in Milestone v0.1. All sensitive tool calls MUST be notarized via the `verify_and_gate` function to ensure technical integrity and hardware — rooted trust.
