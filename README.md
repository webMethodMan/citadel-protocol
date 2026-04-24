# The Citadel Protocol: Hardware — Enforced Agentic Strangler
#
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Version: 1.1](https://img.shields.io/badge/Version-1.1-green.svg)]()

In an era of autonomous agents, the Citadel Protocol acts as a deterministic gatekeeper — a Silicon Airlock for AI agents to interact with legacy systems only after intent has been cryptographically notarized by a Trusted Execution Environment (TEE).

## The Lexicon of Citadel

To understand the architecture, we employ a specific lexicon derived from Sanskrit:

*   **Sankalpa**: The "Intention" — A 32-byte hash representing the specific tool call or action an agent intends to take.
*   **Sakshi**: The "Witness" — The hardware-enforced layer (Intel TDX) that verifies the truth of an intent before execution.
*   **Mudra**: The "Seal" — A cryptographic notarization (returned by the Sakshi) binding the intent to a hardware report.

## How it Works (The Gateway)

1.  **Intercept**: The **Gateway** (citadel-mcp-server) receives an MCP JSON — RPC request via a networked gateway (SSE / HTTP).
2.  **Governance**: An `AttestationPlugin` (Deterministic Floor) checks the **Sankalpa** (intent hash) against a registry (e.g., Hedera Consensus Service).
3.  **Hardware Gate (Sakshi)**: If authorized, the `sakshi-core` layer **welds** the intent hash (RIOM) and the session certificate hash into the Silicon Truth, triggering the Silicon Provider to generate a hardware report (TDREPORT).
4.  **TEE — as — CA**: The Sakshi issues a **Mudra** — a cryptographic seal that notarizes the bound state of the intent and the session identity. 
5.  **Authorize**: The client receives the notarized Mudra, which it uses to authenticate against protected resources across the **Network Mesh**.

## Components

### 1. `sakshi-core` (The Hardware Layer)
The pure `no_std` core that performs the "Verify & Gate" operation. It is designed to be side-loaded into any TEE and provides the `Sankalpa`, `SankalpaHasher`, and `SankalpaVerifier` traits for pluggable, PQC — ready intent logic.

### 2. `sakshi-tdx` (Intel TDX Provider)
The Linux-native driver interface for interacting with `/dev/tdx_guest`, implementing the `SiliconProvider` trait for Intel TDX hardware.

### 3. `citadel-mcp-server` (The Gateway)
The high-performance transport adapter that handles the network boundary, policy enforcement, and the network mesh protocol.

## Getting Started

### Prerequisites
*   Rust 1.75+
*   Intel TDX enabled hardware (or `MockProvider` for development)

### Configuration
The system is configured via `citadel.toml` and `policy.json`. Ensure your `golden_mrtd` matches your hardware's static identity.

```toml
# citadel.toml
golden_mrtd = "8c1c74cabfa8bc2eaac6051c4663ded027909400d29ef648f63e2795742813c3"
```

### Build & Run

```bash
# Execute the optimized release pipeline (Gateway + WASM Core)
./release.sh

# Run the Gateway
./target/release/citadel-mcp-server
```

## Milestone v1.1 Changes
*   **PQC — Ready Abstractions**: Transitioned from hard — coded cryptographic algorithms to a trait — based architecture (`SankalpaHasher`, `SankalpaVerifier`).
*   **Generous Payload Limits**: Increased maximum frame and body sizes to 10MB to accommodate large post — quantum signatures and complex intent payloads.
*   **Networked Transport**: Transitioned from STDIO to a networked HTTP / SSE transport via the Gateway.
*   **Dynamic Policy**: Moving from hard — coded hashes to a configurable `policy.json` provider.
*   **Identity Binding**: Binding session mTLS certificates to the hardware report to support cloud — agnostic migration.

## Security
This project is in Milestone v1.1. All sensitive tool calls MUST be notarized via the `verify_and_gate` function (configured with a project — specific `SankalpaVerifier`) to ensure technical integrity and hardware — rooted trust.
