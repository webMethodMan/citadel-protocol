# Citadel Protocol

The Citadel Protocol is a **Hardware — Enforced Agentic Strangler**. It provides a "Silicon Airlock" for AI agents (MCP clients) to interact with legacy systems — such as webMethods, SQL, and enterprise APIs — only after their intent has been cryptographically notarized by a Trusted Execution Environment (TEE).

## Overview

In an era of autonomous agents, the Citadel Protocol acts as a deterministic gatekeeper. By leveraging Intel TDX and the Model Context Protocol (MCP), it ensures that every tool call made by an AI is verified against a hardware — rooted identity and a governed policy ledger before execution.

## How it Works

1.  **Intercept**: The Proxy receives an MCP JSON — RPC request via an Axum — based HTTP gateway.
2.  **Validate Intent**: The `AttestationPlugin` (e.g., Hedera) checks the request's RIOM hash against a list of authorized tool intents loaded from `citadel.toml`.
3.  **Hardware Gate**: If authorized, the `witness-core` layer triggers the Silicon Provider to generate a hardware report (TDREPORT).
4.  **TEE — as — CA**: The witness-core issues an **Ephemeral Identity** — a short — lived (60 — second) X.509 certificate and private key bound to the specific intent hash. This process occurs within the secure enclave.
5.  **Authorize**: The client receives the notarized identity in the JSON — RPC `result`, which it can then use to authenticate against protected legacy resources.

## Modules — and — Plugins

### 1. `witness-core` (The Hardware Layer)
A high — assurance, **"Clean Room" `no_std`** crate responsible for managing Silicon Truth.
*   **Sovereign Architecture**: Compiled with `#![no_std]` to minimize attack surface.
*   **Morpheme (A2A)**: The "Agent — to — Agent" morpheme collapses tool IDs and metadata into a 32 — byte "Silicon Weld."
*   **SiliconProvider**: Abstract HAL for hardware vendors.

### 2. `witness-tdx` (Intel TDX Provider)
A specialized provider crate for Intel TDX.
*   **Isolation**: Encapsulates Linux — specific `ioctl` logic and hardware report generation for Intel TDX environments.

### 3. `proxy` (The Application Gate)
The network — facing gateway that governs the "Silicon Airlock."
*   **Axum Gateway**: Listens on `127.0.0.1:9000` for MCP tool calls.
*   **HederaPlugin**: Performs the "Deterministic Floor" check by validating hashes against configured `authorized_tools`.
*   **SecurityFactory**: Manages the injection of hardware and policy providers based on the project configuration.

## Installation — and — Configuration

### Prerequisites
*   Rust (Edition 2024)
*   Python 3 (for integration testing)
*   Intel TDX — enabled environment (or Mock provider for local development)

### Configuration
The system is configured via `citadel.toml`. Ensure your `golden_mrtd` matches your hardware's static identity.

```toml
# citadel.toml
golden_mrtd = "0d0108000000000000000000"
authorized_tools = [
    "1d0fc3d825b822dbce293c6f8bdfacaddba89b0efa782c097bd16b58b3d343b4" # webMethods_Flow_Alpha
]
```

### Building the Project
```bash
# Standard workspace build
cargo build --workspace

# Verify Sovereign (no_std) witness-core state
cargo build -p witness-core --no-default-features
```

### Sovereign Build — and — Release
The `release.sh` script automates the high — assurance build process, extracts the binary's MRTD (Measurement), and creates a hardware — attested Git tag.

```bash
./release.sh
```

### Running the Integration Harness
The integration harness simulates an MCP client attempting to authorize a legacy tool call and verifies the TEE — issued certificate.

```bash
# Ensure the proxy is running in one terminal
# cargo run -p proxy

# Run the test harness
python3 tests/integration_harness.py
```

---
**Note**: This project is currently in Milestone v1.1. All sensitive tool calls MUST be notarized via the `verify_and_gate` function to ensure technical integrity and hardware — rooted trust.
