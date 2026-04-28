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

## The Sovereign Spine: Configuration Matrix

The Citadel Gateway (`citadel-mcp-server`) operates on a three-dimensional configuration matrix to support diverse deployment environments from CI/CD to high-performance production meshes.

### 1. Logic Mode (`--logic`)
*   **`notary`**: The "Signature-Only" mode. Returns a **Mudra** (hardware seal) to the caller.
*   **`proxy`**: The "In-Line" mode. Intercepts the request, wraps it in an ephemeral mTLS certificate (bound to the TDX quote), and forwards it to the target destination.

### 2. Transport Mode (`--transport`)
*   **`mcp-stdio`**: JSON-RPC over standard input/output (Standard MCP).
*   **`mcp-sse`**: JSON-RPC over Server-Sent Events (Axum server).
*   **`grpc`**: High-performance binary mesh (A2A protocol).

### 3. Lifecycle Mode (`--lifecycle`)
*   **`ephemeral`**: The process executes exactly one transaction and exits. Optimized for GitHub Actions and serverless notary tasks.
*   **`persistent`**: The process stays alive, maintaining the TEE warm-state and listening for subsequent requests.

## How it Works (The Gateway)

1.  **Intercept**: The **Gateway** receives an MCP JSON — RPC request via the selected **Transport**.
2.  **Governance**: The system checks the **Sankalpa** (intent hash) against the authorized `policy.json` via the `AirlockPolicyEngine`.
3.  **Hardware Observation (Sakshi)**: If authorized, the `sakshi-core` layer **welds** the intent hash (RIOM), the session certificate hash, and the SPIFFE ID into the Silicon Truth, triggering Intel TDX to generate a **Pramana** (Admissible Proof).
4.  **Verification & Notarization**: The **Pramana** is verified against a `PramanaProvider` (e.g., Hedera Consensus Service) to ensure its ledger-backed validity.
5.  **Seal Issuance (Mudra)**: Upon successful verification, the Sakshi issues a **Mudra** — a cryptographic seal that notarizes the bound state of the intent and the ephemeral session identity.
6.  **Proxy / Forward**: In `proxy` mode, Citadel establishes a secure **Provenance-Bound mTLS tunnel** to the destination, forwarding the request with the hardware quote included in the headers.

## Components

### 1. `sakshi-core` (The Hardware Layer)
The pure `no_std` core that performs the "Verify & Gate" operation. It defines the core primitives (`Pramana`, `Mudra`) and provides the `Sankalpa`, `PramanaProvider`, and `AirlockPolicyEngine` traits.

### 2. `sakshi-tdx` (Intel TDX Provider)
The Linux-native driver interface for interacting with `/dev/tdx_guest`.

### 3. `citadel-mcp-server` (The Gateway)
The high-performance transport adapter and "Sovereign Spine" router.

## Getting Started

### Prerequisites
*   Rust 1.75+
*   Intel TDX enabled hardware (or `MockProvider` for development)

### Build
```bash
./release.sh
```

### CLI Usage Examples

**CI Notary (One-off Signature)**:
```bash
echo '{...}' | ./target/debug/citadel-mcp-server --logic notary --transport mcp-stdio --lifecycle ephemeral
```

**Production Proxy (Long-running SSE Gateway)**:
```bash
./target/debug/citadel-mcp-server --logic proxy --transport mcp-sse --lifecycle persistent --port 9000
```

## Milestone v0.1 Changes
*   **Sovereign Spine Primitives**: Full alignment with "A Forensic Lexicon for the Agentic Era," introducing **Pramana** and **PramanaProvider**.
*   **Deterministic Governance**: Shifted from probabilistic compliance to hardware-enforced necessity.
*   **Real mTLS Forwarding**: Ephemeral mTLS certificates are now cryptographically bound to the TDX quote during proxying.
*   **A2A Handshake Mesh**: Integrated gRPC-based "Agent-to-Agent" handshake protocol for decentralized trust.
*   **Capability-Based Security**: Transitioned to a granular "Airlock" policy engine for validating intent admissibility.

## Security
This project is in Milestone v0.1. All sensitive tool calls MUST be notarized via the `verify_and_gate` function to ensure technical integrity and hardware — rooted trust.
