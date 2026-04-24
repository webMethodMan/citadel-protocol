# The Citadel Protocol: Hardware — Enforced Agentic Strangler

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-green.svg)]()

In an era of autonomous agents, the Citadel Protocol acts as a deterministic gatekeeper — a Silicon Airlock for AI agents to interact with legacy systems only after intent has been cryptographically notarized by a Trusted Execution Environment (TEE).

## The Lexicon of Citadel

To understand the architecture, we employ a specific lexicon derived from Sanskrit:

*   **Sankalpa**: The "Intention" — A 32-byte hash representing the specific tool call or action an agent intends to take.
*   **Sakshi**: The "Witness" — The hardware-enforced layer (Intel TDX) that verifies the truth of an intent before execution.
*   **Mudra**: The "Seal" — A cryptographic notarization (returned by the Sakshi) binding the intent to a hardware report.

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
2.  **Governance**: The system checks the **Sankalpa** (intent hash) against the authorized `policy.json`.
3.  **Hardware Gate (Sakshi)**: If authorized, the `sakshi-core` layer **welds** the intent hash (RIOM), the session certificate hash, and the SPIFFE ID into the Silicon Truth, triggering Intel TDX to generate a hardware report (TDREPORT).
4.  **TEE — as — CA**: The Sakshi issues a **Mudra** — a cryptographic seal that notarizes the bound state of the intent and the ephemeral session identity.
5.  **Proxy / Forward**: In `proxy` mode, Citadel establishes a secure **Provenance-Bound mTLS tunnel** to the destination, forwarding the request with the hardware quote included in the headers.

## Components

### 1. `sakshi-core` (The Hardware Layer)
The pure `no_std` core that performs the "Verify & Gate" operation. It provides the `Sankalpa`, `SankalpaHasher`, and `AirlockPolicyEngine` traits.

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
cargo build --release
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
*   **Sovereign Spine Matrix**: Introduced a 3-dimensional configuration pattern for Logic, Transport, and Lifecycle.
*   **Real mTLS Forwarding**: Ephemeral mTLS certificates are now cryptographically bound to the TDX quote during proxying.
*   **Provenance-Bound Headers**: Proxy requests now include `X-Sakshi-Mudra` and `X-Sakshi-Quote` for end-to-end verification.
*   **A2A Handshake Mesh**: Integrated gRPC-based "Agent-to-Agent" handshake protocol for decentralized trust.
*   **Capability-Based Security**: Transitioned to a granular "Airlock" policy engine for validating intent admissibility.

## Security
This project is in Milestone v0.1. All sensitive tool calls MUST be notarized via the `verify_and_gate` function to ensure technical integrity and hardware — rooted trust.
