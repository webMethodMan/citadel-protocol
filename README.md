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
*   **Hedera Consensus Service (HCS)**: The default production repository. It submits `SovereignEvents` to a public HCS Topic.
*   **Terminal Refusal**: The gateway applies a strict **50ms timeout** on evidence submission during the Intent stage. Failure to notarize triggers a Terminal Refusal.

## The Sovereign Spine: Configuration Matrix

The Citadel Gateway (`citadel-mcp-server`) operates on a three-dimensional configuration matrix to support diverse deployment environments.

### 1. Logic Mode (`--logic`)
*   **`notary`**: Returns a **Mudra** (hardware seal) to the caller.
*   **`proxy`**: Intercepts, notarizes, and forwards via a **Provenance-Bound mTLS tunnel**.

### 2. Transport Mode (`--transport`)
*   **`mcp-stdio`**: JSON-RPC over standard input/output.
*   **`mcp-sse`**: JSON-RPC over Server-Sent Events.
*   **`grpc`**: High-performance binary mesh.

### 3. Lifecycle Mode (`--lifecycle`)
*   **`ephemeral`**: One transaction and exit.
*   **`persistent`**: Long-running gateway listening for subsequent requests.

## How it Works (The Gateway)

1.  **Bootstrap**: On startup, Citadel performs a **Hardware-Rooted Self-Attestation**. It extracts its silicon measurement (MRTD) and verifies it against the **Sovereign Anchor** on the Hedera ledger. If the measurements differ or the ledger is unreachable, the system enters **Terminal Refusal** and exits.
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
Credential management is decoupled from policy. Create a `.env` file to configure the Hedera repository:

```bash
# Hedera Network (testnet, mainnet, or local)
HEDERA_NETWORK=testnet
HEDERA_TOPIC_ID=0.0.xxxxxx

# Local Node Configuration (Required if HEDERA_NETWORK=local)
HEDERA_NODE_ADDRESS=127.0.0.1:50211
HEDERA_NODE_ACCOUNT_ID=0.0.3
HEDERA_MIRROR_NODE_ADDRESS=127.0.0.1:5600

# Hedera Operator (Secrets — Stored out-of-band)
HEDERA_OPERATOR_ID=0.0.xxxxxx
HEDERA_OPERATOR_KEY=302e0201...
HEDERA_OPERATOR_PUBLIC_KEY=89abcdef...
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
