# Gemini Project Context: The Citadel Protocol

This document serves as the high-level context for the Gemini CLI agent when refactoring or extending the Citadel Protocol codebase.

## 1. Project Mission
The Citadel Protocol is a **Hardware — Enforced Agentic Strangler**. It provides a "Silicon Airlock" for AI agents (MCP clients) to interact with legacy systems (webMethods, SQL, etc.) only after intent has been cryptographically notarized by a Trusted Execution Environment (TEE).

## 2. Core Architecture
The project is divided into two primary Rust crates:

### A. `sakshi-core / sakshi-tdx` (The Hardware Layer)
* **Purpose:** Interface with Intel TDX (`/dev/tdx_guest`) and manage Silicon Truth.
* **Key Trait: Sankalpa:** A pluggable interface for "Intents." It collapses tool names and metadata into a 32-byte hash.
* **Intent Payload: SankalpaPayload:** Represents the attested intent bound before execution.
* **Key Trait: SiliconProvider:** An abstraction for hardware vendors (TDX, SEV-SNP, or Mock).
* **Verification (Sakshi):** Uses `verify_and_gate` to weld a RIOM hash and an mTLS certificate hash into a signed 1024-byte `TDREPORT`. It returns a **Mudra** (cryptographic seal).

### B. `citadel-mcp-server` (The Gateway / Application Gate)
* **Purpose:** Intercepts Model Context Protocol (MCP) JSON-RPC calls.
* **Governance:** Uses an `AttestationPlugin` (Deterministic Floor) to check hashes against a registry (e.g., Hedera Consensus Service) before triggering hardware.
* **Transport:** Operating as the **Gateway**, it connects the **Network Mesh** to legacy infrastructure.
* **Trust Anchor:** Performs self — attestation on startup to verify its own MRTD (Static Identity).

## 3. Technical Constraints & Standards
* **Integrator's Tone:** Follow the voice found at https://www.webmethodman.com/p/born-to-be-an-integrator (Professional, precise, technical).
* **Formatting:** * Separate all em dashes with a space before and after ( — ).
    * Do not use `"` or `>` in professional bios or resumes.
    * Minimize colons in titles and subtitles.
* **Security:** Never bypass the `verify_and_gate` function for any sensitive tool call.

## 4. Current Milestone: v0.1
* Transitioning from hard — coded hashes to a configuration provider.
* Moving from STDIO to a networked SSE transport via the Gateway.
* Binding session mTLS certificates to the hardware report to support cloud — agnostic migration.

---
**Note:** Always run `cargo build` after refactors to ensure trait visibility and standard Rust safety rules are maintained.
---
