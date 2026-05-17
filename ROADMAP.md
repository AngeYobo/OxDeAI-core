# Roadmap

**Last updated:** 2026-05-17

---

## Positioning

OxDeAI is an **execution authorization boundary** for autonomous systems.

Core invariant:

> **No valid authorization → no execution path**

---

## Protocol Maturity

```
implementation → interoperable protocol → executable interoperability
```

OxDeAI now specifies:

* accepted wire encodings for external provider interoperability (Encoding A, Encoding B)
* an interoperability profile (Profile A / B / C) with executable conformance coverage
* formal threat model, key lifecycle, and replay-store TTL alignment documentation

This reflects maturity at the **interoperable protocol** layer - not standard adoption.

---

## Version Snapshot

### Protocol

* `@oxdeai/core`: 1.7.0
* `@oxdeai/sdk`: 1.3.2
* `@oxdeai/conformance`: 1.5.0

### Adapters

* `@oxdeai/guard`: 1.0.2
* `@oxdeai/langgraph`: 1.0.1
* `@oxdeai/openai-agents`: 1.0.1
* `@oxdeai/crewai`: 1.0.1
* `@oxdeai/autogen`: 1.0.1
* `@oxdeai/openclaw`: 1.0.1

### Tooling

* `@oxdeai/cli`: 0.2.4

---

## Current State

### Validation

* build: pass
* tests: pass
* conformance: pass (`161 assertions`)
* adapters: pass (`6/6`)
* vectors: pass (TS / Go / Python)

### Deterministic scenario (all adapters)

```
ALLOW → ALLOW → DENY → verifyEnvelope() => ok
```

### Boundary proof

```
ALLOW
DENY_HASH_MISMATCH
REPLAY
BYPASS → rejected
```

---

## Architecture Doctrine

### Optimized for

* deterministic authorization `(intent, state, policy)`
* fail-closed execution
* pre-execution enforcement
* portable verification (offline-capable)

### Not

* agent framework
* runtime replacement
* guardrail / output filtering
* monitoring-only system

---

# Milestones

---

## v1.1 - Authorization Artifact

**Status:** Done

* `AuthorizationV1`
* pre-execution gating semantics
* PEP verification contract

---

## v1.2 - Cryptographic Verification

**Status:** Done

* Ed25519 signatures
* `alg / kid / signature`
* KeySet model
* signature failure conformance

---

## v1.3 - Integration Surface

**Status:** Done

* SDK guard surface
* multi-framework demos
* deterministic envelope verification

---

## v1.4 - Ecosystem Adoption

**Status:** Done

* unified PEP (`@oxdeai/guard`)
* adapter packages (LangGraph, OpenAI, CrewAI, AutoGen, OpenClaw)
* cross-adapter validation
* reproducible demo scenario

**Invariant enforced across adapters:**

```
proposal → authorization → execution
```

---

## v1.5 - Developer Experience

**Status:** Done

* quickstarts
* visual demos
* architecture docs
* reproducible integrations

**Goal achieved:**

> Run a demo < 5 minutes

---

## v2.0 - Delegated Authorization

**Status:** Done

* `DelegationV1`
* scope narrowing (tools, amount, depth)
* single-hop enforcement
* chain verification (local, no control-plane)
* full conformance vectors
* cross-language verification

---

## v2.5 - ETA Core (Execution-Time Authorization)

**Status:** In Progress

### Goal

Turn OxDeAI into a **deployable infra boundary**, not just a protocol.

---

### Delivered

* canonicalization spec
* authorization spec
* PEP gateway spec
* verification spec
* conformance vectors
* cross-language determinism
* non-bypassable execution demo

#### Interoperability Hardening (completed)

* external provider wire encoding specification
  * Encoding A - Core-native (`"Ed25519"`, `expiry`, domain-prefixed preimage)
  * Encoding B - external provider-compatible (`"ed25519"`, `expires_at`, base64url signature)
* durable replay semantics with formal TTL alignment rules (`computeTtl = max(1, expiry − now)`)
* pluggable `computeStateHash` in `OxDeAIGuard` (fail-closed on exception)
* external provider interoperability profile
  * Profile A - Core-native `AuthorizationV1`
  * Profile B - external provider wire-compatible
  * Profile C - full semantic state verification
* Profile C executable conformance vectors (12 assertions; 161 total)
* external provider threat model (12 threat scenarios, T-1 through T-12)
* key custody and rotation guide (8 compromise scenarios, KC-1 through KC-8)
* replay-store TTL alignment guide (10 failure scenarios, RT-1 through RT-10)

---

### In Progress

* infra-native enforcement patterns
* external-builder quickstarts (<10 min)
* failure playbooks (real-world scenarios)
* adapter stress testing
* structured decision events

---

### Key Objective

> Enforcement must live **outside the agent runtime**

---

### Completion Criteria

* deterministic outputs across environments
* full conformance coverage
* reproducible enforcement demos
* ≥3 real-world failure scenarios documented
* external adoption without reading core source

---

## v2.6 - Infra Integrations

**Status:** Planned

### Scope

* HTTP PEP package
* Express / Fastify middleware
* route-level enforcement

### Example

```
POST /payments/charge
→ verify AuthorizationV1
→ execute or deny
```

### Goal

> Make OxDeAI a **drop-in execution boundary**

---

## v3.x - Verifiable Execution

**Status:** Planned

### Scope

* execution receipts
* `VerificationEnvelopeV1`
* Merkle batching
* proof-of-inclusion
* optional on-chain anchoring

### Constraint

* authorization remains **off-chain-first**

---

# Summary

## Done

* authorization artifacts
* cryptographic verification
* adapters + ecosystem
* delegated authorization
* conformance + proof
* external provider interoperability hardening
  * wire encoding specification (Encoding A, Encoding B)
  * interoperability profiles (A / B / C) with executable conformance (161 assertions)
  * threat model, key lifecycle, replay-store TTL alignment

## In Progress

* ETA core
* infra-native enforcement
* failure playbooks
* adoption path

## Planned

* HTTP integrations
* verifiable execution infrastructure

---

---

# Architecture Documentation

## Specification

* [External Provider Interoperability Profile](docs/spec/interoperability/external-provider-profile.md) - Profile A / B / C, accepted wire encodings, interoperability matrix, fail-closed rules

## Architecture Guides

* [Threat Model: External Authorization Providers](docs/architecture/threat-model-external-providers.md) - trust boundaries, T-1 through T-12 threat scenarios
* [Key Custody and Rotation](docs/architecture/key-custody-and-rotation.md) - key lifecycle, KC-1 through KC-8 compromise scenarios, operational checklist
* [Replay-Store TTL Alignment](docs/architecture/replay-store-ttl-alignment.md) - formal TTL rules, RT-1 through RT-10 failure scenarios, store implementation guidance

---

# Key Insight

> Agents generate actions.
> OxDeAI decides if they can happen.