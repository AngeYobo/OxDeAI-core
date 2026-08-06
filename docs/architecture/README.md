# Architecture

This directory contains architecture guides and decision documents for OxDeAI.

---

## Positioning

- [Why OxDeAI](why-oxdeai.md) — execution authorization boundary vs. guardrails, monitoring, sandboxing
- [Decision is Not Execution](decision-is-not-execution.md) — separation of authorization from execution
- [ETA Positioning Note](eta-positioning-note.md) — Execution-Time Authorization scope
- [System-M Execution Boundary](system-m-execution-boundary.md) — multi-agent execution boundary model
- [Invariants](invariants.md) — core protocol invariants

---

## Deployment

- [Overview](overview.md) — architectural overview
- [PEP Production Guide](pep-production-guide.md) — Policy Enforcement Point deployment

---

## Security and Interoperability

- [Tier 1 Evaluator-Input Provenance Boundary](decisions/tier1-evaluator-input-provenance.md) — accepted secure guard/PEP provenance architecture
- [Threat Model: External Authorization Providers](threat-model-external-providers.md) — trust boundaries, T-1 through T-12 threat scenarios
- [Key Custody and Rotation](key-custody-and-rotation.md) — key lifecycle, KC-1 through KC-8 compromise scenarios, operational checklist
- [Replay-Store TTL Alignment](replay-store-ttl-alignment.md) — formal TTL rules, RT-1 through RT-10 failure scenarios, store implementation guidance
