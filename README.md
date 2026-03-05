# OxDeAI-core

Deterministic Economic Guardrails Engine for Autonomous Systems.

OxDeAI-core hosts the OxDeAI protocol docs and the TypeScript reference implementation.

OxDeAI-core provides a formally specified, fail-closed policy engine for controlling
autonomous agents (AI agents, workflows, bots) under strict economic constraints
(budget, caps, velocity, allowlists), with cryptographic authorization and tamper-evident audit logs.

## Core Principles

- Deterministic evaluation
- Fail-closed semantics
- Explicit invariants
- Cryptographic authorization
- Hash-chained audit logs
- Stateless verifiability (snapshot/audit/envelope)
- Property testing (fuzz + meta-property)

## Repo Layout

- `packages/core` - policy engine + invariants enforcement
- `packages/conformance` - frozen vectors + conformance validator
- `protocol` - normative protocol specification
- `packages/sdk` - integration SDK
- `packages/cli` - CLI harness / demo
- `packages/core/tests` - unit + invariants + fuzz/property tests
- `examples` - reference integrations (`gpu-guard`, `langgraph`, `openai-tools`)
- `docs` - architecture, invariants, and verification notes

## Quickstart

Install dependencies:
```bash
pnpm install
