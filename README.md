# OxDeAI-core

Deterministic Economic Guardrails Engine for Autonomous Systems.

OxDeAI-core provides a formally specified, fail-closed policy engine for controlling
autonomous agents (AI agents, workflows, bots) under strict economic constraints
(budget, caps, velocity, allowlists), with cryptographic authorization and tamper-evident audit logs.

## Core Principles

- Deterministic evaluation
- Fail-closed semantics
- Explicit invariants
- Cryptographic authorization
- Hash-chained audit logs
- Property testing (fuzz + meta-property)

## Repo Layout

- `packages/core` — policy engine + invariants enforcement
- `packages/sdk` — integration SDK
- `packages/cli` — CLI harness / demo
- `tests` — unit + invariants + fuzz/property tests

## Quickstart

Install dependencies:
```bash
pnpm install

