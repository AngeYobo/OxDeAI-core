[![npm version](https://img.shields.io/npm/v/@oxdeai/core.svg)](https://www.npmjs.com/package/@oxdeai/core)
[![license](https://img.shields.io/npm/l/@oxdeai/core.svg)](https://github.com/AngeYobo/oxdeai-core/blob/main/packages/core/LICENSE)
[![build](https://github.com/AngeYobo/oxdeai-core/actions/workflows/ci.yml/badge.svg)](https://github.com/AngeYobo/oxdeai-core/actions/workflows/ci.yml)

# @oxdeai/core

**Deterministic Economic Guardrails Engine for Autonomous Systems**

`@oxdeai/core` is a TypeScript policy engine designed to enforce deterministic economic constraints for autonomous agents, AI systems, and programmable services.

It provides composable policy modules for budget control, velocity limits, allowlists, kill switches, and cryptographic verification — enabling secure machine-to-machine economic interactions.

---

## Why oxdeai-core?

As AI agents begin to transact autonomously, we need:

- Deterministic spending controls
- Programmable economic constraints
- Verifiable authorization flows
- Composable policy enforcement
- Cryptographic integrity guarantees

`@oxdeai/core` provides a modular enforcement layer that can sit between:

- Agent runtime
- Payment system (crypto or fiat rails)
- Marketplace execution layer
- Settlement protocol

---

## Installation

```bash
npm install @oxdeai/core
````

---

## Core Concepts

### PolicyEngine

The central deterministic evaluation engine.

```ts
import { PolicyEngine } from "@oxdeai/core";
```

Evaluates actions against registered policy modules before execution.

---

### Policy Modules

Built-in modules include:

* **BudgetModule** — caps total spend
* **VelocityModule** — rate limits actions
* **AllowlistModule** — restricts destinations
* **KillSwitchModule** — emergency stop
* **Cryptographic Verification** — signature validation

Modules are composable and evaluated deterministically.

---

## Example Usage

```ts
import {
  PolicyEngine,
  BudgetModule,
  VelocityModule
} from "@oxdeai/core";

const engine = new PolicyEngine({
  modules: [
    new BudgetModule({ maxBudget: 10_000 }),
    new VelocityModule({ maxPerMinute: 5 })
  ]
});

const result = engine.evaluate({
  actor: "agent-A",
  action: "transfer",
  amount: 250
});

if (!result.allowed) {
  throw new Error(result.reason);
}
```

---

## Design Principles

* Deterministic execution
* Pure evaluation (no hidden side effects)
* Composable policy modules
* Explicit state transitions
* Audit-friendly architecture

---

## Intended Use Cases

* AI agent transaction guardrails
* Autonomous service marketplaces
* Machine-to-machine settlements
* DeAI protocols
* Risk-bounded execution environments
* Programmable compliance layers

---

## Architecture Positioning

```
Agent Runtime
      ↓
PolicyEngine (@oxdeai/core)
      ↓
Payment / Settlement Layer
      ↓
External World
```

`@oxdeai/core` does not move funds.
It enforces economic invariants before execution.

---

## Security Model

* Deterministic rule evaluation
* Explicit authorization objects
* Hash-based audit logs
* Cryptographic signature validation

This package does not handle custody or key management.

---

## Roadmap

* Pluggable module SDK
* Formal invariant validation
* Deterministic replay engine
* WASM-compatible builds
* Policy simulation tooling

---

## License

Apache-2.0




