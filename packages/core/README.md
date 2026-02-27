

# @oxdeai/core

## Deterministic Economic Containment Engine for Autonomous Systems


[![npm version](https://img.shields.io/npm/v/@oxdeai/core.svg)](https://www.npmjs.com/package/@oxdeai/core)
[![license](https://img.shields.io/npm/l/@oxdeai/core.svg)](https://github.com/AngeYobo/oxdeai-core/blob/main/packages/core/LICENSE)
[![build](https://github.com/AngeYobo/oxdeai-core/actions/workflows/ci.yml/badge.svg)](https://github.com/AngeYobo/oxdeai-core/actions/workflows/ci.yml)


`@oxdeai/core` is a TypeScript library that enforces **economic invariants** for autonomous agents and programmable services **before execution**.

It evaluates structured action intents against a deterministic policy state, and emits a signed authorization when allowed.

This is not observability. This is **pre-execution containment**.

---

## Why

Agentic systems amplify cost and risk via:
- tool-call chains and retries
- recursion / planning loops
- parallel executions (concurrency blowups)
- consumption-based billing (tokens, APIs, compute)

Most teams rely on dashboards and alerts (post-fact). `@oxdeai/core` aims to provide **hard, deterministic guardrails** at the execution boundary.

---

## What this library does (and does not)

### Does
- Deterministic evaluation: given `(intent, state, policy_version)` ⇒ stable decision
- Pure evaluation path (`evaluatePure`) returning `nextState`
- Backward-compatible state-committing path (`evaluate`)
- Signed authorizations (HMAC) + verification
- Hash-chained audit log for decisions
- Composable invariant modules (budget / velocity / replay / recursion / concurrency)

### Does NOT
- move funds, custody keys, or manage wallets
- replace cloud budgets or billing tools
- do content moderation or prompt-injection security
- provide a dashboard (by design)

---

## Core model

`@oxdeai/core` evaluates:

```

Agent / Runtime
↓
Structured Intent (what you want to do)
↓
PolicyEngine (@oxdeai/core)  →  ALLOW + Authorization  OR  DENY + Reasons
↓
Execution Layer (APIs / payments / infra provisioning)

````

---

## Installation

```bash
npm install @oxdeai/core
````

---

## Concepts

### Intent

A structured request representing an economic action.

Examples:

* EXECUTE a paid tool call
* RELEASE an execution slot after completion

### State

A deterministic policy state containing:

* per-agent budget limits and spend
* velocity windows
* replay protection (nonce windows)
* recursion depth caps
* concurrency caps and active authorizations

### Authorization

If an intent is allowed, the engine emits a signed authorization:

* bound to `intent_hash`, `policy_version`, and `state_snapshot_hash`
* includes an expiry (`expires_at`)
* verifiable via `verifyAuthorization()`

---

## Example: Evaluate + Commit (backward-compatible)

`evaluate()` mutates the passed state by committing `nextState`.

```ts
import { PolicyEngine } from "@oxdeai/core";
import type { State, Intent } from "@oxdeai/core";

const engine = new PolicyEngine({
  policy_version: "v0.2",
  engine_secret: process.env.OXDEAI_ENGINE_SECRET!,
  authorization_ttl_seconds: 60,
});

const state: State = {
  policy_version: "v0.2",
  period_id: "2026-02",
  kill_switch: { global: false, agents: {} },
  allowlists: {},
  budget: { budget_limit: { "agent-1": 10_000n }, spent_in_period: { "agent-1": 0n } },
  max_amount_per_action: { "agent-1": 5_000n },
  velocity: { config: { window_seconds: 60, max_actions: 100 }, counters: {} },

  replay: { window_seconds: 3600, max_nonces_per_agent: 256, nonces: {} },
  recursion: { max_depth: { "agent-1": 2 } },
  concurrency: { max_concurrent: { "agent-1": 2 }, active: {}, active_auths: {} },
};

const intent: Intent = {
  agent_id: "agent-1",
  type: "EXECUTE",
  tool_call: true,
  tool: "openai.responses",
  nonce: 42n,
  amount: 100n,
  timestamp: Math.floor(Date.now() / 1000),
  depth: 0,
};

const result = engine.evaluate(intent, state);

if (result.decision === "DENY") {
  console.error("Blocked:", result.reasons);
  process.exit(1);
}

console.log("Allowed, authorization:", result.authorization.authorization_id);
```

---

## Example: Pure evaluation (recommended for infra)

`evaluatePure()` returns `nextState` without mutating the input state.

```ts
const out = engine.evaluatePure(intent, state, { mode: "fail-fast" });

if (out.decision === "DENY") {
  console.error(out.reasons);
} else {
  // persist out.nextState in your store (db/redis/etc)
  // then execute the action using out.authorization
}
```

---

## Concurrency lifecycle: RELEASE (authorization-bound)

To avoid concurrency deadlocks, `RELEASE` must reference a real `authorization_id` that is currently active.

```ts
const releaseIntent: Intent = {
  agent_id: "agent-1",
  type: "RELEASE",
  authorization_id: out.authorization.authorization_id,
  nonce: 43n,
  amount: 0n,
  timestamp: Math.floor(Date.now() / 1000),
};

const rel = engine.evaluatePure(releaseIntent, out.nextState);

if (rel.decision === "DENY") {
  console.error("Release denied:", rel.reasons);
} else {
  // persist rel.nextState
}
```

---

## Built-in modules

* **KillSwitchModule**: global or per-agent shutdown
* **AllowlistModule**: allowlist action types / assets / targets
* **ReplayModule**: nonce window (prevents replay)
* **RecursionDepthModule**: max planning / tool-call depth
* **ConcurrencyModule**: max in-flight executions + authorization-bound release
* **ToolAmplificationModule**: windowed tool/API call caps (prevents tool-call amplification loops)
* **BudgetModule**: per-period spend cap + per-action cap
* **VelocityModule**: action count rate limit per window

---

## Determinism and auditability

* Decisions are deterministic for the same `(intent, state, policy_version)`
* The engine produces signed authorizations (HMAC)
* A hash-chained audit log records intent hashes and decisions

---

## Roadmap

### Near-term (v0.3)

* Tool amplification limits (tool-call cap per window)
* Deterministic replay trace hash (evaluation id)
* Cleaner audit output as data (optional pure mode: return events instead of mutating `engine.audit`)

### Mid-term

* Pluggable state adapter interface (Redis / Postgres reference adapters)
* Simulation tooling (policy stress tests / Monte Carlo)
* WASM-compatible build target

---

## License

Apache-2.0


