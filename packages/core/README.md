# @oxdeai/core

**Deterministic Economic Containment Engine for Autonomous Systems**

[![npm version](https://img.shields.io/npm/v/@oxdeai/core.svg)](https://www.npmjs.com/package/@oxdeai/core)
[![license](https://img.shields.io/npm/l/@oxdeai/core.svg)](https://github.com/AngeYobo/oxdeai-core/blob/main/packages/core/LICENSE)
[![build](https://github.com/AngeYobo/oxdeai-core/actions/workflows/ci.yml/badge.svg)](https://github.com/AngeYobo/oxdeai-core/actions/workflows/ci.yml)


`@oxdeai/core` is a TypeScript policy engine that enforces hard economic invariants *before* an agent executes an action.

It answers a narrow question:

> Given an intent and a policy state, is this action economically allowed - deterministically?

If allowed, it emits a signed, expiring authorization bound to the intent and state snapshot.
If denied, it fails closed.

No dashboards.
No LLM classifiers.
No heuristics.
No post-fact monitoring.

Just deterministic pre-execution containment.

---

## The Problem

Autonomous systems fail economically before they fail semantically.

Common failure modes:

* runaway tool-call loops
* recursive planning explosions
* uncontrolled concurrency
* replayed actions
* silent budget drain
* consumption-based billing surprises

Most “guardrails” operate after execution or rely on probabilistic models.

Economic invariants should not be probabilistic.

---

## What This Library Is

A deterministic policy substrate that:

* evaluates `(intent, state)` → stable decision
* enforces:

  * per-period budgets
  * per-action caps
  * velocity windows
  * recursion depth limits
  * concurrency slots
  * replay protection
* emits signed authorizations (HMAC)
* produces hash-chained audit logs
* supports pure evaluation (`evaluatePure`)
* produces content-addressed `policyId`
* produces canonical `stateHash`
* produces tamper-evident `auditHeadHash`

Same inputs ⇒ same outputs.

---

## What This Library Is Not

* Not a billing tool
* Not a cloud budget monitor
* Not a prompt filter
* Not a dashboard
* Not distributed coordination

It is the deterministic outer boundary.

---

## Deterministic Guarantees

v0.5.0 formalizes three reproducible identifiers:

* `policyId` - content-addressed engine configuration
* `stateHash` - canonical snapshot hash
* `auditHeadHash` - tamper-evident execution trace hash

If the engine version, module set, state, and event sequence are the same, these hashes are identical across runs.

Intent identity is canonical and signature-stripped.

Strict mode removes implicit entropy sources.

---

## Show me the invariant

```ts
const out = engine.evaluatePure(intent, state);
const { policyId } = engine;
const stateHash = engine.computeStateHash(out.nextState);
const auditHead = engine.audit.headHash();

console.log(policyId, stateHash, auditHead);
```

**Invariant:**

Same `(engine version + modules + options + state + intent sequence)`
⇒ identical `policyId`, `stateHash`, and `auditHead`.

No randomness.
No hidden clocks (in strict mode).
No non-deterministic ordering.

---

## Design Philosophy

* Fail closed.
* Make invariants explicit.
* Make state portable.
* Make execution replayable.
* Separate identity from proof.
* Prefer deterministic containment over probabilistic detection.

---

## Installation

```bash
npm install @oxdeai/core
```

---

## Core Model

```
Agent / Runtime
↓
Structured Intent
↓
PolicyEngine (@oxdeai/core)
    → ALLOW + Authorization
    → DENY + Reasons
↓
Execution Layer (APIs / payments / infra provisioning)
```

---

## Concepts

### Intent

A structured economic action.

Examples:

* `EXECUTE` a paid tool call
* `RELEASE` an authorization-bound concurrency slot

---

### State

Deterministic policy state containing:

* per-agent budgets
* per-action caps
* velocity windows
* replay nonce windows
* recursion depth caps
* concurrency caps + active authorizations
* tool amplification limits
* kill switches and allowlists

---

### Authorization

If an intent is allowed, the engine emits a signed authorization:

* bound to `intent_hash`
* bound to `policy_version`
* bound to `state_snapshot_hash`
* includes `expires_at`
* verifiable via `verifyAuthorization()`

---

## Example: Pure Evaluation (Recommended)

```ts
import { PolicyEngine } from "@oxdeai/core";
import type { State, Intent } from "@oxdeai/core";

const engine = new PolicyEngine({
  policy_version: "v0.5",
  engine_secret: process.env.OXDEAI_ENGINE_SECRET!,
  authorization_ttl_seconds: 60,
  strictDeterminism: false
});

const now = 1730000000; // injected timestamp (seconds)

const state: State = {
  policy_version: "v0.5",
  period_id: "2026-02",
  kill_switch: { global: false, agents: {} },
  allowlists: {},
  budget: { budget_limit: { "agent-1": 10_000n }, spent_in_period: { "agent-1": 0n } },
  max_amount_per_action: { "agent-1": 5_000n },
  velocity: { config: { window_seconds: 60, max_actions: 100 }, counters: {} },
  replay: { window_seconds: 3600, max_nonces_per_agent: 256, nonces: {} },
  recursion: { max_depth: { "agent-1": 2 } },
  concurrency: { max_concurrent: { "agent-1": 2 }, active: {}, active_auths: {} }
};

const intent: Intent = {
  agent_id: "agent-1",
  type: "EXECUTE",
  tool_call: true,
  tool: "openai.responses",
  nonce: 42n,
  amount: 100n,
  timestamp: now,
  depth: 0
};

const out = engine.evaluatePure(intent, state, { mode: "fail-fast" });

if (out.decision === "DENY") {
  console.error(out.reasons);
} else {
  // persist out.nextState
  // execute using out.authorization
}
```

---

## Concurrency Lifecycle: RELEASE

`RELEASE` must reference a valid active `authorization_id`.

```ts
const releaseIntent: Intent = {
  agent_id: "agent-1",
  type: "RELEASE",
  authorization_id: out.authorization.authorization_id,
  nonce: 43n,
  amount: 0n,
  timestamp: now
};

const rel = engine.evaluatePure(releaseIntent, out.nextState);
```

---

## Built-In Modules

* KillSwitchModule
* AllowlistModule
* ReplayModule
* RecursionDepthModule
* ConcurrencyModule
* ToolAmplificationModule
* BudgetModule
* VelocityModule

---

## Determinism and Auditability

* Pure evaluation mode available
* Stable canonical JSON encoding
* BigInt normalization
* Sorted key hashing
* Hash-chained audit log
* Strict-mode clock injection

---

## Roadmap

### v0.6 -  Stateful Canonical Snapshots

* State-bound module codecs
* Snapshot round-trip invariants
* Versioned canonical snapshot format
* Strict determinism completeness

### v0.7 -  Replay as Verification

* Replay verification API
* Optional state checkpoints
* Misuse hardening (explicit “inconclusive” mode)

### v0.8 -  Host Integration Adapters

* StateStore interface
* AuditSink interface
* Minimal in-memory + file adapters

---

## License

Apache-2.0

