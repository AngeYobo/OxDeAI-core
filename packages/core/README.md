# @oxdeai/core

Deterministic Economic Containment Engine for Autonomous Systems

[![npm version](https://img.shields.io/npm/v/@oxdeai/core.svg)](https://www.npmjs.com/package/@oxdeai/core)
[![Snyk](https://snyk.io/test/github/AngeYobo/oxdeai-core/badge.svg)](https://snyk.io/test/github/AngeYobo/oxdeai-core)
[![license](https://img.shields.io/npm/l/@oxdeai/core.svg)](https://github.com/AngeYobo/oxdeai-core/blob/main/packages/core/LICENSE)
[![build](https://github.com/AngeYobo/oxdeai-core/actions/workflows/ci.yml/badge.svg)](https://github.com/AngeYobo/oxdeai-core/actions/workflows/ci.yml)


## Status

`@oxdeai/core` is a stable protocol library.

Version 1.0.0 freezes the stateless verification surface introduced in v0.9:

- verifySnapshot
- verifyAuditEvents
- verifyEnvelope
- VerificationResult schema
- Verification Envelope format

Future releases will maintain backward compatibility for these artifacts.

---


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

## Overview

`@oxdeai/core` is a deterministic economic containment engine for autonomous systems.

It enforces economic invariants before an action executes and emits deterministic artifacts that can be verified independently.

The library exposes:

* deterministic policy evaluation
* canonical state snapshots
* hash-chained audit events
* stateless verification primitives

---

## Key Concepts

### PolicyEngine

Deterministic evaluation of action intents against a policy state.

### Canonical Snapshot

Deterministic binary representation of the policy state.

### Audit Chain

Hash-chained sequence of execution events.

### Verification Envelope

Portable artifact combining:

* snapshot
* audit events
* policy identity

---

## Stateless Verification

Stateless verification API:

* `verifySnapshot(snapshotBytes)`
* `verifyAuditEvents(events)`
* `verifyEnvelope(envelopeBytes)`

All three return `VerificationResult` with status:

* `ok`
* `invalid`
* `inconclusive`

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

Deterministic invariants enforced and tested:

* I1 Canonical hashing ignores key insertion order
* I2 Snapshot round-trip is idempotent
* I3 Decision equivalence across import/export
* I4 Replay verification determinism
* I5 Cross-process determinism

* `policyId` - content-addressed engine configuration
* `stateHash` - canonical snapshot hash
* `auditHeadHash` - tamper-evident execution trace hash
* `formatVersion: 1` for canonical snapshots
* canonical JSON snapshot payloads (`modules: Record<string, unknown>`)
* portability across runtimes (no v8 blobs in snapshots)
* decode validation rejects malformed snapshots

If the engine version, module set, state, and event sequence are the same, these hashes are identical across runs.

Intent identity is canonical and signature-stripped.

Strict mode removes implicit entropy sources.

---

## Show me the invariant

```ts
const out = engine.evaluatePure(intent, state);
const policyId = engine.computePolicyId();
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

## Minimal Example

```ts
import { PolicyEngine, verifyEnvelope } from "@oxdeai/core";
const decision = engine.evaluate(intent, state);
const result = verifyEnvelope(envelopeBytes);
if (result.ok) console.log("artifact verified");
```

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

## Example: Pure Evaluation

```ts
import { PolicyEngine } from "@oxdeai/core";
import type { State, Intent } from "@oxdeai/core";

const engine = new PolicyEngine({
  policy_version: "v0.9",
  engine_secret: process.env.oxdeai_ENGINE_SECRET!,
  authorization_ttl_seconds: 60,
  strictDeterminism: false
});

const now = 1730000000; // injected timestamp (seconds)

const state: State = {
  policy_version: "v0.9",
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
* Property-based determinism tests (seeded, no deps)

---

## Snapshot API (v0.6)

```ts
import {
  PolicyEngine,
  encodeCanonicalState,
  decodeCanonicalState
} from "@oxdeai/core";

// 1. Export canonical snapshot
const snapshot = engine.exportState(state);
// 2. Encode to portable bytes (canonical JSON)
const bytes = encodeCanonicalState(snapshot);
// 3. Decode in another process/runtime
const decoded = decodeCanonicalState(bytes);
// 4. Import into fresh state container
const freshState = structuredClone(state);
engine.importState(freshState, decoded);
engine.computeStateHash(freshState); // identical to original
```

`importState` enforces `formatVersion: 1` and rejects policy mismatches (`policyId` must match `engine.computePolicyId()`).

Snapshots are:

- Canonical JSON (no v8 serialization)
- Versioned (`formatVersion: 1`)
- Policy-bound (policyId must match)
- Deterministically hashed

---

## Adapters (v0.8)

```ts
import { PolicyEngine, FileStateStore, FileAuditSink } from "@oxdeai/core";

const stateStore = new FileStateStore("./policy-state.bin");
const auditSink = new FileAuditSink("./audit.ndjson");

const engine = new PolicyEngine({
  policy_version: "v0.9",
  engine_secret: "secret",
  authorization_ttl_seconds: 60,
  stateStore,
  auditSink
});

const out = engine.evaluate(intent, state);
engine.commitState(state);
await engine.flushAudit();
await engine.flushState();
```

Core ships only minimal in-memory and file adapters; no redis/postgres adapters in core. Build those in separate packages.

---

## Replay Verification (v0.7)

`ReplayEngine.verify` recomputes `auditHeadHash` offline from the provided events, and validates policy binding (`policyId`) plus non-decreasing timestamps.

Strict mode returns `inconclusive` unless the trace contains at least one `STATE_CHECKPOINT` (`stateHash` anchor).

```ts
import { PolicyEngine, ReplayEngine } from "@oxdeai/core";
const engine = new PolicyEngine({ policy_version: "v0.9", engine_secret: "secret", authorization_ttl_seconds: 60, checkpoint_every_n_events: 2 });
engine.evaluatePure(intent1, state);
const out = engine.evaluatePure(intent2, state);
const events = engine.audit.snapshot();
const verified = ReplayEngine.verify(events, { policyId: engine.computePolicyId() }); // strict by default
console.log(verified.ok, verified.status); // true, "ok" when checkpoints exist
```

---

## Roadmap

### v0.6 - Stateful Canonical Snapshots (shipped)

* State-bound module codecs (canonical JSON)
* Snapshot round-trip invariants (smoke + property tests)
* Versioned canonical snapshot format (formatVersion=1)
* Strict determinism completeness (no implicit entropy)

### v0.7 - Replay as Verification (shipped)

* Replay verification API
* Optional deterministic state checkpoints (`STATE_CHECKPOINT`)
* Misuse hardening (`strict` => `inconclusive` without state anchors)

### v0.8 - Host Integration Adapters (shipped)

* StateStore interface
* AuditSink interface
* Minimal in-memory + file adapters

### v0.9 - Stateless Verification Surface (shipped)

Stateless verification layer for protocol artifacts.

* Pure verifiers: `verifySnapshot`, `verifyAuditEvents`, `verifyEnvelope`
* Portable Verification Envelope (snapshot + audit events)
* Unified `VerificationResult` (`ok` / `invalid` / `inconclusive`)
* Deterministic violation ordering

### v1.0 - Protocol Stability Release (shipped)
* API freeze for verification surface + envelope codec
* Spec lock (formats, invariants, violation codes)
* Backwards-compat policy and conformance tests

---

## License

Apache-2.0
