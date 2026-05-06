# @oxdeai/guard
Policy Enforcement Point for the OxDeAI execution-time authorization protocol.
Enforces the non-bypassable execution boundary: verifies AuthorizationV1 locally, fail-closed.
No valid authorization → no execution callback is invoked.

---

## Why this package exists

Every runtime adapter (LangGraph, CrewAI, OpenAI Agents SDK, OpenClaw, custom agents etc.)
needs to enforce the same authorization boundary. Without a shared PEP layer,
each adapter re-implements authorization logic, creating divergence and security
gaps.

`@oxdeai/guard` provides that shared layer:

- **One place** for all PEP logic — adapters stay thin.
- **Fail-closed** — ambiguous state, missing artifacts, or evaluation errors
  block execution.
- **No runtime-specific code** — pure TypeScript, no LangGraph/CrewAI/OpenAI
  imports.

---

## Installation

```sh
pnpm add @oxdeai/guard @oxdeai/core
```

---

## Basic usage

```typescript
import { OxDeAIGuard } from "@oxdeai/guard";

// Build the guard once per agent session.
const guard = OxDeAIGuard({
  engine,      // PolicyEngine from @oxdeai/core
  getState,    // () => State | Promise<State>
  setState,    // (state: State) => void | Promise<void>
});

// Call it before every tool execution.
const result = await guard(
  {
    name: "provision_gpu",
    args: { asset: "a100", region: "us-east-1" },
    estimatedCost: 500,
    resourceType: "gpu",
    context: {
      agent_id: "agent-xyz",
      target: "gpu-pool-us-east-1",
    },
  },
  async () => provisionGpu("a100", "us-east-1")
);
```

The `execute` callback is **only invoked when the policy engine returns ALLOW
and the authorization artifact passes cryptographic verification**. On DENY,
`OxDeAIDenyError` is thrown and execution never reaches the callback.

---

## Custom action-to-intent mapping

The default normalizer converts a `ProposedAction` to an OxDeAI `Intent` using
heuristics (cost → amount, resourceType → action_type, etc.). For production
deployments you should supply a custom mapper that expresses your domain model
precisely:

```typescript
import { OxDeAIGuard } from "@oxdeai/guard";
import { buildIntent } from "@oxdeai/sdk";

const guard = OxDeAIGuard({
  engine,
  getState,
  setState,
  mapActionToIntent(action) {
    return buildIntent({
      agent_id: action.context?.agent_id as string,
      action_type: "PROVISION",
      asset: action.args.asset as string,
      target: action.args.region as string,
      amount: BigInt(Math.round((action.estimatedCost ?? 0) * 1_000_000)),
      nonce: BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)),
      intent_id: crypto.randomUUID(),
      timestamp: action.timestampSeconds ?? Math.floor(Date.now() / 1000),
    });
  },
});
```

---

## Lifecycle hooks

```typescript
OxDeAIGuard({
  engine,
  getState,
  setState,

  // Called after authorization but before execution.
  async beforeExecute(action, authorization) {
    logger.info("executing", { action: action.name, auth_id: authorization.auth_id });
  },

  // Called after every decision (ALLOW and DENY). Errors here are swallowed.
  async onDecision({ action, decision, authorization, reasons }) {
    auditLog.write({ action: action.name, decision, reasons });
  },
});
```

---

## Security invariants

| Condition | Outcome |
|---|---|
| Engine returns DENY | `OxDeAIDenyError` thrown — execute not called |
| ALLOW without authorization artifact | `OxDeAIAuthorizationError` thrown |
| ALLOW without nextState | `OxDeAIAuthorizationError` thrown |
| `verifyAuthorization` fails | `OxDeAIAuthorizationError` thrown |
| Normalization fails | `OxDeAINormalizationError` thrown |
| `evaluatePure` throws | `OxDeAIAuthorizationError` thrown (fail-closed) |
| Delegation chain verification fails | `OxDeAIDelegationError` thrown — execute not called |
| Delegation scope widens or expiry exceeds parent | `OxDeAIDelegationError` thrown |
| In-scope delegation action | `execute` called; `setState` not called on delegation path |

**There is no code path that executes without a valid, verified authorization.**

---

## Replay store — production requirements

The guard prevents replay via a pluggable `ReplayStore`. Every `auth_id` and
`delegation_id` is atomically check-and-consumed before execution.

### Default: in-memory (development only)

```typescript
import { OxDeAIGuard } from "@oxdeai/guard";
// No replayStore config → createInMemoryReplayStore() used automatically.
```

**NOT suitable for production.** Replay state is:
- lost on process restart
- not shared across instances (horizontal scaling allows cross-instance replay)

### Production: Redis backend

```typescript
import { OxDeAIGuard, createRedisReplayStore } from "@oxdeai/guard";
import Redis from "ioredis"; // or node-redis v4

const redis = new Redis({ host: "redis.internal", port: 6379 });

const guard = OxDeAIGuard({
  engine,
  getState,
  setState,
  trustedKeySets: [myKeySet],
  replayStore: createRedisReplayStore({ client: redis }),
});
```

Atomicity is guaranteed by `SET key value NX EX ttl`. Exactly one caller
wins across any number of instances; all others see `null` and receive
`OxDeAIAuthorizationError: replay detected`.

**Key schema:**

| Artifact | Redis key |
|---|---|
| `AuthorizationV1` | `replay:auth:<auth_id>` |
| `DelegationV1` | `replay:delegation:<delegation_id>` |

**TTL:** derived from artifact `expiry` — `max(1, expiry - now)`. Keys
auto-evict after the artifact expires. No manual cleanup required.

**Fail-closed:** if Redis is unavailable (network failure, timeout, restart),
`consumeAuthId` throws. The guard catches this and raises
`OxDeAIAuthorizationError: Replay store unavailable`, blocking execution.
There is no fallback to memory and no best-effort path.

### node-redis v4 adapter

```typescript
import { createClient } from "redis";
import type { RedisClient } from "@oxdeai/guard";

const nodeRedis = createClient({ url: "redis://redis.internal:6379" });
await nodeRedis.connect();

// Adapt the node-redis v4 API to the RedisClient interface.
const client: RedisClient = {
  set: (key, value, _nx, _ex, ttl) =>
    nodeRedis.set(key, value, { NX: true, EX: ttl }),
};

const guard = OxDeAIGuard({
  // ...
  replayStore: createRedisReplayStore({ client }),
});
```

### Custom backends

Implement `ReplayStore` directly for DynamoDB, Postgres, or any store that
provides compare-and-set semantics:

```typescript
import type { ReplayStore } from "@oxdeai/guard";

const myStore: ReplayStore = {
  async consumeAuthId(authId, { expiry }) {
    // Must be atomic. Return true = first use, false = replay, throw = fail-closed.
    return await db.setIfAbsent(`auth:${authId}`, expiry);
  },
};
```

---

## Error classes

| Class | When thrown |
|---|---|
| `OxDeAIDenyError` | Policy DENY — inspect `.reasons` for violation codes |
| `OxDeAIAuthorizationError` | Missing/invalid authorization artifact |
| `OxDeAIGuardConfigurationError` | Misconfigured guard (programming error) |
| `OxDeAINormalizationError` | ProposedAction cannot be converted to an Intent |
| `OxDeAIDelegationError` | Delegation chain invalid, expired, out-of-scope, or parent hash mismatch |

---

## Delegation execution path

When a sub-agent presents a `DelegationV1` chain, pass it in `opts.delegation`:

```typescript
const result = await guard(action, execute, {
  delegation: { delegation: delegationChain, parentAuth },
});
```

The guard verifies the full delegation chain before policy evaluation:

- Parent `auth_id` hash matches `delegationParentHash`
- Scope does not widen relative to parent (budget, tools, expiry)
- Signatures are valid at every link

On any violation, `OxDeAIDelegationError` is thrown and `execute` is never
called. `setState` is also not called on the delegation path — the scope is
committed by the parent authorization.

Property-based coverage: G-D1 (allow path), G-D2 (all invalid classes fail
closed), G-D3 (wrong parent hash mismatch).

---

## Default normalizer — field mapping

| `ProposedAction` field | Maps to `Intent` field | Default when absent |
|---|---|---|
| `context.agent_id` (**required**) | `agent_id` | throws |
| `name` | `action_type` (heuristic) | `"PROVISION"` |
| `resourceType` | `action_type` (overrides name) | — |
| `estimatedCost` | `amount` (× 1 000 000, bigint) | `0n` |
| `timestampSeconds` | `timestamp` | `Date.now() / 1000` |
| `context.target` | `target` | `action.name` |
| `context.intent_id` | `intent_id` | random hex |
| `context.nonce` | `nonce` | random bigint |
| `args` (sorted JSON) | `metadata_hash` (sha256 hex) | — |

---

## Architecture boundary

`@oxdeai/guard` is **the only place** where universal PEP logic should live.

- Do **not** add LangGraph / CrewAI / OpenAI / runtime-specific imports here.
- Runtime adapter packages must remain **thin bindings** that call `OxDeAIGuard`.
- Do **not** duplicate authorization checks inside adapters.

---

## See also

- [Adapter stack architecture](https://github.com/oxdeai/oxdeai/blob/main/docs/integrations/adapter-stack.md)
- [Adapter reference architecture](https://github.com/oxdeai/oxdeai/blob/main/docs/adapters/adapter-reference-architecture.md)
- [Adapter release notes](https://github.com/oxdeai/oxdeai/blob/main/docs/adapters/adapter-stack-release-notes.md)
- [Root README](https://github.com/oxdeai/oxdeai/blob/main/README.md)
