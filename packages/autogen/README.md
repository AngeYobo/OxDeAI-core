# @oxdeai/autogen
AutoGen adapter to the OxDeAI execution-time authorization protocol.
Sends AutoGen tool calls through @oxdeai/guard; enforcement is local, fail-closed, non-bypassable.

---

## What this package does

AutoGen function calls (`{ name, args, id }`) carry no agent identity and use
a different shape from OxDeAI's `ProposedAction`. This adapter:

1. Injects `agentId` from config into every call (function calls carry no agent identity)
2. Maps `toolCall.id` → `context.intent_id` (when present)
3. Passes the resulting `ProposedAction` to `OxDeAIGuard`

Everything else - policy evaluation, authorization verification, state
persistence, fail-closed behavior - happens inside `@oxdeai/guard`.

---

## Installation

```sh
pnpm add @oxdeai/autogen @oxdeai/core
```

---

## Usage

```ts
import { createAutoGenGuard } from "@oxdeai/autogen";

const guard = createAutoGenGuard({
  engine,      // PolicyEngine from @oxdeai/core
  getState,    // () => { state, version } | Promise<{ state, version }>
  setState,    // (state, expectedVersion) => boolean | Promise<boolean>  (CAS)
  agentId: "gpu-agent-1",
});

// In your AutoGen function executor:
await guard(
  { name: "provision_gpu", args: { asset: "a100", region: "us-east-1" }, id: "call-123" },
  () => provisionGpu("a100", "us-east-1")
);
```

The `execute` callback is only invoked when the policy engine returns ALLOW
**and** the authorization artifact passes verification. On DENY, `OxDeAIDenyError`
is thrown and the callback is never called.

---

## With a custom intent mapper

Use `mapActionToIntent` when you need full control over how a function call
maps to an OxDeAI `Intent` (e.g. to set a precise `amount`, `asset`, or `target`):

```ts
const guard = createAutoGenGuard({
  engine,
  getState,
  setState,
  agentId: "gpu-agent-1",
  mapActionToIntent(action) {
    // action.name, action.args, action.context.agent_id and intent_id are available
    return buildProvisionIntent(action.args.asset as string, action.args.region as string);
  },
});
```

---

## Error handling

```ts
import {
  OxDeAIDenyError,
  OxDeAIAuthorizationError,
  OxDeAINormalizationError,
} from "@oxdeai/autogen";

try {
  await guard(toolCall, execute);
} catch (err) {
  if (err instanceof OxDeAIDenyError) {
    // Policy denied - err.reasons contains the violation codes
    console.error("denied:", err.reasons);
  } else if (err instanceof OxDeAIAuthorizationError) {
    // Authorization artifact missing or invalid - hard security failure
    throw err;
  }
}
```

---

## Deterministic boundary semantics

This adapter preserves the same deterministic, offline-verifiable boundary
semantics as every other OxDeAI protocol demo:

- **No Authorization = no execution**, even on ALLOW
- **DENY** blocks the execute callback before it is called
- **State transitions** happen only after successful execution
- **Envelope verification** remains offline and deterministic

All of this is guaranteed by `@oxdeai/guard` - this package adds nothing on top.

---

## Trust profile

**Declared.**

This adapter integrates the lower-level `OxDeAIGuard` boundary. `agent_id` is
fixed by deployment configuration (`config.agentId`) and is not proposer-controlled;
the same value is bound as `expectedAudience`, so an authorization issued for a
different audience fails closed.

Tool identity and recursion depth are **not** established from a
`TrustedExecutionContext` on this path. The default adapter normalization does not
populate `intent.tool` or `intent.depth`, so `ToolAmplificationModule` and
`RecursionDepthModule` do not constrain execution here. The adapter deliberately
does not derive `intent.tool` from the proposer-supplied tool-call name: doing so
would activate the module against a value the caller controls, which is weaker than
leaving it unset.

Deployments that require authenticated Tier 1 evaluator-input provenance should
establish trusted execution context at an authenticating PEP — where a principal is
actually authenticated and the route is resolved — and integrate `createSecureGuard`
from `@oxdeai/guard` there. A framework adapter has no authenticated principal of its
own, so it cannot construct that context honestly.

Replay protection defaults to a per-guard in-memory store. Multi-process or
restart-durable deployments must pass an explicit `replayStore`; see
`createRedisReplayStore` in `@oxdeai/guard`.

Wire `onBoundaryEvent` alongside `onDecision` to observe guard-boundary rejections
(replay, CAS conflict, hash-binding failure). The two streams are disjoint: a
boundary rejection produces no decision record.

---

## Architecture boundary

This package is a **thin binding only**. Do not add:

- Authorization logic
- Policy evaluation logic
- `verifyAuthorization` calls
- Runtime security semantics beyond the ToolCall → ProposedAction mapping

All of that lives in `@oxdeai/guard`.

---

## See also

- [AutoGen integration guide](../../docs/integrations/autogen.md)
- [Adapter stack architecture](../../docs/integrations/adapter-stack.md)
- [Adapter reference architecture](../../docs/adapters/adapter-reference-architecture.md)
- [Root README](../../README.md)
