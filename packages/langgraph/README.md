# @oxdeai/langgraph
LangGraph adapter for the OxDeAI execution-time authorization protocol (non-bypassable boundary).
Maps LangGraph tool calls to @oxdeai/guard; verification stays local and fail-closed.

---

## What this package does

LangGraph tool calls (`{ name, args, id }`) carry no agent identity and use
a different shape from OxDeAI's `ProposedAction`. This adapter:

1. Injects `agentId` from config into every call (tool calls carry no agent identity)
2. Maps `toolCall.id` → `context.intent_id`
3. Passes the resulting `ProposedAction` to `OxDeAIGuard`

Everything else - policy evaluation, authorization verification, state
persistence, fail-closed behavior - happens inside `@oxdeai/guard`.

---

## Installation

```sh
pnpm add @oxdeai/langgraph @oxdeai/core
```

---

## Usage

```ts
import { createLangGraphGuard } from "@oxdeai/langgraph";

const guard = createLangGraphGuard({
  engine,      // PolicyEngine from @oxdeai/core
  getState,    // () => State | Promise<State>
  setState,    // (state: State) => void | Promise<void>
  agentId: "gpu-agent-1",
});

// In your LangGraph tool node:
const result = await guard(
  { name: "provision_gpu", args: { asset: "a100", region: "us-east-1" }, id: "call-xyz" },
  () => provisionGpu("a100", "us-east-1")
);
```

The `execute` callback is only invoked when the policy engine returns ALLOW
**and** the authorization artifact passes verification. On DENY, `OxDeAIDenyError`
is thrown and the callback is never called.

---

## With estimated cost

Attach `estimatedCost` and `resourceType` directly on the tool call to give
the default normalizer richer context:

```ts
await guard(
  {
    name: "provision_gpu",
    args: { asset: "a100", region: "us-east-1" },
    id: "call-xyz",
    estimatedCost: 500,
    resourceType: "gpu",
  },
  () => provisionGpu("a100", "us-east-1")
);
```

---

## With a custom intent mapper

Use `mapActionToIntent` when you need full control over how a tool call maps
to an OxDeAI `Intent` (e.g. to set a precise `amount`, `asset`, or `target`):

```ts
import { createLangGraphGuard } from "@oxdeai/langgraph";

const guard = createLangGraphGuard({
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
} from "@oxdeai/langgraph";

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

## Architecture boundary

This package is a **thin binding only**. Do not add:

- Authorization logic
- Policy evaluation logic
- `verifyAuthorization` calls
- Runtime security semantics beyond the ToolCall → ProposedAction mapping

All of that lives in `@oxdeai/guard`.

---

## Cross-adapter validation

This adapter is cross-validated by `@oxdeai/compat` against the OpenAI Agents
SDK and CrewAI adapters. Equivalent intents produce identical decisions,
authorization artifacts, and denial reasons across all three runtimes.

| Test | What it proves |
|------|----------------|
| CA-1 | Same intent + isolated state → same ALLOW/DENY decision across all adapters |
| CA-6 | Per-action cap boundary: `amount == cap` → ALLOW (inclusive) |
| CA-7 | Per-action cap exceeded: `amount > cap` → DENY + `PER_ACTION_CAP_EXCEEDED` |
| CA-8 | PBT sweep: seeded variation, same decision + evidence across all adapters |
| CA-9 | Nonce replay → DENY + `REPLAY_NONCE` across all adapters |
| CA-10 | Concurrent isolation: 30 parallel calls, all ALLOW with isolated state |

See [`packages/compat/src/test/cross-adapter.test.ts`](../compat/src/test/cross-adapter.test.ts)
and [`docs/testing/delegation-pbt.md`](../../docs/testing/delegation-pbt.md).

---

## See also

- [LangGraph integration guide](https://github.com/oxdeai/oxdeai/blob/main/docs/integrations/langgraph.md)
- [Adapter stack architecture](https://github.com/oxdeai/oxdeai/blob/main/docs/integrations/adapter-stack.md)
- [Adapter reference architecture](https://github.com/oxdeai/oxdeai/blob/main/docs/adapters/adapter-reference-architecture.md)
- [Root README](https://github.com/oxdeai/oxdeai/blob/main/README.md)
