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
  getState,    // () => State | Promise<State>
  setState,    // (state: State) => void | Promise<void>
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
