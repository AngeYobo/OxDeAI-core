# @oxdeai/openai-agents
OpenAI Agents SDK adapter for the OxDeAI execution-time authorization protocol.
All tool calls pass through @oxdeai/guard (non-bypassable boundary, fail-closed verification).

---

## What this package does

OpenAI Agents SDK tool calls (`{ name, input, call_id }`) carry no agent
identity and use a different shape from OxDeAI's `ProposedAction`. This adapter:

1. Injects `agentId` from config into every call (tool calls carry no agent identity)
2. Maps `toolCall.input` → `args` (OpenAI uses `input`, not `args`)
3. Maps `toolCall.call_id` → `context.intent_id` (OpenAI uses `call_id`, not `id`)
4. Passes the resulting `ProposedAction` to `OxDeAIGuard`

Everything else - policy evaluation, authorization verification, state
persistence, fail-closed behavior - happens inside `@oxdeai/guard`.

---

## Installation

```sh
pnpm add @oxdeai/openai-agents @oxdeai/core
```

---

## Usage

```ts
import { createOpenAIAgentsGuard } from "@oxdeai/openai-agents";

const guard = createOpenAIAgentsGuard({
  engine,      // PolicyEngine from @oxdeai/core
  getState,    // () => { state, version } | Promise<{ state, version }>
  setState,    // (state, expectedVersion) => boolean | Promise<boolean>  (CAS)
  agentId: "gpu-agent-1",
});

// In your tool execution handler:
const result = await guard(
  { name: "provision_gpu", input: { asset: "a100", region: "us-east-1" }, call_id: "call-xyz" },
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
    input: { asset: "a100", region: "us-east-1" },
    call_id: "call-xyz",
    estimatedCost: 500,
    resourceType: "gpu",
  },
  () => provisionGpu("a100", "us-east-1")
);
```

---

## With a custom intent mapper

Use `mapActionToIntent` when you need full control over how a tool call maps
to an OxDeAI `Intent`:

```ts
const guard = createOpenAIAgentsGuard({
  engine,
  getState,
  setState,
  agentId: "gpu-agent-1",
  mapActionToIntent(action) {
    // action.name, action.args (from toolCall.input), action.context.agent_id available
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
} from "@oxdeai/openai-agents";

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

## Cross-adapter validation

This adapter is cross-validated by `@oxdeai/compat` against the LangGraph
and CrewAI adapters. Equivalent intents produce identical decisions,
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

- [OpenAI Agents SDK integration guide](https://github.com/oxdeai/oxdeai/blob/main/docs/integrations/openai-agents-sdk.md)
- [Adapter stack architecture](https://github.com/oxdeai/oxdeai/blob/main/docs/integrations/adapter-stack.md)
- [Adapter reference architecture](https://github.com/oxdeai/oxdeai/blob/main/docs/adapters/adapter-reference-architecture.md)
- [Root README](https://github.com/oxdeai/oxdeai/blob/main/README.md)
