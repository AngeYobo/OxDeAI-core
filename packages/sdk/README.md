# @oxdeai/sdk

Developer-facing integration layer on top of `@oxdeai/core`.

## What It Adds

- Intent/state builder helpers
- Typed client wrapper for common flow: evaluate + persist + verify
- Runtime adapters (in-memory and file-based)

## Quick Example

```ts
import { PolicyEngine } from "@oxdeai/core";
import {
  OxDeAIClient,
  buildState,
  buildIntent,
  InMemoryStateAdapter,
  InMemoryAuditAdapter
} from "@oxdeai/sdk";

const engine = new PolicyEngine({
  policy_version: "v1",
  engine_secret: "dev-secret",
  authorization_ttl_seconds: 120
});

const stateAdapter = new InMemoryStateAdapter(
  buildState({
    policy_version: "v1",
    agent_id: "agent-1",
    allow_action_types: ["PROVISION"],
    allow_targets: ["us-east-1"]
  })
);

const auditAdapter = new InMemoryAuditAdapter();

const client = new OxDeAIClient({
  engine,
  stateAdapter,
  auditAdapter,
  clock: { now: () => 1770000000 }
});

const intent = buildIntent({
  intent_id: "intent-1",
  agent_id: "agent-1",
  action_type: "PROVISION",
  amount: 320n,
  target: "us-east-1",
  nonce: 1n
});

const result = await client.evaluateAndCommit(intent);
```

## Main Exports

- `buildIntent`, `buildState`
- `OxDeAIClient`
- `InMemoryStateAdapter`, `InMemoryAuditAdapter`
- `JsonFileStateAdapter`, `NdjsonFileAuditAdapter`

## Scripts

```bash
pnpm -C packages/sdk build
pnpm -C packages/sdk test
```
