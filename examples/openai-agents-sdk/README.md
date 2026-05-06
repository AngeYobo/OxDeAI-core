# OpenAI Agents SDK Integration Demo

Framework-shaped integration demo showing OxDeAI as the deterministic authorization boundary.

The PEP layer uses [`@oxdeai/openai-agents`](../../packages/openai-agents/README.md) — a thin adapter that maps OpenAI Agents SDK tool calls (`{ name, input, call_id }`) to the universal guard. No authorization logic lives in this example.

## Run

```bash
pnpm -C examples/openai-agents-sdk start
```

Expected sequence: `ALLOW`, `ALLOW`, `DENY` with strict `verifyEnvelope()` result `ok`.

See the canonical shared scenario: [`docs/integrations/shared-demo-scenario.md`](../../docs/integrations/shared-demo-scenario.md).
