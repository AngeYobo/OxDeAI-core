# AutoGen Integration Demo

Framework-shaped integration demo showing OxDeAI as the deterministic authorization boundary.

The PEP layer uses [`@oxdeai/autogen`](../../packages/autogen/README.md) — a thin adapter that maps AutoGen function calls (`{ name, args, id }`) to the universal guard. No authorization logic lives in this example.

## Run

```bash
pnpm -C examples/autogen start
```

Expected sequence: `ALLOW`, `ALLOW`, `DENY` with strict `verifyEnvelope()` result `ok`.

See the canonical shared scenario: [`docs/integrations/shared-demo-scenario.md`](../../docs/integrations/shared-demo-scenario.md).
