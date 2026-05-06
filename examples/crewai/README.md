# CrewAI Integration Demo

Framework-shaped integration demo showing OxDeAI as the deterministic authorization boundary.

The PEP layer uses [`@oxdeai/crewai`](../../packages/crewai/README.md) — a thin adapter that maps CrewAI tool calls (`{ name, args, id }`) to the universal guard. No authorization logic lives in this example.

## Run

```bash
pnpm -C examples/crewai start
```

Expected sequence: `ALLOW`, `ALLOW`, `DENY` with strict `verifyEnvelope()` result `ok`.

See the canonical shared scenario: [`docs/integrations/shared-demo-scenario.md`](../../docs/integrations/shared-demo-scenario.md).
