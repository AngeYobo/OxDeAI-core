# GPU Guard (Runnable Example)

Deterministic GPU provisioning guard using `@oxdeai/core` semantics.

## Run
```bash
cd examples/gpu-guard
pnpm run demo
```

The demo prints:
- decision
- authorization id (if ALLOW)
- policyId
- stateHash
- auditHeadHash

## Notes
- This is a local runnable example.
- It imports `packages/core/dist/index.js` after building core.
