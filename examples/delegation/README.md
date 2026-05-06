# OxDeAI - DelegationV1 Demo

Demonstrates how a parent agent delegates strictly narrowed authority to a child agent using `DelegationV1`.

## Scenario

```
parent-agent  → full authority: tools=[provision_gpu, query_db], budget=1000
     ↓ delegates
child-agent   → narrow scope:   tools=[provision_gpu],           max_amount=300, expiry=60s
```

## Expected Output

```
call 1: ALLOW   provision_gpu / amount=200     (within scope)
call 2: ALLOW   provision_gpu / amount=200     (within scope)
call 3: DENY    query_db / amount=200          (tool not in delegation scope)
call 4: DENY    provision_gpu / amount=200     (delegation expired)
```

## Run

```bash
pnpm -C examples/delegation start
```

## What It Demonstrates

- **Scope narrowing** - delegation cannot expand parent authority
- **Tool allowlist** - child can only call tools explicitly delegated
- **Expiry enforcement** - expired delegation is rejected at the PEP
- **Local verification** - no control plane required at execution time
- **Cryptographic binding** - delegation is Ed25519-signed, bound to parent auth hash

## Architecture

```
parent-agent
  → holds AuthorizationV1 (from PDP evaluation)
  → creates DelegationV1 (signed, narrow scope)
       ↓
child-agent
  → presents DelegationV1 to PEP
  → PEP: verifyDelegation(delegation, parentAuth, ...)
  → ALLOW → tool executes
  → DENY  → tool blocked, no side effect
```

## Protocol Reference

- Spec: [`docs/spec/delegation-v1.md`](../../docs/spec/artifacts/delegation-v1.md)
- Implementation plan: [`docs/spec/artifacts/delegation-v1.md`](../../docs/spec/artifacts/delegation-v1.md)
- Roadmap: [`v2.x - Delegated Agent Authorization (shipped)`](../../ROADMAP.md)
