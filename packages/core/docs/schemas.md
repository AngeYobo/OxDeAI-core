# Schemas

`@oxdeai/core` ships protocol JSON Schemas under `packages/core/schemas`.

These schemas are stable contract artifacts for non-TypeScript implementations and payload validation.

## Included Schemas

- `intent.schema.json`
- `canonical-state.schema.json`
- `snapshot.schema.json`
- `authorization.schema.json`
- `audit-event.schema.json`
- `audit-log.schema.json`
- `verification-envelope-v1.schema.json`
- `verification-result.schema.json`

## Validation in Runtime Code

The runtime uses deterministic validators in `src/schemas/validate.ts` for schema checks and deterministic issue ordering.

Verifier mappings:

- Snapshot schema failures -> `SNAPSHOT_CORRUPT`
- Audit event schema failures -> `MALFORMED_EVENT`
- Envelope schema failures -> `ENVELOPE_MALFORMED`

Violation ordering is deterministic (`code`, then `index`).

## Stability Expectations

- Schema IDs (`$id`) are versioned and immutable for protocol v1.
- `formatVersion` fields are strict (`const: 1`) where applicable.
- Breaking schema changes require protocol version evolution.
- Additive optional fields are non-breaking only when canonical semantics remain unchanged.

## Local Check

Run:

```bash
pnpm -C packages/core schema:validate
```

This checks schema file parseability and required metadata fields (`$id`, `title`, `description`).
