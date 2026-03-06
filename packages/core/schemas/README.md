# OxDeAI Schemas (v1.0.2)

This directory contains JSON Schemas for protocol artifacts shipped by `@oxdeai/core`.

All schemas use JSON Schema Draft 2020-12.

## Artifact Mapping

- `intent.schema.json`: `Intent` JSON representation.
- `canonical-state.schema.json`: `CanonicalState` object.
- `snapshot.schema.json`: alias of canonical snapshot (`CanonicalState`).
- `authorization.schema.json`: authorization artifact emitted on `ALLOW`.
- `audit-event.schema.json`: single `AuditEvent`.
- `audit-log.schema.json`: ordered list of audit events.
- `verification-envelope-v1.schema.json`: wire JSON shape used by `VerificationEnvelopeV1` codec.
- `verification-result.schema.json`: unified `VerificationResult` shape.

## Notes on Numeric / BigInt Representation

- Intent numeric bigint-like fields (`amount`, `nonce`) follow runtime acceptance:
  - integer JSON number, or
  - decimal string (optionally suffixed by `n`)
- Canonical snapshot module payloads are codec-defined and may serialize bigint values as decimal strings.
- These schemas intentionally avoid over-constraining module-internal payloads beyond shipped runtime behavior.

## Validation Guidance

- Runtime deterministic validators are implemented in `packages/core/src/schemas/validate.ts`.
- For strict protocol validation, prefer validating with both:
  1. JSON Schema validation
  2. Runtime semantic validators (`verifySnapshot`, `verifyAuditEvents`, `verifyEnvelope`)

## Stability

- `$id` values are versioned under `https://oxdeai.org/schemas/v1/`.
- Breaking changes to existing schema semantics require protocol version evolution.
