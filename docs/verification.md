# Verification

OxDeAI exposes stateless verification APIs:
- `verifySnapshot(snapshotBytes)`
- `verifyAuditEvents(events)`
- `verifyEnvelope(envelopeBytes)`

All return `VerificationResult` with status:
- `ok`
- `invalid`
- `inconclusive`

## Snapshot Verification
Checks canonical decode, schema/version, policy binding, and deterministic state-hash recomputation.

## Audit Verification
Checks canonical hash-chain recomputation, timestamp monotonicity, and policy consistency.
Strict mode may return `inconclusive` without state anchors.

## Envelope Verification
Composes snapshot and audit verification and enforces policy consistency between both artifacts.

## Conformance
Use `@oxdeai/conformance` to validate implementations against frozen vectors.
A passing run indicates protocol-aligned behavior for the targeted version.
