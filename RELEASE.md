# OxDeAI Release Policy

This document defines release discipline for OxDeAI protocol and implementation artifacts.

## Scope

- Protocol spec and artifacts (`protocol/`, `packages/core` verification surface)
- Reference implementation (`@oxdeai/core`)
- Companion packages (`@oxdeai/sdk`, `@oxdeai/conformance`)

## SemVer Rules

### Patch (`1.0.x`)

- MUST be backward compatible with prior `1.0.y`.
- MUST NOT change protocol semantics:
  - canonicalization
  - hashing/signature binding
  - envelope `formatVersion` behavior
  - verification result semantics
- MAY include:
  - documentation clarifications
  - schema publication/validation tightening aligned to existing behavior
  - CI/tooling hardening
  - non-breaking bug fixes

### Minor (`1.x.0`, `x>0`)

- Adds backward-compatible capabilities (new helpers/modules/adapters).
- MUST preserve all stable protocol artifacts from `1.0.0`.

### Major (`2.0.0`)

- Required for any breaking protocol/API change.

## What Is Breaking

The following require a major release:

- Changing `VerificationResult` schema in a non-backward-compatible way
- Changing `VerificationEnvelopeV1` wire semantics
- Changing violation code semantics used by stateless verifiers
- Changing canonical hashing behavior for stable artifacts
- Removing/renaming public API symbols relied on by documented usage

## Required CI Gates (Release Branch / Main)

All must pass before tagging:

1. `pnpm install --frozen-lockfile`
2. `pnpm build`
3. `pnpm test`
4. `pnpm -C packages/core api:check`
5. `pnpm -C packages/core api:fingerprint:check`
6. `pnpm -C packages/conformance validate`
7. Demo smoke (if demo package is in repo)

## API Report / Fingerprint Baseline Update

Update API baseline only when the API change is intentional and reviewed.

1. Run:
   - `pnpm -C packages/core api:report`
   - `pnpm -C packages/core api:fingerprint`
2. Review diffs:
   - `packages/core/temp/core.api.md`
   - `packages/core/etc/core.api.md`
   - `packages/core/API_FINGERPRINT`
3. If approved, copy/update baseline files in the same PR with rationale.
4. Re-run `api:check` and `api:fingerprint:check`.

## Security Requirements

- Follow coordinated disclosure process in [SECURITY.md](/home/ange/OxDeAI-core/SECURITY.md).
- Release notes MUST mention any security-relevant changes.
- Secrets used for signing/verification tests MUST remain test-only and non-production.

## Release Checklist

1. Ensure working tree is clean.
2. Ensure changelog/version updates are complete.
3. Run all required gates.
4. Tag release commit.
5. Publish packages in dependency order:
   - `@oxdeai/core`
   - `@oxdeai/sdk`
   - `@oxdeai/conformance`
6. Verify npm published versions.
