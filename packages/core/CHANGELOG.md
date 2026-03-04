# Changelog

All notable changes to `@oxdeai/core` will be documented in this file.

The format is based on Keep a Changelog.
This project follows Semantic Versioning.

---

## [1.0.0] - 2026-03-04

Protocol stability release.

### Added

- Stable stateless verification API.
- Verification Envelope specification.
- Unified VerificationResult schema.
- Protocol documentation (`docs/protocol.md`).

### Changed

- Project status upgraded from pre-release to stable protocol library.

### Notes

This release freezes:

- verification API surface
- envelope encoding format
- verification result schema
- deterministic invariants

---

## [0.9.3] - 2026-03-04

Documentation release before v1.0.

### Added
- Protocol documentation.
- Verification Envelope specification.
- Minimal example script for envelope verification.
- Deterministic invariants documentation.

### Changed
- README expanded with stateless verification API and protocol concepts.

### Notes
- No runtime behavior changes.

---

## [0.9.2] - 2026-03-04
### Added
- Verification Envelope codec (`encodeEnvelope` / `decodeEnvelope`).
- Pure verifier `verifyEnvelope(...)` composing snapshot + audit verification.

### Changed
- Unified verification results to `VerificationResult` shape across stateless verifiers.
- Deterministic violation ordering (stable sort).

---

## [0.9.1] - 2026-03-04
### Added
- Pure verifier `verifyAuditEvents(...)` for audit chain validation (stateless).

### Changed
- Replay verification helper renamed to avoid export collision (`verifyReplayEvents`).

---

## [0.9.0] - 2026-03-03
### Added
- Pure verifier `verifySnapshot(snapshotBytes, opts?)` (stateless snapshot integrity check).

---

## [0.8.0] - 2026-03-03

**Host Integration Adapters**

v0.8.0 introduces first-class host integration primitives to @oxdeai/core without weakening its deterministic guarantees. The engine now supports pluggable StateStore and AuditSink interfaces, along with minimal in-memory and file-based reference adapters. PolicyEngine wiring ensures ordered audit delivery (sync and async) while preserving fully synchronous, deterministic evaluation semantics. State persistence is explicit (commitState, flushState) and does not affect decision outcomes. Deterministic identifiers (policyId, stateHash, auditHeadHash) remain stable across processes, and integration hooks introduce no entropy or behavioral drift. This release makes the engine production-integrable while keeping containment logic strictly deterministic.

### Added
- Adapter interfaces: `StateStore` and `AuditSink`.
- Reference adapters: `InMemoryStateStore`, `InMemoryAuditSink`, `FileStateStore`, `FileAuditSink`.
- Optional PolicyEngine integration hooks: `auditSink`, `stateStore`, `autoPersist`, plus `flushAudit()` / `commitState()` / `flushState()`.

### Tests
- Adapter integration tests validating sink event ordering for sync and async sinks.

---

## [0.7.1] - 2026-03-03

### Added
- Cross-process determinism test (spawn child process) to validate reproducible fingerprints.

---

## [0.7.0] - 2026-03-03

### Added
- `ReplayEngine.verify(...)` offline audit verifier.
- Strict verification mode returning `"inconclusive"` without state anchors.
- Optional `STATE_CHECKPOINT` audit events (stateHash only).
- `checkpoint_every_n_events` engine option.

### Security
- Strict mode refuses to certify traces without deterministic anchors.
- PolicyId consistency enforced across event streams.
- Offline recomputation of audit hash chain.

### Verification
- Chain continuity validation (GENESIS → headHash).
- Monotonic timestamp enforcement.
- Policy binding validation.
- Checkpoint stateHash format validation (64-hex).


---

## [0.6.1] - 2026-03-03

### Changed
- Documentation updates (README): added snapshot section, badge, and clarified roadmap positioning.

---

## [0.6.0] - 2026-03-03

### Added
- Versioned canonical snapshot format (`formatVersion: 1`) with schema validation.
- Deterministic module snapshot payloads (canonical JSON) replacing v8 byte snapshots.
- Property-based test suite for determinism invariants (seeded, no deps).

### Changed
- `CanonicalState` schema: `modules` replaces `moduleStates`; snapshot payloads are JSON.
- Authorization binding now uses canonical engine `stateHash` (normalized) for snapshot determinism.
- Tool amplification snapshot import tolerates `tool: null` (canonical undefined normalization).

### Invariants
- Snapshot `export → encode → decode → import` preserves `stateHash`.
- Equivalent key insertion orders produce identical per-module and global state hashes.
- Replay and decision sequences match before/after snapshot import.

---

## [0.5.1] - 2026-03-03

### Changed

* README rewritten for clarity and infra positioning.
* Added “Show me the invariant” deterministic snippet.
* Updated roadmap to reflect post-v0.5 direction (v0.6 snapshot hardening, v0.7 replay verification, v0.8 adapters).

### Documentation

* Clarified deterministic guarantees (`policyId`, `stateHash`, `auditHeadHash`).
* Reframed project positioning as deterministic economic containment.
* Removed outdated roadmap references (v0.3-era notes).

---

## [0.5.0] - 2026-02-27

### Added

- Canonical state snapshot layer:
  - `CanonicalState`
  - `createCanonicalState`
  - `withModuleState`
  - `encodeCanonicalState` / `decodeCanonicalState`
- Deterministic `computeStateHash()` derived from module state codecs.
- Content-addressed `computePolicyId()`:
  - Stable module ordering
  - Canonicalized engine configuration
  - SHA-256 over canonical payload.
- `ReplayEngine` (deterministic log replay interface).
- Strict determinism mode:
  - `Date.now()` fallback disallowed when `strictDeterminism` is enabled.
- Signature-stripped canonical intent identity:
  - `intentHash(intent)` excludes signature.
  - `verifyAuthorization()` aligned to canonical intent identity.

### Changed

- Audit chain canonicalization now binds `policyId` (null-normalized) into hash computation.
- State type exports made explicit (no wildcard re-export).
- Root export surface tightened:
  - Removed wildcard `utils` export.
  - Removed duplicate replay/determinism exports.
- Module ordering normalized via sorted registry when computing snapshots and state hashes.

### Security

- Deterministic triple guaranteed across runs:
  - `policyId`
  - `stateHash`
  - `auditHeadHash`
- Canonical JSON hardened:
  - Sorted keys
  - BigInt normalization
  - undefined normalization
  - Explicit UTF-8 hashing.
- Intent identity separated from signature proof to prevent hash fragmentation across signature encodings.
- Strict-mode clock injection required for reproducible authorization validation.

### Invariants

- Same engine version + module set + deterministic opts => identical `policyId`.
- Same state => identical `stateHash`.
- Same event sequence + `policyId` => identical audit head hash.
- Signature presence does not alter intent identity.

---

## [0.4.3] - 2026-02-27

### Fixed
- Test suite aligned to `evaluatePure()` using shared `makeState` / `makeIntent` helpers.
- Helper typing hardened so overrides remain valid (State/tool_limits merge, Intent RELEASE shape).

---

## [0.4.0] - 2026-02-27

### Added

- ToolAmplificationModule (deterministic tool/API call cap per agent per window).
- `tool_call` and `tool` fields in Intent for explicit tool accounting.
- `tool_limits` in State for tool-call window enforcement.
- ReplayModule (state-based replay protection).
- ConcurrencyModule (active authorization tracking).
- RecursionDepthModule (bounded agent depth).
- `evaluatePure()` returning `{ nextState }` for deterministic simulation.

### Changed

- `evaluate()` now acts as `evaluatePure + commit`.
- Budget and Velocity modules return `stateDelta`.
- State validation extended to include replay, concurrency, recursion, tool limits.

### Security

- Deterministic containment of:
  - Budget overflow
  - Tool-call amplification
  - Recursion depth escalation
  - Concurrency explosion
  - Replay abuse

---

## [0.2.2] - 2026-02-27

### Added

- `evaluatePure()` – deterministic evaluation returning `{ nextState }` without mutating input state.
- Replay protection moved fully into state via `ReplayModule` (nonce window tracking).
- `RecursionDepthModule` – per-agent max depth invariant.
- `ConcurrencyModule` – per-agent concurrency cap.
- Authorization-bound `RELEASE` lifecycle:
  - `Intent.type: "EXECUTE" | "RELEASE"`
  - `RELEASE` requires valid `authorization_id`
  - Concurrency slots are tied to active authorizations.
- `stateDelta` support in modules for deterministic state transitions.
- `active_auths` structure in state for concurrency ownership tracking.

### Changed

- `evaluate()` now acts as a backward-compatible wrapper over `evaluatePure()` and commits `nextState`.
- Concurrency lifecycle is now explicit and state-driven.
- State validation extended to include replay, recursion, and concurrency structures.

### Security

- Release spoofing prevented via authorization-bound concurrency slots.
- Replay protection fully deterministic and persisted in policy state.
- All invariants evaluated before commit.
- Fail-closed behavior preserved.

---

## [0.2.0] - 2026-02-26

### Added

- BudgetModule with per-period cap.
- Per-action cap enforcement.
- VelocityModule (windowed rate limiting).
- KillSwitchModule (global and per-agent).
- AllowlistModule (action / asset / target allowlists).
- Signed authorizations (HMAC-based).
- Hash-chained audit log.

---

## [0.1.x]

Initial release.
Basic deterministic policy engine with budget and velocity controls.
