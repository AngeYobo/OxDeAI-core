# Changelog

All notable changes to `@oxdeai/core` will be documented in this file.

The format is based on Keep a Changelog.
This project follows Semantic Versioning.

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
