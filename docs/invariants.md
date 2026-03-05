# Invariants

Protocol-level invariants expected at v1.0.0.

## I1 — Canonical hashing ignores key insertion order
Equivalent objects with different insertion order produce identical canonical hashes.

## I2 — Snapshot round-trip determinism
`export -> encode -> decode -> import` preserves canonical state hash.

## I3 — Decision equivalence across import/export
For identical intent sequence and equivalent state, decisions and resulting hashes are identical.

## I4 — Replay verification determinism
Given identical audit events, recomputed verification output is identical.

## I5 — Cross-process consistency
Independent runs with same inputs produce identical deterministic identifiers.

## Intent Binding Invariant
`intent_hash` includes only v1.0 binding fields and excludes `signature` and unknown fields.

## Fail-Closed Invariant
Malformed/invalid protocol artifacts must produce denial (`invalid` or deny/no-execute behavior).
