#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Profile C state-hash semantics cross-language conformance verifier.

Validates modes 001–005 from docs/spec/test-vectors/profile-c-state-verification.json.
Modes 006–008 (Encoding B) are TypeScript-only and are NOT validated here.

Reuses the canonicalization-v1 implementation from verify_canonicalization_vectors.py.
"""
from __future__ import annotations

import hashlib
import json
import sys
from enum import Enum
from pathlib import Path
from typing import Any, Callable

# Reuse canonical JSON and SHA-256 from the existing canonicalization harness.
# main() in that module is guarded by __name__, so it will not run on import.
from verify_canonicalization_vectors import canonicalize, sha256_hex, CanonicalError  # noqa: E402


# ── Typed outcome constants ───────────────────────────────────────────────────

class ProfileCOutcome(str, Enum):
    OK                  = "ok"
    STATE_HASH_MISMATCH = "state-hash-mismatch"
    COMPUTE_ERROR       = "compute-error"


# ── Hash strategies ───────────────────────────────────────────────────────────

def _compute_core_hash(state: Any) -> str:
    """SHA-256(canonicalJson(state)) — standard OxDeAI state hash."""
    return sha256_hex(canonicalize(state))


def _compute_provider_hash(state: Any) -> str:
    """SHA-256('PROVIDER:' + canonicalJson(state)) — external provider hash."""
    return sha256_hex("PROVIDER:" + canonicalize(state))


def _compute_throws_hash(_state: Any) -> str:
    """Simulates a computeStateHash failure (compute-error outcome)."""
    raise RuntimeError("hash backend unavailable")


def _get_hash_fn(strategy: str) -> Callable[[Any], str] | None:
    return {
        "core":     _compute_core_hash,
        "provider": _compute_provider_hash,
        "throws":   _compute_throws_hash,
    }.get(strategy)


# ── Outcome computation ───────────────────────────────────────────────────────

def _compute_outcome(vector: dict[str, Any]) -> ProfileCOutcome:
    mode: str = vector.get("mode", "")

    # compute-throws: directly simulate computeStateHash failure.
    if mode == "compute-throws":
        return ProfileCOutcome.COMPUTE_ERROR

    # Resolve signing and verify strategies.
    hash_strategy: str = vector.get("hash_strategy", "core")
    signing_strategy: str = vector.get("signing_strategy", hash_strategy)
    verify_strategy: str  = vector.get("verify_strategy",  hash_strategy)

    signing_fn = _get_hash_fn(signing_strategy)
    verify_fn  = _get_hash_fn(verify_strategy)
    if signing_fn is None or verify_fn is None:
        return ProfileCOutcome.COMPUTE_ERROR

    # Compute committed hash from state_input.
    state_input = vector.get("state_input")
    try:
        committed_hash = signing_fn(state_input)
    except Exception:
        return ProfileCOutcome.COMPUTE_ERROR

    # Live state falls back to state_input when live_state_input is absent.
    live_state = vector.get("live_state_input", state_input)

    # Compute live hash with verify strategy.
    try:
        live_hash = verify_fn(live_state)
    except Exception:
        return ProfileCOutcome.COMPUTE_ERROR

    if live_hash == committed_hash:
        return ProfileCOutcome.OK
    return ProfileCOutcome.STATE_HASH_MISMATCH


# ── Vector loading ────────────────────────────────────────────────────────────

def _load_vectors() -> list[dict[str, Any]]:
    path = (
        Path(__file__).resolve().parent.parent
        / "docs" / "spec" / "test-vectors"
        / "profile-c-state-verification.json"
    )
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return data["vectors"]


# ── Runner ────────────────────────────────────────────────────────────────────

def main() -> int:
    vectors = _load_vectors()
    failed = 0

    for vector in vectors:
        vid: str = vector["id"]
        expected_outcome: str = vector["expected"]["outcome"]

        computed = _compute_outcome(vector)

        if computed.value != expected_outcome:
            failed += 1
            print(f"FAIL {vid}: outcome mismatch", file=sys.stderr)
            print(f"  expected: {expected_outcome}", file=sys.stderr)
            print(f"  actual:   {computed.value}", file=sys.stderr)
            continue

        print(f"PASS {vid}")

    if failed:
        print(f"\n{failed} Profile C vector(s) failed", file=sys.stderr)
        return 1

    print(f"\nAll {len(vectors)} Profile C vector(s) passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
