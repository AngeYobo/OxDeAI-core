# Security Policy

## Security Model

OxDeAI-core is designed with strict fail-closed guarantees:

- Any malformed state → DENY (STATE_INVALID)
- Any invariant violation → DENY
- No implicit ALLOW
- Deterministic evaluation
- No randomness inside engine

---

## Threat Model

Protected against:

- Budget overflow
- Velocity bypass
- Kill-switch override
- Replay attacks
- Allowlist circumvention
- State corruption
- Signature forgery (HMAC)
- Audit tampering (hash chaining)

---

## Not in Scope

- Network-layer attacks
- Compromised host runtime
- Secret leakage outside engine boundary

---

## Reporting Vulnerabilities

Report privately to:

security@oxdeai.io

Do not disclose publicly before coordinated disclosure.

---

## Cryptography

Engine uses:
- SHA-256 hashing
- HMAC-SHA256 authorization
- Constant-time signature verification

---

## Audit Status

Internal invariant testing complete.
External audit pending.
