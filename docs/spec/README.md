# Specification

This directory contains the **normative specification** of OxDeAI.

## Model

```
(intent, state, policy) → ALLOW | DENY
```

Execution is only reachable if authorization is verified.

---

## Structure

### Core

- canonicalization-v1
- eta-core-v1
- trusted-time-v1

### Artifacts

- authorization-v1
- delegation-v1

### Enforcement

- pep-gateway-v1

### Verification

- verification-v1

### Conformance

- conformance-v1
- test-vectors-v1

### Interoperability

- external-provider-profile

---

## Guarantees

- deterministic evaluation  
- fail-closed execution  
- pre-execution enforcement  
- cryptographic verification  

---

## Invariant

> No valid authorization → no execution