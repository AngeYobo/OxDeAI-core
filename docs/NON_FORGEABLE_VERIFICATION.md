# Non-Forgeable Verification (Future: v1.2 Target)

Status: **Design proposal only**.  
This document is **not shipped behavior** in OxDeAI v1.0.2.

## 1. Purpose

OxDeAI v1.0.2 authorization verification uses a shared-secret trust profile (HMAC in the reference implementation).  
That model is operationally simple but requires verifier-side secret sharing.

v1.2 target: add a non-forgeable verification profile using public-key signatures so third parties can verify artifacts without possessing signing secrets.

## 2. Motivation

Goals for non-forgeable verification:

- allow independent third-party verification with public material only
- reduce blast radius of verifier compromise (no signing secret at verifier)
- improve inter-org auditability and settlement workflows
- preserve deterministic artifact semantics and replay behavior

Non-goals:

- replacing the v1.0.x profile immediately
- changing existing v1.0.x envelope/snapshot semantics retroactively

## 3. Proposed Trust Model

## 3.1 KeySet Distribution

Introduce a signed/verifiable key distribution artifact, `KeySet`, containing active and historical verification keys.

Proposed conceptual shape:

```json
{
  "issuer": "did:example:oxdeai-engine-1",
  "version": 1,
  "keys": [
    {
      "kid": "2026-rot-01",
      "alg": "EdDSA",
      "use": "sig",
      "publicKey": "<public-key-material>",
      "notBefore": 1775000000,
      "notAfter": 1800000000
    }
  ]
}
```

Requirements:

- verifiers MUST trust `KeySet` only through configured trust anchors
- key validity windows (`notBefore`/`notAfter`) SHOULD be enforced
- `kid` MUST be unique per issuer

## 3.2 Trust Anchors

Each relying party maintains a trust anchor set for accepted issuers.

Trust anchor examples:

- pinned issuer public key
- signed issuer registry
- governance-controlled key root

## 4. Artifact Evolution (Backward-Compatible)

v1.2 should add explicit signature metadata while retaining v1.0.x compatibility paths.

Proposed additional fields on signed artifacts:

- `issuer` (who signed)
- `kid` (which key signed)
- `alg` (signature algorithm identifier)

Current fields in v1.0.x (e.g., `engine_signature`) remain valid during migration.

Compatibility objective:

- v1.0.x verifiers continue to function for old artifacts
- v1.2 verifiers can validate both legacy and new signature profiles during transition

## 5. Migration Strategy

Two viable migration profiles:

## 5.1 Dual-Sign (Preferred)

During transition window, emit both:

- legacy shared-secret signature field
- new public-key signature field + (`issuer`, `kid`, `alg`)

Benefits:

- no abrupt verifier cutover
- staged rollout by relying party class

## 5.2 Versioned Authorization Artifact

Alternative: introduce versioned authorization shape in v1.2 and support both decoders.

Benefits:

- cleaner long-term model

Tradeoff:

- stricter version branching in SDK/CLI and verifier pipelines

## 6. Verification Rules (v1.2 Profile)

For public-key profile verification:

1. parse artifact and required signature metadata (`issuer`, `kid`, `alg`)
2. resolve issuer key set via trusted source
3. select key by `kid` and validate key validity window
4. verify signature over canonical payload using declared `alg`
5. enforce existing policy checks (expiry, intent binding, policy identity, replay constraints)

Failure of any step MUST yield non-pass verification outcome.

## 7. Threat Model Improvements

Compared to shared-secret verification:

- verifier compromise no longer yields signing capability
- cross-organization verification becomes possible without secret sharing
- stronger provenance guarantees for independently audited artifacts

Residual risks still require handling:

- key distribution poisoning (mitigated by trust anchors)
- stale key sets / rotation lag
- compromised signer key before revocation propagation

## 8. Rotation and Revocation Guidance

Operational guidance for v1.2:

- rotate signing keys on fixed cadence
- publish overlapping validity windows for smooth cutover
- maintain historical keys long enough to verify archival artifacts
- publish revocation status through trusted channel

Relying parties SHOULD cache key sets with bounded TTL and refresh on `kid` misses.

## 9. Impact on SDK / CLI

Expected SDK impact:

- add key resolver interface for verifier flows
- add verification mode selection (`legacy`, `public-key`, `auto`)
- expose richer verification diagnostics (`unknown_kid`, `untrusted_issuer`, `alg_mismatch`)

Expected CLI impact:

- commands to verify using key sets and trust anchors
- optional key set path/URL inputs (implementation-specific transport)
- explicit reporting of profile used for verification

## 10. Conformance Impact

v1.2 conformance should add vectors for:

- valid public-key signed authorization
- unknown `kid`
- untrusted `issuer`
- wrong `alg`
- revoked/expired key window
- dual-sign acceptance during migration period

v1.0.x vectors remain frozen and unchanged.

## 11. Rollout Recommendation

Recommended sequence:

1. define v1.2 artifact/profile spec
2. ship dual-sign support in reference implementation
3. publish v1.2 conformance vectors
4. migrate relying parties to public-key verification
5. deprecate legacy shared-secret verifier profile on planned timeline

## 12. Explicit Version Boundary

This document is a forward-looking design note.  
OxDeAI v1.0.2 behavior remains unchanged and authoritative for current deployments.
