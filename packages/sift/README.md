# @oxdeai/sift

Sift adapter for OxDeAI.

This package converts a **Sift governance receipt** into deterministic OxDeAI authorization inputs:

```text
Sift receipt
→ local verification
→ intent normalization
→ state normalization
→ AuthorizationV1 construction
````

It does **not** execute actions and it does **not** treat a Sift receipt as execution authorization.

## Purpose

Sift is an upstream **decision / governance layer** providing signed receipt-level decisions.
With the current receipt shape, it does not provide cryptographic proof of parameter-level approval.

OxDeAI is the **execution-time authorization and enforcement layer**.

This adapter bridges the two without weakening OxDeAI invariants:

* no valid authorization → no execution
* fail-closed on ambiguity
* deterministic intent/state binding
* local verification at execution time
* no runtime dependency on remote receipt verification

## Wire format

The Sift verifier contract specifies a particular canonicalization and encoding scheme.
This package implements it exactly so that digests and signatures computed locally
match those produced by the Sift service.

| Surface | Format |
|---|---|
| Canonical JSON | Python `json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=True)` - keys sorted lexicographically, no whitespace, non-ASCII UTF-16 code units escaped as `\uXXXX` (lowercase); supplementary characters (U+10000+) as two surrogate escapes each |
| Signatures | Ed25519 over canonical JSON UTF-8 bytes, encoded as base64url without padding (RFC 4648 §5) |
| Public keys | Raw 32-byte Ed25519 key material - matches the `x` field of a JWKS entry (RFC 8037 OKP); no PEM wrapper required at this boundary |

**Algorithm naming.** There are two distinct surfaces:

* `alg: "EdDSA"` - JWKS metadata field for key-discovery tooling (RFC 8037).
* `alg: "ed25519"` - Sift contract runtime literal present in `AuthorizationV1.signature.alg` (lowercase).

These are not interchangeable. The runtime artifact always uses `"ed25519"`.

## What this package does

### `verifyReceipt`

Validates and verifies a Sift receipt locally.

Responsibilities:

* structural validation (field presence and types)
* receipt version validation
* receipt hash integrity validation (Sift-canonical JSON, ensure_ascii=True)
* Ed25519 signature verification (raw 32-byte key; base64url-decoded signature)
* `ALLOW` / `DENY` decision validation
* bounded freshness validation (`maxAgeMs` - configurable per deployment; treat as a security parameter)

Verification order (integrity before semantics):

1. Structural validation
2. Version check
3. `receipt_hash` integrity
4. Ed25519 signature
5. Decision (`ALLOW` / `DENY`)
6. Freshness

Properties:

* fail-closed
* no network calls
* explicit typed errors
* deterministic behavior

**Public key input.** `verifyReceipt` accepts the public key as:

* `publicKeyRaw` - raw 32-byte Ed25519 key material, either as a `Uint8Array` or a base64url-no-padding string matching the JWKS `x` field. This is the primary Sift-contract-native path.
* `publicKeyPem` - PEM-encoded SPKI Ed25519 public key. Accepted for backward compatibility. `publicKeyRaw` takes precedence when both are provided.

In production, the raw key is obtained by decoding the JWKS `x` field for the `kid` matching the receipt, after confirming the key is not revoked in the KRL.

### `normalizeIntent`

Transforms explicit execution parameters plus a verified Sift receipt into a deterministic OxDeAI intent object.

Properties:

* no receipt-only execution path
* no implicit defaults
* no hidden coercion
* safe integers only
* rejects non-deterministic runtime objects
* prototype-safe object construction
* parameters are supplied by the caller and are not cryptographically bound to the receipt

### `normalizeState`

Validates and normalizes explicit execution-relevant state.

Properties:

* state must be supplied explicitly
* no inferred or default state
* deterministic normalized output
* required top-level keys supported
* prototype-safe object construction

### `receiptToAuthorization`

Builds an unsigned `AuthorizationV1`-style payload from:

* verified Sift receipt
* normalized intent
* normalized state
* explicit issuer / audience bindings

Explicit bindings:

| Authorization field | Source                                                              |
| ------------------- | ------------------------------------------------------------------- |
| `auth_id`           | `receipt.nonce`                                                     |
| `policy_id`         | `receipt.policy_matched`                                            |
| `intent_hash`       | SHA-256 of Sift-canonical JSON bytes of intent (ensure_ascii=True)  |
| `state_hash`        | SHA-256 of Sift-canonical JSON bytes of state (ensure_ascii=True)   |
| `issued_at`         | single captured adapter time (Unix seconds)                         |
| `expires_at`        | derived from configured TTL                                         |
| `audience`          | caller-supplied                                                     |
| `issuer`            | caller-supplied                                                     |
| `signature.alg`     | `"ed25519"` - Sift contract runtime literal (lowercase)             |
| `signature.kid`     | caller-supplied `keyId`                                             |
| `signature.sig`     | `""` placeholder - caller MUST sign the returned `signingPayload`  |

This function constructs the payload. It does **not** sign it.

**Signing preimage.** The returned `signingPayload` is `AuthorizationV1` with `signature.sig` **absent**.
`signature.alg` and `signature.kid` are present. The caller MUST:

1. Sift-canonicalize `signingPayload` (ensure_ascii=True, sort_keys).
2. Sign the resulting UTF-8 bytes with Ed25519.
3. Encode the signature as base64url without padding.
4. Place the result in `authorization.signature.sig`.

The PEP Gateway reconstructs the same `signingPayload` to verify the signature.

## What this package does not do

This package does **not**:

* call Sift `/verify-receipt` at runtime
* execute actions
* enforce at the PEP boundary
* fetch state from external systems
* infer missing execution parameters
* treat Sift receipts as portable execution authorization

## Security model

This package is designed around OxDeAI's execution-boundary model.

### Important constraint

A Sift receipt is a **governance decision artifact**.

It is **not** an OxDeAI authorization artifact.

Execution must remain gated by valid `AuthorizationV1` verified at the PEP boundary.

### Parameter binding limitation

Sift receipts do **not** cryptographically bind execution parameter values.

A Sift receipt proves that a governance decision was issued for the signed fields
(e.g. `action`, `tool`, `decision`, `nonce`, `timestamp`).

It does **not** prove that the `params` later supplied to `normalizeIntent`
are the same parameters evaluated by Sift.

Therefore:

- `AuthorizationV1.intent_hash` commits to **adapter-supplied params**
- it does **not** prove parameter-level approval by Sift
- parameter mismatch between Sift evaluation and execution is **not detectable**
  from the receipt alone

A receipt alone MUST NEVER be treated as sufficient to construct an executable intent.

This limitation does **not weaken the execution boundary**:

- execution remains strictly gated by `AuthorizationV1`
- the PEP Gateway enforces exact `intent_hash` and `state_hash` matching
- any mismatch at execution time still results in **DENY → no execution**

If parameter-level guarantees are required, the Sift receipt format MUST include:

- canonical `params`, or
- `params_hash = sha256(sift_canonical(params))`

### Fail-closed behavior

Any ambiguity or invalid input results in failure.

Examples:

* malformed receipt
* invalid signature
* stale receipt
* unsupported param/state type
* missing issuer / audience
* failed canonical hashing

### Freshness window

The adapter enforces a bounded freshness window on Sift receipts.

- Default: 30 seconds
- MUST be configurable per deployment
- MUST be treated as a security parameter, not a convenience value

A shorter window reduces replay exposure but increases sensitivity to clock skew and network latency.

The adapter MUST reject:
- stale receipts (age > configured window)
- receipts too far in the future (beyond allowed clock skew)

### Receipt hash integrity

`receipt_hash` MUST be computed over the Sift-canonical JSON payload with:

- `signature` excluded
- `receipt_hash` excluded

Canonicalization requirements (Sift wire format):

- lexicographic key ordering
- no whitespace between tokens
- `ensure_ascii=True` - every UTF-16 code unit above U+007F escaped as `\uXXXX`; supplementary characters as two surrogate escapes each
- UTF-8 encoding

The adapter MUST:

1. recompute the hash locally
2. compare with the provided `receipt_hash`
3. only proceed if they match

### Signature verification scope

The Ed25519 signature is verified over the Sift-canonical payload with:

- `signature` excluded
- `receipt_hash` INCLUDED

This enforces the sequence:

```text
payload → integrity check (receipt_hash) → signature verification
```

The adapter MUST NOT:
- verify signature before validating `receipt_hash`
- mutate payload before verification

Signatures are base64url without padding. The verifier accepts both base64url (Sift-native) and
standard base64 - both normalize to the same underlying bytes before decoding.

### Key management and JWKS/KRL surface

The adapter verifies Sift receipts using raw 32-byte Ed25519 keys distributed via the Sift JWKS endpoint.

JWKS entry shape (RFC 8037 OKP):

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "alg": "EdDSA",
  "use": "sig",
  "kid": "<key-id>",
  "x": "<base64url-no-padding 32-byte raw public key>"
}
```

Production key resolution sequence:

1. Extract `kid` from the receipt.
2. Check `kid` against the KRL - if revoked, DENY immediately.
3. Look up the JWKS entry for `kid`. If not found, trigger a JWKS refresh (cache may be stale) and retry once.
4. If still not found → DENY. No fallback guessing.
5. Decode `x` (base64url → 32 bytes) and pass as `publicKeyRaw` to `verifyReceipt`.

Minimum requirements:

- support multiple active keys identified by `kid`
- check the KRL before trusting any key when KRL is available
- refresh JWKS on unknown `kid` before failing closed
- fail closed if the key cannot be resolved after refresh
- no fallback guessing
- deterministic key selection

**KRL integrity modes.** `SiftHttpKeyStore` supports three KRL integrity modes controlled by the `krlMode` constructor option:

| Mode | Description | Production status |
|------|-------------|------------------|
| `"signed_required"` | Every KRL must be cryptographically signed (`SignedKRLV1`). Unsigned KRLs are rejected with `KRL_UNSIGNED_IN_SIGNED_REQUIRED` *before* calling `verifyKrl`. Requires a `verifyKrl` callback at construction. **Closes the transport-integrity gap.** | Recommended |
| `"signed_preferred"` *(default)* | Signed KRLs are verified when present; unsigned KRLs are accepted as a transport-trust fallback (`unsigned_fallback` status). If a signature field is present but no `verifyKrl` is configured, refresh fails closed - there is no downgrade path. | Default transition mode |
| `"unsigned_legacy"` | Preserves pre-Patch-B unsigned KRL behavior. Deprecated. Emits a warning at construction. **Residual risk: transport security only.** | Deprecated |

**Wiring signed KRL verification.** Supply a `verifyKrl` callback that delegates to `verifySignedKrl` from `@oxdeai/core`. This preserves `@oxdeai/sift`'s zero-dependency boundary:

```ts
import { verifySignedKrl } from "@oxdeai/core";
import type { KeySet } from "@oxdeai/core";

const krlSigningKeySets: KeySet[] = [/* your trusted KRL signing key sets */];

const store = new SiftHttpKeyStore({
  jwksUrl: "https://your-sift-host/sift-jwks.json",
  krlUrl:  "https://your-sift-host/sift-krl.json",
  krlMode: "signed_required",
  verifyKrl: (payload, ctx) => verifySignedKrl(payload, {
    trustedKeySets: krlSigningKeySets,
    ...ctx,
  }),
});
```

**KRL status surface.** `store.getKrlStatus()` returns an integrity snapshot:

```ts
const status = store.getKrlStatus();
// {
//   mode: "signed_required",
//   lastIntegrity: "signed" | "unsigned_fallback" | "unsigned_legacy" | "failed" | "none",
//   lastReason: undefined,           // cleared on success; error code on failure
//   unsignedFallbackActive: false,
//   lastVerifiedAt: 1744550000,      // unix seconds of last accepted KRL
//   lastKrlVersionByIssuer: { "krl-authority": 5 }
// }
```

`lastReason` is always cleared to `undefined` on a successful refresh. It never carries a stale failure reason after a later success.

**Version watermark.** `SiftHttpKeyStore` tracks the highest accepted `krl_version` per issuer and passes this to `verifyKrl` as `previousKrlVersionByIssuer`. This causes `verifySignedKrl` to reject any KRL whose `krl_version` is less than the previously accepted version (`KRL_VERSION_REGRESSION`). By default the watermark is in-memory and resets on process restart. Configure a `KrlWatermarkStore` to persist the watermark across restarts - see **Persistent KRL high-watermark** below.

**Unsigned path behavior (legacy).** The unsigned fallback path (used by `unsigned_legacy` and by `signed_preferred` when the fetched KRL has no `signature` field) silently skips non-string entries in `revoked_kids`. **This is legacy behavior and is NOT `SignedKRLV1` semantics.** `SignedKRLV1` verification rejects non-string entries and duplicate entries as `KRL_MALFORMED`.

**KRL reason codes.** Two sets of codes are surfaced in `krlStatus.lastReason` and `KeyStoreError` messages:

*Sift-local mode/contract codes* - produced by `SiftHttpKeyStore` mode logic; never imported from `@oxdeai/core`:

| Code | Trigger |
|------|---------|
| `KRL_UNSIGNED_IN_SIGNED_REQUIRED` | Unsigned KRL rejected in `signed_required` mode before `verifyKrl` is called |
| `KRL_MISSING_VERIFY_CALLBACK` | KRL has a `signature` field but no `verifyKrl` callback configured; refresh fails closed |
| `KRL_VERIFY_CALLBACK_ERROR` | `verifyKrl` callback threw instead of returning a result; refresh fails closed |
| `KRL_VERIFY_RESULT_INCOMPLETE` | `verifyKrl` returned `ok: true` but omitted `accepted` issuer/`krl_version` metadata; refresh fails closed |
| `KRL_WATERMARK_LOAD_FAILED` | *(Phase A)* Persistent watermark store could not be loaded before verification; refresh fails closed before `verifyKrl` is called |
| `KRL_WATERMARK_PERSIST_FAILED` | *(Phase A)* Signed KRL verified but persisting the new watermark failed; refresh fails closed before cache swap |

*Core KRL codes* - passed through as opaque strings from the `verifyKrl` callback (originated in `@oxdeai/core`):
`KRL_MALFORMED`, `KRL_SIG_INVALID`, `KRL_EXPIRED`, `KRL_UNSUPPORTED_ALG`, `KRL_UNKNOWN_SIGNING_KID`, `KRL_SIGNING_KEY_INACTIVE`, `KRL_VERSION_REGRESSION`.

**`result.accepted` contract.** When `verifyKrl` returns `ok: true`, it MUST include `accepted: { issuer, krl_version }` populated from the verified `SignedKRLV1` payload fields. This is how `SiftHttpKeyStore` advances the per-issuer version watermark without independently re-parsing the body. Omitting `accepted` fails closed with `KRL_VERIFY_RESULT_INCOMPLETE`.

**Persistent KRL high-watermark.** By default, the per-issuer `krl_version` watermark is in-memory only and resets on process restart, opening a one-cycle downgrade window. Supply a `KrlWatermarkStore` to make the watermark durable:

```ts
import {
  SiftHttpKeyStore,
  createFileBackedKrlWatermarkStore,
} from "@oxdeai/sift";
import { verifySignedKrl } from "@oxdeai/core";

const store = new SiftHttpKeyStore({
  jwksUrl, krlUrl,
  krlMode: "signed_required",
  verifyKrl: (payload, ctx) => {
    const result = verifySignedKrl(payload, { trustedKeySets: myKrlKeys, ...ctx });
    if (!result.ok) return result;
    const krl = payload as { issuer: string; krl_version: number };
    return { ...result, accepted: { issuer: krl.issuer, krl_version: krl.krl_version } };
  },
  // Phase A: persistent high-watermark (single-node)
  krlWatermarkStore: createFileBackedKrlWatermarkStore("/var/app/krl-watermark.json"),
});
```

| Interface | Description |
|-----------|-------------|
| `KrlWatermarkStore` | Pluggable interface: `get(issuer)`, `set(issuer, version)`, `list()` |
| `createInMemoryKrlWatermarkStore()` | Default in-process store (current behavior, no persistence) |
| `createFileBackedKrlWatermarkStore(path)` | Persistent single-node store; atomic write via temp-file + rename |

**No constructor I/O.** The store is never accessed at construction time. On the first signed `refresh()`, `list()` is called to load persisted watermarks and merge them into the in-memory map.

**Persist-before-cache-swap.** After signed KRL verification succeeds, the new `krl_version` is written to the store *before* the in-memory revocation cache is swapped. If the write fails, `refresh()` throws `KRL_WATERMARK_PERSIST_FAILED` and the cache is not updated. A KRL is only accepted if its version was durably recorded.

**Restart downgrade protection.** With a persistent store configured, an older signed KRL replayed after process restart will be rejected with `KRL_VERSION_REGRESSION` because the persisted watermark is restored before `verifyKrl` is called on the new refresh.

**`krlStatus.watermarkStore`:** `"memory"` when no store is configured (default); `"persistent"` when a `KrlWatermarkStore` is configured.

**Single-node / single-writer.** `createFileBackedKrlWatermarkStore` uses read-modify-write and is NOT safe for concurrent writes from multiple processes. Multi-node deployments should implement `KrlWatermarkStore` backed by a database with atomic compare-and-set.

**Last-known-good (LKG) signed-KRL cache.** Opt-in cache that improves cold-start and fetch-failure resilience. When configured, `SiftHttpKeyStore` writes the signed KRL payload to the cache after every successful signed verification + durable watermark persistence. On subsequent fetch failures, the cache provides a fallback — but **only after full re-verification through `verifyKrl`**. A cached payload is never trusted without re-verification.

```ts
import {
  SiftHttpKeyStore,
  createFileBackedSignedKrlCache,
  createFileBackedKrlWatermarkStore,
} from "@oxdeai/sift";
import { verifySignedKrl } from "@oxdeai/core";

const store = new SiftHttpKeyStore({
  jwksUrl, krlUrl,
  krlMode: "signed_required",
  verifyKrl: (payload, ctx) => {
    const result = verifySignedKrl(payload, { trustedKeySets: myKrlKeys, ...ctx });
    if (!result.ok) return result;
    const krl = payload as { issuer: string; krl_version: number };
    return { ...result, accepted: { issuer: krl.issuer, krl_version: krl.krl_version } };
  },
  krlWatermarkStore: createFileBackedKrlWatermarkStore("/var/app/krl-watermark.json"),
  // Phase B: last-known-good cache
  signedKrlCache: createFileBackedSignedKrlCache("/var/app/krl-lkg.json"),
});
```

| Interface | Description |
|-----------|-------------|
| `SignedKrlCache` | Pluggable interface: `get()`, `set(payload, verifiedAt)` |
| `createInMemorySignedKrlCache()` | In-process cache (lost on restart) |
| `createFileBackedSignedKrlCache(path)` | Persistent single-node cache; atomic write |

**Mode behavior:**
- `signed_required` — valid LKG may be used after re-verification on fetch failure; invalid/expired/malformed LKG fails closed.
- `signed_preferred` — LKG fallback attempted; if LKG is invalid or absent, preserves existing compatibility behavior.
- `unsigned_legacy` — LKG is never read or written.

**No constructor I/O.** LKG is never accessed at construction time. Cache access happens exclusively inside `refresh()`.

**LKG is never trusted without re-verification.** Every load runs the payload through `verifyKrl` with the current `now` and the current persisted watermark before any `revoked_kids` derived from it enter the store.

**LKG write sequencing.** Written only after signed verification succeeds AND watermark persistence succeeds. Unsigned fallback KRLs are never written to LKG.

**LKG write failure is non-fatal.** After durable watermark persistence, a failing LKG write does not invalidate the accepted KRL. The failure is logged via `console.warn`.

**Status fields:** `lkgCacheActive: boolean` (true when active `revokedKids` came from LKG), `lkgVerifiedAt?: number` (unix seconds of the LKG entry's `verifiedAt`). No payload, signature bytes, or key material is ever exposed in status.

**Closing RT-TRUST-2.** The KRL transport-integrity gap is closeable for a given deployment when all three are configured: `signed_required` + `KrlWatermarkStore` + `SignedKrlCache`. Without all three, residual risks remain (see `docs/audits/protocol-audit-post-interoperability.md`).

**Deprecation trajectory:**

| Release | Change |
|---------|--------|
| Current (`signed_preferred` default) | `unsigned_legacy` warns at construction via `process.emitWarning(DEP_OXDEAI_KRL_UNSIGNED_LEGACY)`; `signed_preferred` unsigned fallback warns once per instance via `console.warn` |
| `v-next` | See above (already landed) |
| `v-after` | `unsigned_legacy` removed; default becomes `signed_required` — **breaking change for callers not wiring `verifyKrl`** |

---

## Migration guide

### Closing the KRL transport-integrity gap

The `RT-TRUST-2` transport-integrity gap is fully closeable when all four are configured. Use this pattern for production deployments:

```ts
import {
  SiftHttpKeyStore,
  createFileBackedKrlWatermarkStore,
  createFileBackedSignedKrlCache,
} from "@oxdeai/sift";
import { verifySignedKrl } from "@oxdeai/core";
import type { KeySet } from "@oxdeai/core";

// Your KRL signing key sets — distinct from AuthorizationV1 signing keys.
const krlSigningKeySets: KeySet[] = [
  {
    issuer: "your-krl-authority",
    version: "1",
    keys: [{ kid: "krl-2026-01", alg: "Ed25519", public_key: "...PEM..." }],
  },
];

const store = new SiftHttpKeyStore({
  jwksUrl: "https://your-sift-host/sift-jwks.json",
  krlUrl:  "https://your-sift-host/sift-krl.json",
  krlMode: "signed_required",                         // 1. close transport-integrity gap
  verifyKrl: (payload, ctx) => {                       // 2. cryptographic KRL verification
    const result = verifySignedKrl(payload, {
      trustedKeySets: krlSigningKeySets,
      ...ctx,
    });
    if (!result.ok) return result;
    const krl = payload as { issuer: string; krl_version: number };
    return { ...result, accepted: { issuer: krl.issuer, krl_version: krl.krl_version } };
  },
  krlWatermarkStore: createFileBackedKrlWatermarkStore("/var/app/krl-watermark.json"), // 3. prevent restart downgrade
  signedKrlCache:    createFileBackedSignedKrlCache("/var/app/krl-lkg.json"),          // 4. cold-start resilience
});
```

### Mode descriptions

| Mode | Posture | When to use |
|------|---------|-------------|
| `signed_required` | **Production target.** Every KRL must be cryptographically signed and verified. | New deployments; all deployments when ready |
| `signed_preferred` | **Transition mode.** Signed KRLs verified; unsigned KRLs accepted via transport trust fallback. Will not remain the default permanently. | Migrations in progress; deployments working toward signed KRLs |
| `unsigned_legacy` | **Deprecated.** Transport-trust only. No cryptographic KRL integrity. Emits `DeprecationWarning` at construction. Will be removed in a future release. | Do not use in new code |

### Migrating from `unsigned_legacy`

1. Remove `krlMode: "unsigned_legacy"` from your `SiftHttpKeyStore` options
2. If your KRL provider supplies signed KRLs: configure `krlMode: "signed_required"` + `verifyKrl` (see full example above)
3. If your KRL provider does not yet supply signed KRLs: use `krlMode: "signed_preferred"` (no `verifyKrl` needed; unsigned fallback remains available as a temporary bridge)

### Migrating from `signed_preferred` unsigned fallback to `signed_required`

`signed_preferred` will remain available as an explicit opt-in after `signed_required` becomes the default. To proactively migrate:

1. Ensure your KRL publisher produces `SignedKRLV1` payloads
2. Obtain the KRL signing public key from your provider; configure it as a `KeySet`
3. Wire `verifyKrl` as shown in the production example above
4. Change `krlMode: "signed_required"`
5. Optionally add `krlWatermarkStore` and `signedKrlCache` for restart resilience

### Prototype safety

All user-controlled normalized objects are created with `Object.create(null)`.

This prevents `__proto__` setter side effects and silent key loss during normalization.

### Responsibility split

Sift provides:

- signed governance decisions (`ALLOW` / `DENY`)
- receipt integrity and authenticity

OxDeAI provides:

- deterministic intent binding (including params)
- deterministic state binding
- audience binding
- replay protection
- non-bypassable execution enforcement at the PEP

These guarantees are intentionally separated.

A Sift receipt alone cannot authorize execution.
Only a valid `AuthorizationV1` verified at the PEP Gateway can.

## Package structure

```text
packages/sift/
├── src/
│   ├── siftCanonical.ts        ← Sift-contract canonicalization, base64url, raw key import
│   ├── siftKeyStore.ts         ← JWKS/KRL key store (SiftHttpKeyStore, createStagingKeyStore)
│   ├── verifyReceipt.ts        ← verifyReceipt + verifyReceiptWithKeyStore
│   ├── normalizeIntent.ts
│   ├── state.ts
│   ├── receiptToAuthorization.ts
│   └── index.ts
├── test/
├── package.json
└── tsconfig.json
```

`siftCanonical.ts` is an internal module. It is not exported from `index.ts`. Use the public API (`verifyReceipt`, `receiptToAuthorization`, etc.) at integration boundaries.

## API surface

### Receipt verification - local key path

```ts
import { verifyReceipt } from "@oxdeai/sift";
```

Synchronous.  Accepts the public key directly via `publicKeyRaw` (raw 32-byte `Uint8Array` or base64url string matching the JWKS `x` field) or the deprecated `publicKeyPem`.  No network calls.  Use this path for deterministic offline tests or when your application resolves the key externally.

Verifies:

* structure and version
* receipt hash integrity (Sift-canonical, ensure_ascii=True)
* Ed25519 signature (raw 32-byte key; base64url signature)
* decision and freshness

### Receipt verification - keystore path

```ts
import { verifyReceiptWithKeyStore, createStagingKeyStore } from "@oxdeai/sift";

const keyStore = createStagingKeyStore();
const result   = await verifyReceiptWithKeyStore(receipt, { kid, keyStore });
```

Async.  Resolves the Ed25519 public key by `kid` from a `SiftKeyStore`.  Enforces KRL revocation, refresh-on-unknown-kid (once), and fail-closed on any unresolvable key.  After key resolution it delegates to `verifyReceipt` with the same verification ordering.

Key resolution sequence:

1. Reject empty `kid` → `MISSING_KID`.
2. Check KRL → `REVOKED_KID` if revoked.
3. Look up `kid` in the in-memory cache.
4. If not found: call `keyStore.refresh()` once.
   - On refresh failure → `JWKS_FETCH_FAILED` / `KRL_FETCH_FAILED` / `KEYSTORE_REFRESH_FAILED`.
   - Re-check KRL after refresh.
   - Re-check key lookup after refresh.
   - If still not found → `UNKNOWN_KID`.
5. Call `verifyReceipt` with the resolved key.

**KRL cache freshness.** Steps 2 and 4b check revocation against the in-memory cache only.
A kid that is already in the key cache does **not** trigger a refresh, so a revocation added
to the KRL after the last `refresh()` call will not be detected until the next explicit
`refresh()`.  Callers SHOULD call `refresh()` on a schedule appropriate to their revocation
latency requirements - not just on startup.

### Key store

```ts
import { SiftHttpKeyStore, createStagingKeyStore, type SiftKeyStore } from "@oxdeai/sift";

// Staging (development / testing only - NOT for production):
const store = createStagingKeyStore();
await store.refresh();
// Note: createStagingKeyStore() throws if NODE_ENV === "production".
// Use new SiftHttpKeyStore({ jwksUrl, krlUrl }) with your production endpoints.

// Production (signed KRL integrity):
import { verifySignedKrl } from "@oxdeai/core";
const prodStore = new SiftHttpKeyStore({
  jwksUrl: "https://your-production-sift-host/sift-jwks.json",
  krlUrl:  "https://your-production-sift-host/sift-krl.json",
  krlMode: "signed_required",
  verifyKrl: (payload, ctx) => verifySignedKrl(payload, { trustedKeySets: myKrlKeySets, ...ctx }),
});

// Transition (default - unsigned fallback if KRL is unsigned):
const transStore = new SiftHttpKeyStore({
  jwksUrl: "https://your-production-sift-host/sift-jwks.json",
  krlUrl:  "https://your-production-sift-host/sift-krl.json",
  // krlMode defaults to "signed_preferred"
});

// Inject a mock fetch for tests:
const testStore = new SiftHttpKeyStore({ jwksUrl, krlUrl, fetch: mockFetch });
```

`SiftKeyStore` is the interface.  `SiftHttpKeyStore` is the HTTP-backed implementation.  Both `getPublicKeyByKid` and `isKidRevoked` operate on the in-memory cache; only `refresh()` makes network calls.

`createStagingKeyStore()` is for development and testing only.  It throws if `NODE_ENV === "production"` unless `{ _allowInProduction: true }` is passed explicitly.  Do not call it in production processes.

Staging endpoints:

* JWKS: `https://sift-staging.walkosystems.com/sift-jwks.json`
* KRL:  `https://sift-staging.walkosystems.com/sift-krl.json`

To run the live staging integration test:

```bash
SIFT_STAGING_LIVE=1 pnpm -C packages/sift test
```

### Intent normalization

```ts
import { normalizeIntent } from "@oxdeai/sift";
```

Builds:

```json
{
  "type": "EXECUTE",
  "tool": "<receipt.tool>",
  "params": { "...": "..." }
}
```

### State normalization

```ts
import { normalizeState } from "@oxdeai/sift";
```

Builds a deterministic state object suitable for later canonicalization and hashing.

### Authorization construction

```ts
import { receiptToAuthorization } from "@oxdeai/sift";
```

Builds an unsigned `AuthorizationV1` payload plus the signing payload ready for Ed25519 signing.

## Example

```ts
import {
  verifyReceipt,
  normalizeIntent,
  normalizeState,
  receiptToAuthorization,
} from "@oxdeai/sift";

// publicKeyRaw is the raw 32-byte key decoded from the JWKS x field for the
// matching kid, after confirming the key is not revoked in the KRL.
const verified = verifyReceipt(receipt, {
  publicKeyRaw: jwksXDecoded,        // Uint8Array or base64url string (JWKS x field)
  requireAllowDecision: true,
  maxAgeMs: 30_000,                  // configurable per deployment; treat as a security parameter
});

if (!verified.ok) {
  throw new Error(`${verified.code}: ${verified.message}`);
}

const intentResult = normalizeIntent({
  receipt: verified.receipt,
  params: {
    amount: 500,
    currency: "USD",
    destination: "acct_9f3a",
  },
});

if (!intentResult.ok) {
  throw new Error(`${intentResult.code}: ${intentResult.message}`);
}

const stateResult = normalizeState({
  state: {
    available_budget: 10000,
    account_status: "active",
    prior_transfers_today: 2,
  },
  requiredKeys: ["available_budget", "account_status"],
});

if (!stateResult.ok) {
  throw new Error(`${stateResult.code}: ${stateResult.message}`);
}

const authResult = receiptToAuthorization({
  receipt: verified.receipt,
  intent: intentResult.intent,
  state: stateResult.state,
  issuer: "oxdeai.pdp.local",
  audience: "pep-gateway.local",
  keyId: "main-1",
  ttlSeconds: 30,
});

if (!authResult.ok) {
  throw new Error(`${authResult.code}: ${authResult.message}`);
}

// authResult.authorization.signature.sig is "" - sign it before use.
// authResult.signingPayload is AuthorizationV1 with signature.sig absent.
// Sign sift_canonical(signingPayload) with Ed25519 → base64url, no padding.
console.log(authResult.authorization);
console.log(authResult.signingPayload);
```

## Build

From repo root:

```bash
pnpm -C packages/sift build
```

## Typecheck

```bash
pnpm -C packages/sift typecheck
```

## Tests

```bash
pnpm -C packages/sift test
```

## Design notes

### Why local verification only?

A runtime dependency on remote receipt verification weakens the execution boundary and introduces availability-dependent trust decisions.

This adapter verifies receipts locally using the supplied Ed25519 public key.

### Why explicit params and explicit state?

OxDeAI authorization is bound to:

```text
(intent, state, policy) → ALLOW | DENY
```

If params or state are guessed, omitted, or defaulted, the authorization loses determinism.

### Why `auth_id = receipt.nonce`?

Replay identity must be explicit and stable.

This adapter maps:

```text
receipt.nonce → AuthorizationV1.auth_id
```

No generated UUIDs. No mutation. No hidden prefixes.

### Why `ensure_ascii=True`?

The Sift staging verifier canonicalizes payloads with Python's `json.dumps(ensure_ascii=True)`.
This escapes every non-ASCII UTF-16 code unit as `\uXXXX`, including both halves of surrogate pairs
for supplementary characters. The TypeScript implementation must match this exactly so that hashes
computed locally are identical to those the Sift service produces.

### Why raw 32-byte keys instead of PEM?

The Sift JWKS endpoint distributes Ed25519 public keys as raw 32-byte material in the `x` field
(RFC 8037 OKP). Accepting the key in that form directly - rather than requiring a PEM-wrapped
derivative - eliminates a conversion step and removes any ambiguity about which encoding is
authoritative at the Sift contract boundary.

## Related docs

* `../../docs/adapters/sift.md`
* `../../docs/spec/authorization-v1.md`
* `../../docs/spec/pep-gateway-v1.md`
* `../../docs/spec/verification-v1.md`
* `../../docs/spec/canonicalization-v1.md`

## Invariant

```text
No valid AuthorizationV1
→ no execution path
```
