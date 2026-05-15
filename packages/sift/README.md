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

**KRL payload integrity limitation.** `SiftHttpKeyStore` checks whether a `kid` appears in the fetched KRL but does NOT verify a cryptographic signature over the KRL payload itself. KRL payload integrity depends on transport security (HTTPS to a trusted endpoint). A compromised intermediary could return a modified KRL that omits specific revoked kids. Unknown and revoked kids still fail closed. Production deployments requiring cryptographic revocation integrity must wait for a signed KRL contract from Sift.

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

// Staging (development / testing only — NOT for production):
const store = createStagingKeyStore();
await store.refresh();
// Note: createStagingKeyStore() throws if NODE_ENV === "production".
// Use new SiftHttpKeyStore({ jwksUrl, krlUrl }) with your production endpoints.

// Production:
const prodStore = new SiftHttpKeyStore({
  jwksUrl: "https://your-production-sift-host/sift-jwks.json",
  krlUrl:  "https://your-production-sift-host/sift-krl.json",
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
