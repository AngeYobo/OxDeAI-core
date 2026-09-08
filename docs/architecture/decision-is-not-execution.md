# Decision Is Not Execution

**Status:** Architecture documentation (non-normative)
**Applies to:** OxDeAI v1.x, packages/core, packages/guard, packages/sift
**Branch context:** after `feat/sift-production-hardening` merge

---

## Contents

1. [Problem Framing](#1-problem-framing)
2. [OxDeAI Architecture](#2-oxdeai-architecture)
3. [Boundary Enforcement Model](#3-boundary-enforcement-model)
4. [Sift Integration Model](#4-sift-integration-model)
5. [Cryptographic Enforcement](#5-cryptographic-enforcement)
6. [Adversarial Scenarios](#6-adversarial-scenarios)
7. [Explicit Limitations](#7-explicit-limitations)
8. [Current Production-Readiness State](#8-current-production-readiness-state)
9. [Conclusion](#9-conclusion)

---

## 1. Problem Framing

### 1.1 The predominant approach: more agents

Current agentic systems predominantly address execution risk by adding evaluation layers: supervisory agents, output classifiers, content filters, approval chains. An agent proposes an action; another agent or model decides whether to allow it. In some implementations a human is included in the loop. The pattern is additive: when a bad outcome is observed, another evaluation layer is inserted upstream.

This approach has a structural property that is worth stating precisely: the evaluation layers sit outside the execution path. A policy layer that evaluates a proposed action and returns "ALLOW" does not prevent that action from being executed through a different path. Nothing in the architecture structurally prevents downstream code from invoking the tool directly. The supervisor's judgment is advisory to the extent that the caller chooses to consult it.

This is not a criticism of the pattern — it is a description of its trust model. Supervisor-based architectures assume that callers are cooperative and that no component bypasses the evaluation chain. That assumption may hold in controlled environments with trusted codebases. It does not hold at the execution boundary when the threat model includes a compromised agent, an attacker with partial system access, or code that was authorized at the wrong level.

### 1.2 Why tool approval is insufficient

Tool-level approval grants permission to use a tool class. A system that approves `payments_api` does not constrain the parameters passed to it. Approving the tool and approving the specific action the tool will take are different operations. The approval is categorical; the execution is specific.

In the absence of parameter binding, an attacker who can influence the parameters of an approved tool call — or who can replay an authorization token obtained for one parameter set against a different execution — has bypassed the policy intent while remaining within its literal scope.

### 1.3 Why policy engines alone are insufficient

A policy engine evaluates `(intent, state, policy) → ALLOW | DENY`. The evaluation is correct for the inputs it receives at evaluation time. The problem is that nothing in a policy engine architecture structurally guarantees that the inputs at evaluation time are the same as the inputs at execution time. An agent could evaluate a low-cost operation, receive ALLOW, then execute a different operation using the resulting authorization.

The policy engine makes the correct decision for what it was asked. The execution boundary problem is not in the engine — it is in the gap between evaluation and execution.

### 1.4 The execution boundary as the security boundary

The fundamental position of OxDeAI is that the execution boundary is the appropriate place to enforce authorization. Not upstream of it, not alongside it — at it. The enforcement point must be:

- structurally non-bypassable: the protected deployment must ensure that no execution path bypasses the enforcement point
- cryptographically binding: the artifact authorizing execution must commit to the specific action, the specific state, and the specific target
- single-use: the artifact must not be reusable across invocations
- fail-closed: any ambiguity, missing artifact, or verification failure must block execution

These properties cannot be achieved by adding more evaluation layers. They require a different architectural property: the execution target refuses to execute without a valid, specific, non-replayed authorization from a trusted issuer. Everything upstream of that refusal is governance; the refusal itself is enforcement.

---

## 2. OxDeAI Architecture

### 2.1 Proposal vs. execution separation

OxDeAI separates two concerns that are often conflated:

- **Policy decision**: should this action be allowed, given this intent, state, and policy?
- **Execution authorization**: is this specific invocation authorized to execute, given this signed artifact?

The `PolicyEngine` (`packages/core/src/policy/PolicyEngine.ts`) implements the decision function:

```
evaluatePure(intent, state) → { decision, reasons, authorization?, nextState? }
```

When the decision is ALLOW, the engine returns an `Authorization` artifact and a `nextState`. The artifact commits to the evaluated intent and state via cryptographic hashes. When the decision is DENY, no artifact is produced and no state transition occurs.

The returned `Authorization` is not a permission in the advisory sense. It is a signed artifact that the PEP must independently verify before execution can proceed. The engine's ALLOW decision and the PEP's execution authorization are coupled by the artifact but evaluated independently.

A policy decision is an evaluation result. An `AuthorizationV1` artifact is an execution capability.

### 2.2 AuthorizationV1

`AuthorizationV1` is the canonical OxDeAI execution authorization artifact. Its schema, from `docs/spec/artifacts/authorization-v1.md` and the implementation in `packages/sift/src/receiptToAuthorization.ts`:

```json
{
  "version":      "AuthorizationV1",
  "auth_id":      "<single-use identifier>",
  "issuer":       "<issuer identity>",
  "audience":     "<target PEP identifier>",
  "decision":     "ALLOW",
  "intent_hash":  "<sha256 hex, 64 chars>",
  "state_hash":   "<sha256 hex, 64 chars>",
  "policy_id":    "<policy identifier>",
  "issued_at":    1712448000,
  "expires_at":   1712448060,
  "signature": {
    "alg": "ed25519",
    "kid": "<key identifier>",
    "sig": "<base64url-no-padding Ed25519 signature>"
  }
}
```

Each field carries a specific verification obligation at the PEP:

| Field | Verification obligation |
|-------|------------------------|
| `version` | Must be `"AuthorizationV1"` |
| `auth_id` | Must not have been previously consumed (single-use enforcement) |
| `issuer` | Must match a trusted issuer in the configured key set |
| `audience` | Must exactly equal the PEP's own configured audience identifier |
| `decision` | Must be `"ALLOW"`; any other value is rejected |
| `intent_hash` | Must equal SHA-256 of the canonical form of the action about to execute |
| `state_hash` | Must equal SHA-256 of the canonical form of the current execution state |
| `policy_id` | Must match the expected policy identifier |
| `issued_at` | Must be a valid Unix timestamp (integer) |
| `expires_at` | Must be in the future at the time of verification. Internal TypeScript implementations map this wire field to an `expiry` field during parsing; the semantic meaning is identical. |
| `signature.alg` | Must be a supported algorithm (`"ed25519"` in Sift-path, `"Ed25519"` in core path) |
| `signature.kid` | Must identify a key in the trusted key set for the issuer |
| `signature.sig` | Must verify the canonical signing payload under the resolved key |

Note the algorithm field naming: in the Sift adapter path, `signature.alg` is the literal string `"ed25519"` (lowercase), which is the Sift contract runtime identifier. In `packages/core`'s `verifyAuthorization`, the recognized algorithm is `"Ed25519"` (capitalized). These are distinct surfaces for the same underlying algorithm. The Sift JWKS metadata field `alg: "EdDSA"` is a third label used for key-discovery metadata per RFC 8037 and is not the runtime literal. These three labels are not interchangeable; confusing them would cause signature verification to fail.

### 2.3 Deterministic verification

`verifyAuthorization` in `packages/core/src/verification/verifyAuthorization.ts` implements structural verification with explicit violation collection. Violations are sorted by code before return. The function never throws — it returns a `VerificationResult` with `ok: boolean` and a violations array.

In `strict` mode (required by `packages/guard`), empty `trustedKeySets` is an immediate failure with code `TRUSTED_KEYSETS_REQUIRED`. This prevents silent operation without key material.

`requireSignatureVerification: true` (also required by `packages/guard`) causes missing key material to produce a `AUTH_TRUST_MISSING` violation rather than being silently skipped.

The full violation space from the implementation:

```
AUTH_DECISION_INVALID     AUTH_MISSING_FIELD        AUTH_EXPIRED
AUTH_ISSUER_MISMATCH      AUTH_AUDIENCE_MISMATCH    AUTH_POLICY_ID_MISMATCH
AUTH_REPLAY               AUTH_TRUST_MISSING        AUTH_KID_UNKNOWN
AUTH_KEY_INACTIVE         AUTH_SIGNATURE_INVALID    AUTH_ALG_UNSUPPORTED
TRUSTED_KEYSETS_REQUIRED
```

### 2.4 Canonicalization-v1

All hash inputs — `intent_hash`, `state_hash`, and signing payloads — must be canonicalized before hashing or signing. `canonicalization-v1.md` defines the requirements:

- key-sorted by byte-wise UTF-8 order
- no insignificant whitespace
- UTF-8 encoded output without BOM
- integers only: floats, NaN, and Infinity are rejected
- safe integer range only: `[-2^53+1, +2^53-1]`; values outside this range must be encoded as strings
- forbidden types: functions, symbols, undefined, Date, Map, Set, custom class instances
- duplicate keys rejected after NFC normalization

The Sift adapter uses a distinct but related canonicalization: the Sift wire format equivalent of Python's `json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=True)`, implemented in `packages/sift/src/siftCanonical.ts`. The `ensure_ascii=True` requirement causes every UTF-16 code unit above U+007F to be escaped as `\uXXXX` (lowercase four-digit hex). Supplementary characters (U+10000 and above) are each encoded as two surrogate escapes. This is not the same behavior as UTF-8 passthrough; the distinction matters for cross-language parity with the Sift service.

The contract-vector tests in `packages/sift/test/contract-vector.test.ts` lock in the exact escaped output for:
- U+00E9 (`é` → `\u00e9`)
- U+0100 (`Ā` → `\u0100`)
- U+1F600 (`😀` → `\ud83d\ude00`)

### 2.5 Intent binding

`intent_hash` is the SHA-256 of the canonical form of the intent object:

```json
{ "type": "EXECUTE", "tool": "<tool>", "params": { ... } }
```

Before execution, the PEP recomputes this hash from the action it is about to execute and compares it to `authorization.intent_hash`. Any discrepancy — a changed parameter, a different tool, a reordered key in the params object (impossible to achieve since canonicalization normalizes order) — causes the comparison to fail and execution to be blocked.

In `packages/guard/src/guard.ts`, the guard recomputes the intent hash before execution and blocks on mismatch:

```typescript
computedIntentHash = intentHash(intent);
if (computedIntentHash !== authorization.intent_hash) {
  throw new OxDeAIAuthorizationError(
    "Intent hash mismatch: computed hash does not match authorization.intent_hash. Execution blocked."
  );
}
```

The `intentHash` function calls `canonicalJson(intent)` before hashing. A canonicalization failure throws, and the guard treats that as an authorization failure — fail-closed.

### 2.6 State binding

`state_hash` is the SHA-256 of the canonical form of the state snapshot at authorization time. At execution time, the guard recomputes the state hash from the current state and verifies it matches the artifact:

```typescript
actualStateHash = config.engine.computeStateHash(state);
if (actualStateHash !== expectedStateHash) {
  throw new OxDeAIAuthorizationError(
    "Authorization state_hash does not match the current execution-time state snapshot. Execution blocked."
  );
}
```

State binding prevents using an authorization obtained under one policy state against a changed state. If the policy state changes between authorization issuance and execution — for example, a spending budget is consumed, a permission is revoked, or a kill switch is activated — the recomputed state hash will not match and execution will be blocked.

The check occurs after signature verification and before the CAS state commit, so a stale authorization can never produce a state side effect.

### 2.7 Audience binding

`audience` is part of the signed payload. The PEP verifies exact equality between `authorization.audience` and its own configured audience string:

```typescript
if (opts?.expectedAudience !== undefined && auth.audience !== opts.expectedAudience) {
  violations.push({ code: "AUTH_AUDIENCE_MISMATCH", ... });
}
```

Audience binding prevents cross-service replay: an authorization issued for `payments-service-prod` will be rejected by `reporting-service-prod`. This applies regardless of whether all other fields are valid.

### 2.8 Expiry enforcement

`expires_at` is a Unix timestamp in seconds. The PEP verifies `now < expires_at`:

```typescript
} else if (now >= auth.expiry) {
  violations.push({ code: "AUTH_EXPIRED", ... });
}
```

The default TTL in the Sift adapter path is 30 seconds (`receiptToAuthorization.ts`, `DEFAULT_TTL_SECONDS = 30`). This is configurable. Short TTLs reduce the window during which a stolen or intercepted authorization artifact could be replayed before the single-use check catches it.

### 2.9 Replay protection

`auth_id` is a single-use token. The guard's `consumeAuthId` is atomic: it checks whether the id has been consumed and marks it consumed in a single operation, with no read-then-write race window.

Two implementations exist in `packages/guard`:

**In-memory** (`createInMemoryReplayStore`): two `Set` objects, one for auth ids, one for delegation ids. Appropriate for single-process, single-instance deployments and tests. Not restart-durable; consumed ids are lost on process restart.

**Redis** (`createRedisReplayStore`): uses `SET key value NX EX ttl` — a single atomic Redis command. Across any number of guard instances sharing the same Redis cluster, exactly one caller receives `"OK"` for a given key. The key schema is `replay:auth:<auth_id>` and `replay:delegation:<delegation_id>`. TTL is computed as `max(1, expires_at - now)`. Any Redis error is re-thrown; the guard catches it and blocks execution. There is no fallback.

The fail-closed property of the replay store is explicit in the implementation:

> "Any Redis error (network failure, timeout, cluster failover) is re-thrown. The guard catches this and raises `OxDeAIAuthorizationError`, blocking execution. There is no fallback, no best-effort path, no silent memory store."

In `packages/guard/src/guard.ts`:

```typescript
try {
  authConsumed = await replayStore.consumeAuthId(
    authorization.auth_id, { expiry: authorization.expiry }
  );
} catch (err) {
  throw new OxDeAIAuthorizationError(
    `Replay store unavailable: ... Execution blocked.`
  );
}
if (!authConsumed) {
  throw new OxDeAIAuthorizationError(
    "Authorization replay detected: auth_id already consumed. Execution blocked."
  );
}
```

`consumeAuthId` is called before `strictVerifyAuthorization` in the guard but after the policy engine returns ALLOW. This ordering means a replay can be detected without performing the more expensive signature verification — but note that in the Sift adapter path (reference PEP gateway), the replay check is deliberately placed last (after all other checks) to prevent an attacker from burning valid auth ids by replaying them before complete verification passes. If replay consumption occurs before full verification, invalid or attacker-crafted artifacts could intentionally consume otherwise valid auth_ids, creating a denial-of-service condition. The ordering choice involves a tradeoff and both implementations are explicit about it.

### 2.10 Fail-closed semantics

The fail-closed property appears throughout the implementation as a repeated explicit guarantee:

- Missing authorization artifact → `OxDeAIAuthorizationError` (execution blocked)
- Missing `nextState` from policy engine → `OxDeAIAuthorizationError`
- State store returns no version → `OxDeAIAuthorizationError`
- `consumeAuthId` throws → `OxDeAIAuthorizationError`
- Signature verification fails → `OxDeAIAuthorizationError`
- Intent hash mismatch → `OxDeAIAuthorizationError`
- State hash mismatch → `OxDeAIAuthorizationError`
- CAS `setState` returns `false` (concurrent modification) → `OxDeAIConflictError`
- Canonicalization failure during hash computation → `OxDeAIAuthorizationError`
- Normalization failure → `OxDeAINormalizationError`

The `execute()` callback is never called unless all preceding checks pass without exception. There is no partial authorization path.

---

## 3. Boundary Enforcement Model

### 3.1 Non-bypassable PEP

`packages/guard` implements the PEP as a guard function that wraps the execute callback. The execute callback is only invoked at step 9 of an 11-step sequence, after signature verification, intent binding, state binding, and replay protection have all passed. There is no code path that reaches step 9 without passing steps 1–8.

The gateway variant (`packages/guard/src/gateway.ts`, `createPepGatewayExecutor`) implements an HTTP-level enforcement boundary with the same verification sequence. It proxies to the protected execution target only after all verification steps pass, and injects the `x-internal-executor-token` header it requires.

`packages/spec/enforcement/pep-gateway-v1.md` states the core invariant normatively:

> A protected action MUST NOT be reachable without valid authorization verified by the PEP Gateway.

"Non-bypassable" in OxDeAI refers to the enforced execution topology of the protected deployment: protected execution targets must only be reachable through the PEP-controlled path. The protocol cannot compensate for infrastructure that exposes execution paths outside the enforcement boundary. A deployment that makes a protected execution target directly reachable has departed from the boundary model; the protocol cannot detect or prevent that.

### 3.2 Upstream isolation

The protected execution target requires the `x-internal-executor-token` header. This token is generated at startup with `randomBytes(32)` and is known only to the PEP. The protected execution target has no knowledge of `AuthorizationV1`, policy, or the Sift receipt — it trusts only the token.

In `examples/reference-sift-oxdeai/apps/upstream/server.ts`:

```typescript
const token = req.headers["x-internal-executor-token"];
if (token !== config.internalToken) {
  return jsonResponse(res, 403, {
    ok: false,
    code: "FORBIDDEN",
    message: "Direct access not permitted. Route through PEP Gateway.",
  });
}
```

The token is never returned in any response body and is never logged. This means that any caller who does not transit through the PEP — including a compromised agent, an API caller who knows the protected execution target's address, or any component upstream of the PEP — cannot produce a request the protected execution target will honor.

In `packages/guard/src/gateway.ts`, the header constant is defined as:

```typescript
export const INTERNAL_EXECUTOR_TOKEN_HEADER = "x-internal-executor-token";
```

And is injected unconditionally by the PEP on every call to the protected execution target:

```typescript
headers: {
  [INTERNAL_EXECUTOR_TOKEN_HEADER]: config.internalExecutorToken,
}
```

The upstream isolation model assumes that the protected execution target is not directly reachable from outside the PEP's network context. The token mechanism provides a defense-in-depth layer; the primary isolation should be network-level (the protected execution target should not expose its port externally). These are not substitutes for each other.

### 3.3 TOCTOU prevention via CAS state commit

The guard uses compare-and-swap semantics for state transitions. `setState(nextState, version)` returns `false` if the version has changed since `getState()` was called at the start of the guard invocation. In that case:

```typescript
const casOk = await config.setState(nextState, version);
if (!casOk) {
  throw new OxDeAIConflictError(
    "State version mismatch: concurrent modification detected. Execution blocked."
  );
}
```

This prevents a time-of-check to time-of-use race where a concurrent execution modifies the state between the policy evaluation and the state commit. The CAS occurs before `execute()` so that no side effect is produced on a conflict.

### 3.4 The execution path is a single choke point

The full guard execution sequence (standard path) is:

```
1.  getState() + version                   [fail closed if version absent]
2.  normalize(action) → Intent             [fail closed on normalization error]
3.  engine.evaluatePure(intent, state)     [fail closed if engine throws]
4.  DENY? → throw OxDeAIDenyError          [no execution]
5.  authorization artifact required?       [fail closed if absent]
6.  nextState required?                    [fail closed if absent]
6a. consumeAuthId atomic check             [fail closed if store unavailable]
6b. strictVerifyAuthorization              [fail closed on any violation]
    (mode:strict, trustedKeySets,
     requireSignatureVerification:true,
     expectedAudience,
     expectedPolicyId = engine.computePolicyId())
    [#301: the expected policy id comes from trusted engine configuration,
     never from the artifact being verified. No expectedIssuer is asserted
     here — key resolution is already issuer-scoped via trustedKeySets.]
6c. intent_hash recompute + compare        [fail closed on mismatch or canonicalization error]
6d. state_hash recompute + compare         [fail closed on mismatch]
7.  CAS setState(nextState, version)       [fail closed if CAS fails]
8.  beforeExecute hook (optional)
9.  execute()                              [← first and only point of execution]
10. onDecision audit hook
11. return result
```

Steps 1–8 are purely verification and state preparation. Step 9 is the only point at which side effects occur. Any failure in steps 1–8 results in an exception that propagates to the caller — `execute()` is never called.

---

## 4. Sift Integration Model

### 4.1 Governance vs. enforcement: two distinct responsibilities

Sift operates as a governance and policy decision layer. It receives an action proposal from an agent, evaluates it against configured policies, and returns a signed receipt indicating ALLOW or DENY.

OxDeAI operates as an execution authorization and enforcement layer. It requires a valid `AuthorizationV1` artifact before any side-effecting action may execute.

These are distinct responsibilities. Sift produces a governance decision. OxDeAI enforces an execution boundary. Neither can substitute for the other, and neither is subordinate to the other — they operate on different artifacts at different points in the pipeline.

```
Agent
  │
  ▼
Sift                          ← governance: (proposal, policy) → receipt
  │  Ed25519-signed receipt
  ▼
Sift→OxDeAI adapter           ← verify, normalize, bind
  │  AuthorizationV1
  ▼
PEP Gateway                   ← enforcement: verify artifact, block or allow
  │
  ▼
Protected execution target
```

A Sift receipt is not an `AuthorizationV1`. It cannot trigger execution directly. No component in the chain should treat a receipt as execution authorization.

### 4.2 The adapter pipeline

The adapter (`examples/reference-sift-oxdeai/packages/adapter/index.ts`) implements a five-step pipeline. Each step fails closed on any error.

**Step 1: Local receipt verification**

```typescript
const verifyResult = await verifyReceiptWithKeyStore(receipt, {
  kid: kidAndReceipt.kid,
  keyStore: this.keyStore,
  requireAllowDecision: true,
});
```

`verifyReceiptWithKeyStore` from `packages/sift` performs:
1. Structural validation (field presence and types)
2. Version check (only `"1.0"` is accepted)
3. `receipt_hash` integrity: SHA-256 of sift-canonical JSON of receipt excluding both `signature` and `receipt_hash`
4. Ed25519 signature verification: over sift-canonical JSON of receipt excluding `signature` only (`receipt_hash` IS in signed scope)
5. ALLOW decision enforcement
6. Freshness validation (default maximum age 30 seconds; maximum future skew 5 seconds)

KRL resolution (in `verifyReceiptWithKeyStore`):
1. Reject empty `kid`
2. Check KRL — if revoked → `REVOKED_KID`
3. Look up `kid` in JWKS cache
4. If not found: call `keyStore.refresh()` once; re-check KRL; re-check lookup
5. If still not found → `UNKNOWN_KID`

The receipt_hash computation excludes both `signature` and `receipt_hash` from the payload. The signature scope excludes only `signature` — `receipt_hash` is included, which means the hash is covered by the signature and its integrity is established transitively. Verification order enforces this: hash check before signature verification.

**Step 2: Intent normalization**

```typescript
const intentResult = normalizeIntent({ receipt: vr.receipt, params });
```

`normalizeIntent` constructs:

```json
{ "type": "EXECUTE", "tool": "<receipt.tool>", "params": { ... } }
```

The `params` are supplied by the adapter from the execution context. They are not extracted from the receipt. The receipt does not contain parameter values; the adapter is responsible for supplying them. The JSDoc on `normalizeIntent` is explicit:

> The adapter MUST supply params explicitly — a receipt alone is never sufficient.

Normalization rejects: floats, NaN, Infinity, bigint, symbol, undefined, functions, Date, Map, Set, Buffer, class instances (checked via prototype), and empty string keys. All output objects use `Object.create(null)` to prevent prototype pollution.

**Step 3: State normalization**

```typescript
const stateResult = normalizeState({ state });
```

State is supplied by the adapter from the execution environment. The receipt carries no state context. Same type restrictions as `normalizeIntent`.

**Step 4: Authorization construction**

```typescript
const authResult = receiptToAuthorization({
  receipt: vr.receipt,
  intent: intentResult.intent,
  state: stateResult.state,
  issuer, audience, keyId, ttlSeconds, now,
});
```

Field binding:

```
auth_id       ← receipt.nonce
policy_id     ← receipt.policy_matched
intent_hash   ← SHA-256(sift-canonical(intent))
state_hash    ← SHA-256(sift-canonical(state))
audience      ← caller-supplied (from trusted adapter config)
issuer        ← caller-supplied
signature.alg ← "ed25519"  (Sift contract runtime literal, lowercase)
signature.sig ← ""         (placeholder; signing is step 5)
```

`receiptToAuthorization` returns both `authorization` (with empty `sig`) and `signingPayload` (with `sig` key absent entirely). The signing preimage is `authorization` with `signature.sig` absent; `signature.alg` and `signature.kid` are present in the preimage.

**Step 5: Ed25519 signing**

```typescript
const preimage = siftCanonicalJsonBytes(authResult.signingPayload);
const sigBuf = sign(null, preimage, this.config.privateKey);
```

The preimage is the sift-canonical JSON bytes of the signing payload. Signing is real Ed25519 — not mocked.

### 4.3 What Sift guarantees

Sift's signed receipt guarantees that a specific **tool** (identified by `receipt.tool`) matched a specific **policy** (identified by `receipt.policy_matched`) for a specific **action type** (identified by `receipt.action`) at a specific time, as evaluated by Sift's policy engine.

Sift's signature covers: `receipt_version`, `tenant_id`, `agent_id`, `action`, `tool`, `decision`, `risk_tier`, `timestamp`, `nonce`, `policy_matched`, and `receipt_hash`. The `receipt_hash` in turn covers all those fields.

Sift's signature does NOT cover: the specific parameter values that were passed to Sift for evaluation. The `SiftReceipt` type has no `params` or `params_hash` field. This is a structural property of the receipt format, not an implementation choice — `packages/sift/test/parameter-binding.test.ts` (tests PB-1 through PB-4) documents this explicitly.

### 4.4 What OxDeAI guarantees at the PEP

The PEP verifies that:

- the `AuthorizationV1` was signed by a trusted adapter key (not the Sift key — by the adapter's own key)
- the `audience` matches the PEP's own identity
- the `auth_id` has not been used before
- the `intent_hash` matches SHA-256 of the canonical form of the action being submitted for execution now
- the `state_hash` matches SHA-256 of the current execution state
- the artifact has not expired

The PEP does not have any relationship with the Sift service at runtime. There are no network calls to Sift during execution. The Sift signing key is not trusted by the PEP — the PEP trusts only the adapter's signing key. The chain of custody runs: Sift receipt → adapter verification → adapter signing → PEP verification.

### 4.5 The adapter as the security boundary between Sift and OxDeAI

The adapter is the component that bridges governance (Sift) and enforcement (OxDeAI). Its security properties:

- It verifies the Sift receipt locally, with no runtime network dependency on Sift.
- It injects `audience` from trusted configuration, not from the receipt.
- It injects `params` from the execution context, not from the receipt.
- It maps `nonce → auth_id` explicitly.
- It produces a signed `AuthorizationV1` artifact that the PEP can verify independently.

The adapter's private key is the trust anchor for the PEP. If the adapter's key is compromised, the PEP will accept authorizations signed with that key. Adapter key management (rotation, HSM, access control) is outside the scope of this document.

### 4.6 No runtime dependency on Sift during execution

Once the adapter has produced a signed `AuthorizationV1`, the Sift service plays no further role in the execution path. The PEP verifies the adapter's signature — not Sift's. If Sift is unavailable at execution time, this has no effect on verification. If Sift's endpoint is compromised after receipt issuance, this also has no effect on verification, because the PEP does not call Sift.

This property is explicit in `docs/adapters/sift.md`:

> The adapter MUST NOT call `/verify-receipt` or any remote Sift endpoint in the runtime execution path. Remote verification introduces a network dependency that would produce indeterminate outcomes on failure, violating the fail-closed invariant.

---

## 5. Cryptographic Enforcement

### 5.1 Ed25519

The signing algorithm used throughout is Ed25519. The choice is conventional for this class of protocol: deterministic signatures, small key and signature sizes, fast verification, no requirement for random nonce material at signing time (unlike ECDSA).

Key representations:
- In the JWKS, Sift distributes raw 32-byte Ed25519 public key material in the `x` field (base64url, no padding), per RFC 8037 OKP format.
- In `AuthorizationV1`, the key is identified by `kid` and resolved from a `TrustedKeySet` by `(issuer, kid, alg)`.
- `publicKeyFromRaw` in `packages/sift/src/siftCanonical.ts` wraps the raw 32 bytes in SPKI DER format using the hardcoded OID prefix `302a300506032b6570032100`, which is the standard DER encoding for Ed25519 SPKI. This is how Node.js crypto accepts raw Ed25519 keys.

### 5.2 Signing payloads and canonicalization

The signing preimage for both Sift receipts and `AuthorizationV1` artifacts is the sift-canonical JSON byte sequence of the payload with the signature field absent.

For Sift receipts:
- **Signed scope**: receipt minus `signature` (receipt_hash IS in scope)
- **Hash scope for receipt_hash**: receipt minus `signature` AND minus `receipt_hash`

For `AuthorizationV1` (Sift path):
- **Signed scope**: authorization minus `signature.sig` (`signature.alg` and `signature.kid` are present)

The distinction between `receipt_hash` and `intent_hash` is important enough to state explicitly:

- `receipt_hash` is a SHA-256 over the Sift receipt payload. It is part of the Sift wire protocol and covered by Sift's signature.
- `intent_hash` is a SHA-256 over the canonical form of the intent object that the adapter constructed. It is part of the `AuthorizationV1` and covered by the adapter's signature.

These are independent hashes over different objects. `receipt_hash` does not prove anything about `intent_hash`, and `intent_hash` does not prove anything about the Sift receipt beyond what the adapter has committed to.

### 5.3 Ensure-ASCII behavior

The Sift wire format uses `ensure_ascii=True` canonicalization. The implementation in `packages/sift/src/siftCanonical.ts` implements this exactly:

```typescript
function applyEnsureAscii(json: string): string {
  let s = "";
  for (let i = 0; i < json.length; i++) {
    const c = json.charCodeAt(i);
    s += c > 0x7f ? "\\u" + c.toString(16).padStart(4, "0") : json[i];
  }
  return s;
}
```

This processes the string character by character, operating on UTF-16 code units. A supplementary character (U+10000 and above) is represented in JavaScript as a surrogate pair — two UTF-16 code units, each above 0x7F — so each is individually escaped as `\uXXXX`. This matches Python's `ensure_ascii=True` behavior exactly, where each member of a surrogate pair is also escaped independently.

The consequence is that `😀` (U+1F600) becomes `\ud83d\ude00` in the canonical JSON, not raw UTF-8 bytes. This matters for cross-language hash parity: any implementation that handles supplementary characters differently will produce a different hash for receipts or authorization payloads containing such characters.

### 5.4 Deterministic hashing

Because canonicalization is deterministic — same input always produces same output — the SHA-256 hashes of canonical forms are themselves deterministic. `intent_hash` for a given `{type, tool, params}` object is invariant under key insertion order, whitespace variation, or any other surface variation in the input representation.

This is tested in the property tests: `packages/sift/test/receiptToAuthorization.property.test.ts` verifies that `intent_hash` is consistent across repeated calls with the same inputs, and that it changes when any field changes.

### 5.5 Trusted key sets and the trust model

`packages/core` defines `KeySet` as a typed structure containing issuer identity, key identifier, algorithm, and PEM-encoded public key. The guard requires non-empty `trustedKeySets` at construction time:

```typescript
if (!trustedKeySets || trustedKeySets.length === 0) {
  throw new OxDeAIGuardConfigurationError(
    "trustedKeySets are required for authorization verification and must not be empty."
  );
}
```

This check at construction time means a guard instance without key material cannot be created. It is not possible to construct a guard that silently skips signature verification.

Key resolution in `verifyAuthorization` uses `findKeyInKeySets(trusted, auth.issuer, sigKid, "Ed25519")`. The lookup is by `(issuer, kid, alg)`. An authorization from an unknown issuer or with an unknown kid for a known issuer fails with `AUTH_KID_UNKNOWN`. An authorization whose key is outside its active time window fails with `AUTH_KEY_INACTIVE`.

### 5.6 KRL enforcement

`SiftHttpKeyStore` maintains an in-memory revoked kids set populated from the Sift KRL endpoint. On each receipt verification, `isKidRevoked(kid)` is checked before any key lookup or signature verification. A revoked kid returns `REVOKED_KID` immediately.

The KRL and JWKS are fetched concurrently, and both must parse successfully before either cache is updated (atomic swap). If either fetch fails, the previous state is preserved and a `KeyStoreError` is thrown.

KRL payload integrity limitation: see §7.2.

---

## 6. Adversarial Scenarios

The adversarial scenarios below are tested in `examples/reference-sift-oxdeai/test/integration.test.ts` (8/8 pass) and in `packages/sift/test/parameter-binding.test.ts`, `packages/guard/src/test/guard.pep-conformance.test.ts` (GPC-1 through GPC-11), and the property test suites.

### 6.1 Replay

**Scenario:** An attacker obtains a valid `AuthorizationV1` (from network capture, log extraction, or side-channel) and submits it a second time.

**Enforcement:** `consumeAuthId` is called before execution. The first call marks the auth_id as consumed and returns `true`. The second call returns `false`. The guard throws `OxDeAIAuthorizationError("Authorization replay detected: auth_id already consumed. Execution blocked.")`. The PEP returns HTTP 403 `REPLAY_DETECTED`.

**Residual exposure:** If the replay store is in-memory and the process restarts, previously consumed ids are forgotten. Redis-backed stores do not have this property.

### 6.2 Bypass — direct upstream access

**Scenario:** An attacker with network access to the protected execution target's address calls the execution endpoint directly, supplying no `AuthorizationV1` and no PEP interaction.

**Enforcement:** The protected execution target requires `x-internal-executor-token` matching the token generated at startup. The attacker does not know this token. The protected execution target returns HTTP 403 `FORBIDDEN` for every request without the correct token. The token is generated from 32 random bytes, making successful guessing computationally infeasible under standard cryptographic assumptions.

**Test:** `examples/reference-sift-oxdeai/test/integration.test.ts` test "BYPASS" verifies that `POST /execute` on the protected execution target without the token returns 403.

### 6.3 Intent mismatch — parameter substitution

**Scenario:** An attacker obtains a valid `AuthorizationV1` for `{tool: "transfer", params: {amount: 1}}` and presents it with a modified intent `{tool: "transfer", params: {amount: 1000000}}` to the PEP.

**Enforcement:** The PEP recomputes `intent_hash` from the submitted intent. The SHA-256 of the canonical form of `{amount: 1000000, ...}` differs from the SHA-256 of `{amount: 1, ...}`. The comparison fails. The PEP returns 403 `INTENT_HASH_MISMATCH`.

**Residual exposure:** See §7.1 (parameter binding limitation). The PEP correctly prevents execution with mismatched parameters. However, the PEP cannot determine what parameters Sift evaluated when it issued the receipt.

### 6.4 State mismatch

**Scenario:** An attacker obtains authorization when the account has `account_status: "active"`. The account is suspended before the attacker attempts to use the authorization.

**Enforcement:** The state hash in the `AuthorizationV1` was computed over `{account_status: "active", ...}`. At execution time, the PEP recomputes the hash over the current state `{account_status: "suspended", ...}`. The hashes differ. The PEP returns 403 `STATE_HASH_MISMATCH`.

**Residual exposure:** The state sent to the adapter (for hashing) and the state sent to the PEP (for verification) are both supplied by the agent. A compromised agent could supply `{account_status: "active"}` to the adapter for hashing and then ensure that same value is presented to the PEP, regardless of the actual system state. The PEP's guarantee is that the intent and state at execution time match what was authorized — it cannot verify that the state accurately reflects the actual system state unless the state is derived from a trusted source independently of the agent.

### 6.5 Audience mismatch — cross-service replay

**Scenario:** An attacker obtains a valid `AuthorizationV1` issued for `payments-pep` and presents it to `data-pep`.

**Enforcement:** The `audience` field is part of the signed payload. The data PEP verifies `auth.audience === "data-pep"`. The presented artifact has `audience: "payments-pep"`. The check fails with `AUTH_AUDIENCE_MISMATCH`. The attacker cannot modify `audience` without invalidating the signature.

### 6.6 Expiry

**Scenario:** An attacker delays execution until after the authorization TTL (default 30 seconds).

**Enforcement:** The PEP verifies `now < expires_at`. After the TTL window, the check fails with `AUTH_EXPIRED`. An expired `AuthorizationV1` produces no side effects regardless of how many other fields are valid.

### 6.7 Revoked key

**Scenario:** A Sift signing key is compromised and added to the Sift KRL. An attacker uses receipts signed with the revoked key.

**Enforcement:** `verifyReceiptWithKeyStore` calls `isKidRevoked(kid)` before any key lookup or signature verification. If the kid appears in the in-memory KRL set, the verification returns `REVOKED_KID` immediately.

**Residual exposure:** The KRL is checked against the in-memory cache. If the compromise occurs between cache refreshes, the revocation will not be detected until the next `refresh()` call. Additionally: see §7.2 (KRL payload integrity limitation).

### 6.8 Malformed authorization

**Scenario:** An attacker submits an `AuthorizationV1` with missing fields, invalid types, a truncated signature, or a structurally invalid payload.

**Enforcement:** `verifyAuthorization` validates all required fields in a single pass, collecting violations. Missing `auth_id`, `intent_hash`, `state_hash`, `policy_id`, `issuer`, `audience`, `issued_at`, `expiry`, `alg`, `kid`, or `sig` each produce an `AUTH_MISSING_FIELD` violation. A signature that is not exactly 86 base64url characters (for `verifyReceipt`) produces `INVALID_SIGNATURE` before any cryptographic operation is attempted. The 86-character guard in `verifyReceipt` prevents Node.js's `Buffer.from(..., 'base64url')` from silently accepting strings with trailing garbage characters.

### 6.9 Authorization forgery

**Scenario:** An attacker constructs an `AuthorizationV1` with valid-looking fields and an arbitrary signature, without access to the adapter's private key.

**Enforcement:** `verifyAuthorization` resolves the key by `(issuer, kid, alg)` from the trusted key set. If the kid is unknown, `AUTH_KID_UNKNOWN`. If the key is known, the Ed25519 signature is verified against the canonical signing payload. A signature not produced by the adapter's private key will not verify.

---

## 7. Explicit Limitations

### 7.1 Parameter binding limitation

**This limitation exists in the current implementation and is not resolved.**

Sift receipts do not include parameter values. The Sift service evaluates a proposed action against its policies and returns a receipt attesting that `tool X` matched `policy Y` for `action type Z` at time `T`. The receipt does not contain the specific parameter values that were submitted for evaluation, and the Sift signature does not cover them.

The `SiftReceipt` type in `packages/sift/src/verifyReceipt.ts` has no `params` or `params_hash` field. This is a structural property confirmed by test PB-4:

```typescript
test("PB-4: the SiftReceipt type has no params field", () => {
  assert.ok(!Object.prototype.hasOwnProperty.call(receipt, "params"));
  assert.ok(!Object.prototype.hasOwnProperty.call(receipt, "params_hash"));
});
```

The consequence is:

- `intent_hash` in `AuthorizationV1` commits to the adapter-supplied params — what the adapter claims it will execute.
- `intent_hash` does NOT commit to the params that Sift evaluated.
- The PEP cannot determine what params Sift was asked about.
- The PEP verifies that the params at execution time match the params in the authorization artifact. It cannot verify that the adapter supplied the same params to `normalizeIntent` that were submitted to Sift.

A correctly implemented adapter supplies the same params to both. A compromised adapter can supply different params. There is no protocol-level mechanism to detect this at the receipt boundary.

The PEP does enforce that the params at execution time match the params in the `AuthorizationV1`. If an attacker attempts to execute with different params than those in the authorization, `intent_hash` will not match and execution will be blocked. This remains a real enforcement property.

The gap is specifically: the adapter could obtain an authorization from Sift for low-risk params and then construct an `AuthorizationV1` committing to high-risk params. The Sift receipt would be valid, the adapter's signature would be valid, and the PEP would verify correctly against the high-risk params.

**Future resolution path:** If the Sift protocol adds a `params_hash` field to the signed receipt, the adapter can add a verification step:

```
recompute = sha256(sift_canonical(adapter_params))
assert recompute == receipt.params_hash  → DENY if mismatch
```

Until that field exists in the Sift receipt contract, this check cannot be performed and the parameter binding gap remains. `docs/adapters/sift.md §"Parameter Binding Guarantee"` contains the full description and extension path.

### 7.2 KRL payload integrity limitation

**This limitation exists in the current implementation and is not resolved.**

`SiftHttpKeyStore` checks whether a `kid` appears in the fetched KRL, but does NOT verify a cryptographic signature over the KRL payload itself.

The KRL fetch path in `packages/sift/src/siftKeyStore.ts` (`parseKrl`):

1. Fetches the KRL endpoint over HTTPS
2. Parses the JSON body
3. Extracts `revoked_kids` as a set
4. No signature is verified over the KRL body

KRL payload integrity therefore depends on transport security (HTTPS to a trusted endpoint). A compromised intermediary — CDN edge, stale unsigned cache, or man-in-the-middle who can present a valid TLS certificate for the endpoint — could return a modified KRL that omits specific revoked kids. This would allow a revoked Sift signing key to pass the revocation check.

The current behavior:
- `kid` in `revoked_kids` → `REVOKED_KID` immediately (correct)
- `kid` not found after one refresh → `UNKNOWN_KID` (correct)
- Modification of `revoked_kids` list via compromised transport → not detectable

This is documented in the source (`parseKrl` JSDoc in `siftKeyStore.ts`) and in `docs/adapters/sift.md §"KRL payload integrity limitation"`.

**Production deployments that require cryptographic revocation integrity must wait for the Sift protocol to define and publish a KRL signing contract.** Until that contract exists, revocation guarantees depend on transport integrity and the trustworthiness of the KRL hosting endpoint. This should be disclosed in any security assessment that depends on revocation guarantees.

### 7.3 State trust model

State is supplied by the agent to both the adapter (for hashing into the `AuthorizationV1`) and the PEP (for verification). A compromised agent can supply a state snapshot that does not reflect the actual system state. The PEP's state binding guarantee is consistency between authorization-time state and execution-time state as presented by the caller, not consistency between the presented state and the authoritative system state.

For state binding to provide meaningful security, the state snapshot must be derived from a source that the agent cannot tamper with. This is a deployment requirement, not a protocol enforcement.

### 7.4 Replay store durability

The in-memory replay store (`createInMemoryReplayStore`) does not persist consumed auth ids across process restarts. After a restart, previously consumed ids become available again. An attacker who can time a restart can replay authorizations that were consumed before the restart.

For production deployments, `createRedisReplayStore` (which uses `SET key NX EX`) provides restart-durable atomic consume semantics. The choice of replay store is a deployment configuration decision.

---

## 8. Current Production-Readiness State

### 8.1 Production-ready components

**`packages/sift` core verification library**

- `verifyReceipt`: structural validation, receipt hash integrity, Ed25519 signature verification, decision enforcement, freshness validation. 119 tests pass (including property tests and staging fixture vectors). The verification ordering is normative and matches `docs/adapters/sift.md`.
- `siftCanonical.ts`: ensure-ASCII canonicalization, surrogate pair handling, prototype-safe output objects, non-finite number rejection. Tested against RFC 8037 Appendix A vector and cross-language parity cases.
- `normalizeIntent` / `normalizeState`: exhaustive type rejection, prototype-safe construction. Tested with property-based tests.
- `receiptToAuthorization`: correct field binding, empty signature placeholder, explicit signing payload. Tested with property-based tests.
- `SiftHttpKeyStore`: concurrent JWKS/KRL fetch, atomic cache swap, OKP/Ed25519-only key acceptance. Tested with injected mock fetch; no live network calls in CI.

KRL kid revocation check: implemented and tested. KRL payload integrity: not implemented (see §7.2).

**`packages/core` verification**

`verifyAuthorization` with `mode:"strict"` and `requireSignatureVerification:true` enforces key-set presence, signature verification, all field constraints, and expiry. 170 tests pass.

**`packages/guard` PEP library**

Full guard implementation with pluggable replay store, CAS state versioning, intent hash binding, state hash binding, audience enforcement, delegation chain verification. 136 tests pass (including GPC-1 through GPC-11 PEP conformance tests).

`createRedisReplayStore`: production-grade, multi-instance-safe, uses atomic `SET NX EX`. Tested.

### 8.2 Reference implementation (not production-ready as-is)

**`examples/reference-sift-oxdeai`**

This example implements the full Sift → OxDeAI → PEP → protected execution target pipeline with real Ed25519 cryptography and runs 8 adversarial integration tests. It is correct and useful as a reference.

The PEP gateway in `apps/pep-gateway/server.ts` is a pedagogical implementation: it implements the 10-step verification sequence inline to make the ordering readable. It does NOT use `packages/guard`. A production deployment should use `packages/guard` directly, which has 136 passing tests including full conformance coverage.

The replay store (`packages/replay-store/MemoryReplayStore`) is in-memory and not suitable for multi-process or restart-durable deployments.

### 8.3 Demo (documentation artifact, not production code)

**`examples/sift-boundary-demo`**

Builds cleanly and demonstrates the four key scenarios (ALLOW, DENY, REPLAY, BYPASS) with real Ed25519 and SHA-256 in a single in-process run. This example inlines its own canonicalization implementation because `siftCanonicalJsonBytes` is not part of `@oxdeai/sift`'s public API; the inlined version is functionally equivalent but creates a maintenance dependency. No automated test assertions exist for the demo's output.

### 8.4 Items requiring resolution before production deployment

| Item | Severity | Status |
|------|----------|--------|
| KRL payload signature verification | P0 | Not implemented; requires Sift protocol support |
| `createStagingKeyStore()` in production | P0 | Runtime guard added (throws on `NODE_ENV=production`); staging URLs remain hardcoded |
| Redis replay store for multi-instance deployments | Deployment req. | Implemented; must be selected explicitly |
| Sift→`packages/guard` integration test | P1 | No end-to-end test exercising the full Sift adapter → guard path |
| Parameter binding (params_hash) | Protocol gap | Requires Sift protocol change; documented |

---

## 9. Conclusion

The core architectural claim of OxDeAI is that the execution boundary is a different concern from the policy decision boundary, and that enforcing the execution boundary requires a different mechanism: a structurally non-bypassable enforcement point that requires a valid, signed, non-replayed, intent-bound, state-bound, audience-bound authorization artifact before any side-effecting execution may proceed.

An agent that proposes an action and receives a DENY from a policy engine produces no side effects — but only if the execution path is gated by the enforcement point, not by the agent's own good behavior. An agent that receives ALLOW must produce a valid `AuthorizationV1` artifact, signed by a trusted issuer, committing to the specific action, the specific state, and the specific execution target. That artifact is verified independently at the PEP before the action executes.

The boundary cannot be satisfied by advisory evaluations, by cooperative agents, or by pipeline architecture alone. It requires that the protected execution target refuses requests that do not satisfy the authorization boundary, and that the artifact is cryptographically unforgeable, temporally bounded, and single-use.

The known limitations in §7 constrain the strength of the guarantee: parameter binding is not cryptographically enforced at the receipt level, KRL integrity depends on transport, state trust depends on the integrity of the state source, and replay protection requires a durable shared store in multi-instance deployments. These are not gaps to be minimized; they define the precise scope of what the current implementation can and cannot attest to.

Within that scope:

> **No valid `AuthorizationV1` verified by the PEP — covering signature, issuer, audience, decision, expiry, intent hash, state hash, and replay status — means no execution path.**
