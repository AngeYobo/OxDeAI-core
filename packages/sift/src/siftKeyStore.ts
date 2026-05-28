// SPDX-License-Identifier: Apache-2.0
/**
 * Sift JWKS + KRL key store for receipt signature verification.
 *
 * Responsibilities:
 *   - JWKS fetch and parse (RFC 8037 OKP / Ed25519)
 *   - KRL fetch, parse, and optional signed-integrity verification
 *   - in-memory key cache keyed by `kid`
 *   - refresh-on-unknown-kid (called externally; one retry is the contract)
 *   - fail-closed on any parse, network, or integrity failure
 *   - KRL integrity modes: signed_required, signed_preferred, unsigned_legacy
 *
 * No network calls are made at construction time.  The caller triggers I/O
 * either explicitly via `refresh()` or implicitly via `verifyReceiptWithKeyStore`.
 *
 * The `fetch` option exists for test injection.  Production code leaves it
 * unset, which falls back to `globalThis.fetch`.
 *
 * ── KRL integrity modes ───────────────────────────────────────────────────────
 *
 *   signed_required
 *     Strict production mode. Every fetched KRL must carry a SignedKRLV1
 *     signature verified by the injected `verifyKrl` callback. Unsigned KRLs
 *     are rejected immediately (without consulting `verifyKrl`) with
 *     KRL_UNSIGNED_IN_SIGNED_REQUIRED. Constructor throws if `verifyKrl` is
 *     absent.
 *
 *   signed_preferred (default)
 *     Transition mode. When the fetched KRL has a `signature` field, the
 *     `verifyKrl` callback is required and verification must succeed. If no
 *     `signature` field is present, the store falls back to unsigned parsing
 *     (status `unsigned_fallback`). If a `signature` field is present but no
 *     `verifyKrl` callback is configured, refresh() fails closed.
 *
 *   unsigned_legacy
 *     Compatibility-only mode. Preserves pre-Patch-B behavior: unsigned KRL
 *     revoked_kids are parsed via HTTPS transport trust. Emits a deprecation
 *     warning at construction. Non-string revoked_kids entries are silently
 *     skipped (this is the legacy behavior and is NOT SignedKRLV1 semantics).
 *
 * ── verifyKrl injection ───────────────────────────────────────────────────────
 *
 *   `verifyKrl` is an optional callback that delegates signed KRL verification
 *   to an external implementation (e.g. `verifySignedKrl` from `@oxdeai/core`).
 *   This preserves @oxdeai/sift's zero-dependency boundary.
 *
 *   Production wiring example:
 *
 *     import { verifySignedKrl } from "@oxdeai/core";
 *     const store = new SiftHttpKeyStore({
 *       jwksUrl, krlUrl,
 *       krlMode: "signed_required",
 *       verifyKrl: (payload, ctx) => verifySignedKrl(payload, {
 *         trustedKeySets: myKrlSigningKeySets,
 *         ...ctx,
 *       }),
 *     });
 */

import { b64uDecode } from "./siftCanonical.js";

// ─── Fetch abstraction ────────────────────────────────────────────────────────

type FetchFn = (url: string, init?: RequestInit) => Promise<Response>;

// ─── Error type ───────────────────────────────────────────────────────────────

export type KeyStoreErrorCode =
  | "JWKS_FETCH_FAILED"
  | "KRL_FETCH_FAILED"
  | "KEYSTORE_REFRESH_FAILED";

export class KeyStoreError extends Error {
  readonly code: KeyStoreErrorCode;

  constructor(code: KeyStoreErrorCode, message: string) {
    super(message);
    this.name = "KeyStoreError";
    this.code = code;
  }
}

// ─── Public interface ─────────────────────────────────────────────────────────

export interface SiftKeyStore {
  /**
   * Returns the raw 32-byte Ed25519 public key for `kid`, or null if the kid
   * is not present in the current in-memory cache.  Does NOT trigger a refresh;
   * the caller is responsible for calling refresh() before the first lookup or
   * when an unknown kid is encountered.
   */
  getPublicKeyByKid(kid: string): Promise<Uint8Array | null>;

  /**
   * Returns true if `kid` is present in the current KRL revocation set.
   * Does NOT trigger a refresh.
   */
  isKidRevoked(kid: string): Promise<boolean>;

  /**
   * Fetches and replaces the in-memory JWKS and KRL from the configured
   * remote endpoints.  Both fetches run concurrently.  Throws a
   * `KeyStoreError` on any network, HTTP, parse, or integrity failure.
   * The in-memory caches are only swapped if both fetches and all checks succeed.
   */
  refresh(): Promise<void>;
}

// ─── KRL integrity modes ──────────────────────────────────────────────────────

/** KRL integrity verification mode. Default: "signed_preferred". */
export type KrlMode = "signed_required" | "signed_preferred" | "unsigned_legacy";

/** Describes the integrity of the most recently accepted KRL. */
export type KrlIntegrity =
  | "signed"            // KRL was cryptographically verified via verifyKrl
  | "unsigned_fallback" // KRL had no signature field; accepted via transport trust
  | "unsigned_legacy"   // krlMode === "unsigned_legacy"; accepted via transport trust
  | "failed"            // last refresh attempt failed at the KRL stage
  | "none";             // no refresh has completed yet

/**
 * Callback for signed KRL verification.
 *
 * This is a structural type — @oxdeai/sift does not import from @oxdeai/core.
 * In production, wire this to `verifySignedKrl` from `@oxdeai/core`:
 *
 *   verifyKrl: (payload, ctx) => verifySignedKrl(payload, {
 *     trustedKeySets: myKrlSigningKeySets,
 *     ...ctx,
 *   })
 *
 * The return shape is structurally compatible with VerificationResult from
 * @oxdeai/core without requiring an import.
 *
 * @public
 */
export type KrlVerifyFn = (
  payload: unknown,
  ctx: {
    now: number;
    previousKrlVersionByIssuer?: Readonly<Record<string, number>>;
  }
) => {
  ok: boolean;
  status?: string;
  violations: Array<{ code: string; message?: string }>;
  /**
   * Verified accepted KRL metadata. Required when `ok: true` for signed KRL paths.
   * `SiftHttpKeyStore` uses this to advance the per-issuer `krl_version` watermark.
   *
   * `accepted.krl_version` MUST be the exact value the verifier validated and used for
   * its regression check. Do not compute it independently from the KRL body.
   *
   * Production wiring example:
   *   const result = verifySignedKrl(payload, { trustedKeySets, ...ctx });
   *   if (!result.ok) return result;
   *   const krl = payload as { issuer: string; krl_version: number };
   *   return { ...result, accepted: { issuer: krl.issuer, krl_version: krl.krl_version } };
   *
   * If absent on `ok: true`, `SiftHttpKeyStore` fails closed with KRL_VERIFY_RESULT_INCOMPLETE.
   */
  accepted?: { issuer: string; krl_version: number };
};

/**
 * KRL status snapshot returned by `SiftHttpKeyStore.getKrlStatus()`.
 *
 * Confidentiality boundary: this surface exposes mode, integrity metadata,
 * reason codes, issuer names, kid values, version numbers, and timestamps.
 * It NEVER exposes public-key PEM contents, private keys, raw signature bytes,
 * full KRL payloads, or trusted signing key material.
 *
 * @public
 */
export interface KrlStatus {
  mode: KrlMode;
  /** Integrity classification of the most recently accepted KRL. */
  lastIntegrity: KrlIntegrity;
  /**
   * Reason code from the last KRL verification failure, or undefined when the
   * last refresh succeeded. Always cleared to undefined on success.
   */
  lastReason?: string;
  /** True when the active KRL was loaded via unsigned fallback. */
  unsignedFallbackActive: boolean;
  /** Unix seconds of the last successful KRL acceptance, or undefined. */
  lastVerifiedAt?: number;
  /** Per-issuer high-watermark of accepted krl_version values (in-memory only). */
  lastKrlVersionByIssuer: Record<string, number>;
}

// ─── Sift-local KRL mode/contract codes ──────────────────────────────────────
//
// These four codes are produced by SiftHttpKeyStore's mode logic and contract
// enforcement.  They are NOT imported from @oxdeai/core VerificationViolationCode.
//
//   KRL_UNSIGNED_IN_SIGNED_REQUIRED
//     Unsigned KRL rejected in signed_required mode before verifyKrl is called.
//
//   KRL_MISSING_VERIFY_CALLBACK
//     KRL has a signature field but no verifyKrl callback is configured.
//     Refresh fails closed — no unsigned fallback when signature key is present.
//
//   KRL_VERIFY_CALLBACK_ERROR
//     verifyKrl callback threw instead of returning a result.
//     Refresh fails closed.
//
//   KRL_VERIFY_RESULT_INCOMPLETE
//     verifyKrl returned ok: true but did not include accepted issuer/krl_version
//     metadata. This is a contract violation between the injected verifier and
//     SiftHttpKeyStore. Refresh fails closed.
//
// The seven core KRL codes (KRL_MALFORMED, KRL_SIG_INVALID, KRL_EXPIRED,
// KRL_UNSUPPORTED_ALG, KRL_UNKNOWN_SIGNING_KID, KRL_SIGNING_KEY_INACTIVE,
// KRL_VERSION_REGRESSION) are passed through as opaque strings from verifyKrl.
//
const KRL_UNSIGNED_IN_SIGNED_REQUIRED  = "KRL_UNSIGNED_IN_SIGNED_REQUIRED";
const KRL_MISSING_VERIFY_CALLBACK      = "KRL_MISSING_VERIFY_CALLBACK";
const KRL_VERIFY_RESULT_INCOMPLETE     = "KRL_VERIFY_RESULT_INCOMPLETE";

// ─── JWKS parsing ─────────────────────────────────────────────────────────────

/**
 * Parses a JWKS response body into a Map of kid → raw 32-byte public key.
 *
 * Accepts only entries where:
 *   - kty === "OKP"
 *   - crv === "Ed25519"
 *   - kid is a non-empty string
 *   - x is a non-empty base64url string that decodes to exactly 32 bytes
 *
 * Invalid entries are silently skipped.  If the response is not a valid JWKS
 * object at all, throws `KeyStoreError("JWKS_FETCH_FAILED", ...)`.
 */
function parseJwks(body: unknown): Map<string, Uint8Array> {
  if (
    typeof body !== "object" ||
    body === null ||
    !Array.isArray((body as Record<string, unknown>)["keys"])
  ) {
    throw new KeyStoreError(
      "JWKS_FETCH_FAILED",
      "JWKS response missing required 'keys' array"
    );
  }

  const keys = (body as { keys: unknown[] }).keys;
  const result = new Map<string, Uint8Array>();

  for (const entry of keys) {
    if (typeof entry !== "object" || entry === null) continue;
    const e = entry as Record<string, unknown>;

    if (e["kty"] !== "OKP") continue;
    if (e["crv"] !== "Ed25519") continue;
    if (typeof e["kid"] !== "string" || e["kid"].length === 0) continue;
    if (typeof e["x"] !== "string" || e["x"].length === 0) continue;

    let raw: Buffer;
    try {
      raw = b64uDecode(e["x"] as string);
    } catch {
      continue;
    }

    if (raw.length !== 32) continue;

    result.set(e["kid"] as string, raw);
  }

  return result;
}

// ─── Unsigned KRL parsing (legacy/fallback) ───────────────────────────────────

/**
 * Parses an unsigned KRL response body into a Set of revoked kid strings.
 *
 * Requires `revoked_kids` to be a present array.  Non-string entries within
 * the array are silently skipped.
 *
 * ── Behavior note ─────────────────────────────────────────────────────────────
 * Silent skipping of non-string entries is LEGACY behavior.  It applies only
 * to the unsigned_legacy mode and the unsigned-fallback path of signed_preferred.
 * The signed KRL path (via verifyKrl / verifySignedKrl) rejects non-string and
 * duplicate revoked_kids entries as KRL_MALFORMED.
 *
 * Throws `KeyStoreError("KRL_FETCH_FAILED", ...)` if the top-level shape is
 * not a valid KRL object.
 */
function parseKrl(body: unknown): Set<string> {
  if (typeof body !== "object" || body === null) {
    throw new KeyStoreError("KRL_FETCH_FAILED", "KRL response is not a JSON object");
  }

  const krl = body as Record<string, unknown>;

  if (!Array.isArray(krl["revoked_kids"])) {
    throw new KeyStoreError(
      "KRL_FETCH_FAILED",
      "KRL response missing required 'revoked_kids' array"
    );
  }

  const result = new Set<string>();
  for (const kid of krl["revoked_kids"] as unknown[]) {
    if (typeof kid === "string") result.add(kid);
    // Non-string entries are silently skipped (legacy behavior).
  }

  return result;
}

// ─── KRL processing helpers ───────────────────────────────────────────────────

/** Returns true if the parsed JSON body contains any `signature` key (value-agnostic). */
function hasSignatureField(body: unknown): boolean {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return false;
  return "signature" in (body as object);
}

/**
 * Extracts `revoked_kids` from a KRL payload that has already been verified
 * by the `verifyKrl` callback.  Defensive: only string entries are added.
 */
function extractRevokedKidsFromVerified(body: unknown): Set<string> {
  if (typeof body !== "object" || body === null) return new Set();
  const b = body as Record<string, unknown>;
  const kids = b["revoked_kids"];
  if (!Array.isArray(kids)) return new Set();
  const result = new Set<string>();
  for (const k of kids) {
    if (typeof k === "string") result.add(k);
  }
  return result;
}


// ─── Internal KRL process result ─────────────────────────────────────────────

type KrlProcessSuccess = {
  ok: true;
  revoked: Set<string>;
  integrity: "signed" | "unsigned_fallback" | "unsigned_legacy";
  updatedVersion?: { issuer: string; krl_version: number };
};

type KrlProcessFailure = {
  ok: false;
  reason: string;
  error: KeyStoreError;
};

type KrlProcessResult = KrlProcessSuccess | KrlProcessFailure;

// ─── HTTP-backed implementation ───────────────────────────────────────────────

export interface SiftHttpKeyStoreOptions {
  jwksUrl: string;
  krlUrl: string;
  /**
   * Custom fetch implementation.  Defaults to `globalThis.fetch`.
   * Override in tests to avoid live network calls.
   */
  fetch?: FetchFn;
  /**
   * KRL integrity verification mode.
   *
   * Default: "signed_preferred"
   *
   * - "signed_required"  — all KRLs must be cryptographically signed and
   *   verified via the `verifyKrl` callback.  Constructor throws if `verifyKrl`
   *   is absent.  Closes the KRL transport-integrity gap.
   * - "signed_preferred" — signed KRLs are verified when present; unsigned KRLs
   *   are accepted via transport trust as a fallback (status: unsigned_fallback).
   *   If a KRL has any `signature` field but no `verifyKrl` is configured,
   *   refresh() fails closed.
   * - "unsigned_legacy"  — preserves pre-Patch-B unsigned KRL behavior.
   *   Deprecated. Emits a warning at construction.
   */
  krlMode?: KrlMode;
  /**
   * Signed KRL verification callback.
   *
   * Required when krlMode is "signed_required". Optional for "signed_preferred"
   * but will cause refresh() to fail closed when a signed KRL is encountered
   * without this callback configured.
   *
   * Production wiring:
   *   import { verifySignedKrl } from "@oxdeai/core";
   *   verifyKrl: (payload, ctx) => verifySignedKrl(payload, {
   *     trustedKeySets: myKrlSigningKeySets,
   *     ...ctx,
   *   })
   *
   * @oxdeai/sift has no runtime dependency on @oxdeai/core. The callback is
   * the integration seam.
   */
  verifyKrl?: KrlVerifyFn;
  /**
   * Unix-seconds clock provider for KRL expiry checks passed to `verifyKrl`.
   * Defaults to `() => Math.floor(Date.now() / 1000)`.
   * Override in tests for deterministic time-sensitive assertions.
   * Must remain optional — existing callers work without it.
   */
  now?: () => number;
}

export class SiftHttpKeyStore implements SiftKeyStore {
  private readonly jwksUrl: string;
  private readonly krlUrl: string;
  private readonly fetchFn: FetchFn;
  private readonly krlMode: KrlMode;
  private readonly verifyKrl: KrlVerifyFn | undefined;
  private readonly nowFn: () => number;

  private keyCache = new Map<string, Uint8Array>();
  private revokedKids = new Set<string>();
  private krlVersionByIssuer = new Map<string, number>();
  private _krlStatus: KrlStatus;

  constructor(opts: SiftHttpKeyStoreOptions) {
    this.jwksUrl = opts.jwksUrl;
    this.krlUrl = opts.krlUrl;
    this.fetchFn = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.krlMode = opts.krlMode ?? "signed_preferred";
    this.verifyKrl = opts.verifyKrl;
    this.nowFn = opts.now ?? (() => Math.floor(Date.now() / 1000));

    // Fast-fail: signed_required mode requires a verifyKrl callback.
    if (this.krlMode === "signed_required" && !this.verifyKrl) {
      throw new TypeError(
        "[SiftHttpKeyStore] krlMode \"signed_required\" requires a verifyKrl callback. " +
        "Provide a verifyKrl function that calls verifySignedKrl from @oxdeai/core with " +
        "your trusted KRL signing key sets. This mode closes the KRL transport-integrity gap."
      );
    }

    // Deprecation warning for unsigned_legacy.
    if (this.krlMode === "unsigned_legacy") {
      console.warn(
        "[SiftHttpKeyStore] krlMode \"unsigned_legacy\" is deprecated. " +
        "KRL payload integrity depends on transport security (HTTPS) only. " +
        "Migrate to \"signed_preferred\" or \"signed_required\" with a verifyKrl callback " +
        "to enforce cryptographic KRL integrity. See docs/spec/artifacts/signed-krl-v1.md."
      );
    }

    this._krlStatus = {
      mode: this.krlMode,
      lastIntegrity: "none",
      lastReason: undefined,
      unsignedFallbackActive: false,
      lastVerifiedAt: undefined,
      lastKrlVersionByIssuer: {},
    };
  }

  async getPublicKeyByKid(kid: string): Promise<Uint8Array | null> {
    return this.keyCache.get(kid) ?? null;
  }

  async isKidRevoked(kid: string): Promise<boolean> {
    return this.revokedKids.has(kid);
  }

  /**
   * Returns a snapshot of the current KRL integrity status.
   *
   * Never exposes public-key PEM contents, private keys, raw signature bytes,
   * full KRL payloads, or trusted signing key material.
   */
  getKrlStatus(): KrlStatus {
    return {
      mode: this._krlStatus.mode,
      lastIntegrity: this._krlStatus.lastIntegrity,
      lastReason: this._krlStatus.lastReason,
      unsignedFallbackActive: this._krlStatus.unsignedFallbackActive,
      lastVerifiedAt: this._krlStatus.lastVerifiedAt,
      lastKrlVersionByIssuer: { ...this._krlStatus.lastKrlVersionByIssuer },
    };
  }

  async refresh(): Promise<void> {
    // Fetch both endpoints concurrently.
    let jwksRes: Response;
    let krlRes: Response;
    try {
      [jwksRes, krlRes] = await Promise.all([
        this.fetchFn(this.jwksUrl),
        this.fetchFn(this.krlUrl),
      ]);
    } catch (err) {
      throw new KeyStoreError(
        "KEYSTORE_REFRESH_FAILED",
        `Network error during JWKS/KRL refresh: ${err instanceof Error ? err.message : String(err)}`
      );
    }

    if (!jwksRes.ok) {
      throw new KeyStoreError(
        "JWKS_FETCH_FAILED",
        `JWKS endpoint returned HTTP ${jwksRes.status}`
      );
    }
    if (!krlRes.ok) {
      throw new KeyStoreError(
        "KRL_FETCH_FAILED",
        `KRL endpoint returned HTTP ${krlRes.status}`
      );
    }

    let jwksBody: unknown;
    let krlBody: unknown;
    try {
      [jwksBody, krlBody] = await Promise.all([
        jwksRes.json() as Promise<unknown>,
        krlRes.json() as Promise<unknown>,
      ]);
    } catch (err) {
      throw new KeyStoreError(
        "KEYSTORE_REFRESH_FAILED",
        `Failed to parse JWKS/KRL JSON: ${err instanceof Error ? err.message : String(err)}`
      );
    }

    // Parse JWKS — throws JWKS_FETCH_FAILED on malformed input.
    const newKeys = parseJwks(jwksBody);

    // Process KRL according to configured mode.
    const nowSeconds = this.nowFn();
    const krlResult = this.processKrlForMode(krlBody, nowSeconds);

    if (!krlResult.ok) {
      // Update status to record failure before throwing (observability).
      // lastReason is set to the specific KRL code; preserved until next refresh.
      this._krlStatus = {
        mode: this.krlMode,
        lastIntegrity: "failed",
        lastReason: krlResult.reason,
        // Preserve previous active-state fields — the cache was not swapped.
        unsignedFallbackActive: this._krlStatus.unsignedFallbackActive,
        lastVerifiedAt: this._krlStatus.lastVerifiedAt,
        lastKrlVersionByIssuer: Object.fromEntries(this.krlVersionByIssuer),
      };
      throw krlResult.error;
    }

    // Both parses and all integrity checks succeeded — atomic cache swap.
    this.keyCache = newKeys;
    this.revokedKids = krlResult.revoked;

    // Update per-issuer krl_version high-watermark for signed KRLs.
    if (krlResult.updatedVersion) {
      this.krlVersionByIssuer.set(
        krlResult.updatedVersion.issuer,
        krlResult.updatedVersion.krl_version
      );
    }

    // Update status — lastReason is ALWAYS cleared on success.
    this._krlStatus = {
      mode: this.krlMode,
      lastIntegrity: krlResult.integrity,
      lastReason: undefined,
      unsignedFallbackActive: krlResult.integrity === "unsigned_fallback",
      lastVerifiedAt: nowSeconds,
      lastKrlVersionByIssuer: Object.fromEntries(this.krlVersionByIssuer),
    };
  }

  // ─── Private: KRL mode routing ──────────────────────────────────────────────

  private processKrlForMode(
    krlBody: unknown,
    nowSeconds: number
  ): KrlProcessResult {
    // unsigned_legacy: preserve pre-Patch-B behavior exactly.
    if (this.krlMode === "unsigned_legacy") {
      try {
        const revoked = parseKrl(krlBody);
        return { ok: true, revoked, integrity: "unsigned_legacy" };
      } catch (err) {
        const error =
          err instanceof KeyStoreError
            ? err
            : new KeyStoreError("KRL_FETCH_FAILED", `KRL parse error: ${String(err)}`);
        return { ok: false, reason: error.code, error };
      }
    }

    const hasSig = hasSignatureField(krlBody);

    // signed_required: any KRL without a signature field is rejected immediately,
    // BEFORE consulting verifyKrl. This ensures verifyKrl is never called for
    // unsigned KRLs in this mode (no bypass path).
    if (this.krlMode === "signed_required") {
      if (!hasSig) {
        const error = new KeyStoreError(
          "KRL_FETCH_FAILED",
          `${KRL_UNSIGNED_IN_SIGNED_REQUIRED}: The fetched KRL does not contain a ` +
          `signature field. Configure the KRL publisher to produce signed KRLs ` +
          `(SignedKRLV1), or downgrade to "signed_preferred" or "unsigned_legacy" mode.`
        );
        return { ok: false, reason: KRL_UNSIGNED_IN_SIGNED_REQUIRED, error };
      }
      // verifyKrl is guaranteed non-null (checked at construction).
      return this.runVerifyKrl(krlBody, nowSeconds);
    }

    // signed_preferred: route on signature field presence.
    if (hasSig) {
      if (!this.verifyKrl) {
        // KRL has a signature field but no verifyKrl configured — fail closed.
        // Do NOT fall back to unsigned: presence of signature means the KRL is
        // attempting the signed path. A fallback would create a downgrade vector.
        const error = new KeyStoreError(
          "KRL_FETCH_FAILED",
          `${KRL_MISSING_VERIFY_CALLBACK}: The fetched KRL contains a signature field ` +
          `but no verifyKrl callback is configured. Provide a verifyKrl callback to ` +
          `verify signed KRLs, or configure krlMode "unsigned_legacy" if signature ` +
          `verification is not yet required.`
        );
        return { ok: false, reason: KRL_MISSING_VERIFY_CALLBACK, error };
      }
      return this.runVerifyKrl(krlBody, nowSeconds);
    }

    // signed_preferred + no signature field → unsigned fallback.
    // verifyKrl is NOT consulted (unsigned KRL path skips it entirely).
    try {
      const revoked = parseKrl(krlBody);
      return { ok: true, revoked, integrity: "unsigned_fallback" };
    } catch (err) {
      const error =
        err instanceof KeyStoreError
          ? err
          : new KeyStoreError("KRL_FETCH_FAILED", `KRL parse error: ${String(err)}`);
      return { ok: false, reason: error.code, error };
    }
  }

  /** Calls verifyKrl callback and translates the result into a KrlProcessResult. */
  private runVerifyKrl(krlBody: unknown, nowSeconds: number): KrlProcessResult {
    const prevVersions: Record<string, number> = Object.fromEntries(this.krlVersionByIssuer);

    let verifyResult: ReturnType<KrlVerifyFn>;
    try {
      verifyResult = this.verifyKrl!(krlBody, {
        now: nowSeconds,
        previousKrlVersionByIssuer: prevVersions,
      });
    } catch (err) {
      const error = new KeyStoreError(
        "KRL_FETCH_FAILED",
        `verifyKrl callback threw unexpectedly: ${err instanceof Error ? err.message : String(err)}`
      );
      return { ok: false, reason: "KRL_VERIFY_CALLBACK_ERROR", error };
    }

    if (!verifyResult.ok) {
      const code = verifyResult.violations[0]?.code ?? "KRL_SIG_INVALID";
      const msg = verifyResult.violations[0]?.message ?? "signed KRL verification failed";
      const error = new KeyStoreError("KRL_FETCH_FAILED", `${code}: ${msg}`);
      return { ok: false, reason: code, error };
    }

    // Verification succeeded — watermark MUST come from result.accepted, never
    // from an independent re-parse of krlBody.  If the caller omits accepted,
    // fail closed rather than silently skipping watermark advancement.
    if (!verifyResult.accepted) {
      const error = new KeyStoreError(
        "KRL_FETCH_FAILED",
        `${KRL_VERIFY_RESULT_INCOMPLETE}: verifyKrl returned ok: true but did not include ` +
        `accepted issuer/krl_version metadata. Production wiring must populate ` +
        `result.accepted from the verified SignedKRLV1 payload fields.`
      );
      return { ok: false, reason: KRL_VERIFY_RESULT_INCOMPLETE, error };
    }

    const revoked = extractRevokedKidsFromVerified(krlBody);
    return {
      ok: true,
      revoked,
      integrity: "signed",
      updatedVersion: verifyResult.accepted,
    };
  }
}

// ─── Staging factory ──────────────────────────────────────────────────────────

const STAGING_JWKS_URL = "https://sift-staging.walkosystems.com/sift-jwks.json";
const STAGING_KRL_URL  = "https://sift-staging.walkosystems.com/sift-krl.json";

export interface CreateStagingKeyStoreOptions {
  /**
   * Set to `true` to suppress the production-environment guard.
   *
   * This escape hatch exists for non-production integration tests that
   * intentionally run in an environment where NODE_ENV is set to "production".
   * It MUST NOT be used in real production deployments.
   */
  _allowInProduction?: boolean;
}

/**
 * Returns a new `SiftHttpKeyStore` pre-configured for the Sift **staging**
 * endpoints with the default krlMode of "signed_preferred".
 *
 * @internal
 *
 * **NOT FOR PRODUCTION USE.**
 *
 * The Sift staging JWKS and KRL endpoints (`sift-staging.walkosystems.com`)
 * are for development and testing only.  Calling this function in a production
 * process trusts staging keys for production receipts and exposes internal
 * staging state to production traffic.
 *
 * For production, construct a `SiftHttpKeyStore` directly with your production
 * JWKS and KRL endpoint URLs:
 *
 * ```ts
 * const keyStore = new SiftHttpKeyStore({
 *   jwksUrl: "https://your-production-sift-host/sift-jwks.json",
 *   krlUrl:  "https://your-production-sift-host/sift-krl.json",
 *   krlMode: "signed_required",
 *   verifyKrl: (payload, ctx) => verifySignedKrl(payload, { trustedKeySets, ...ctx }),
 * });
 * ```
 *
 * This function throws if `NODE_ENV === "production"` unless
 * `_allowInProduction: true` is explicitly passed.
 */
export function createStagingKeyStore(opts?: CreateStagingKeyStoreOptions): SiftHttpKeyStore {
  if (process.env["NODE_ENV"] === "production" && opts?._allowInProduction !== true) {
    throw new Error(
      "[createStagingKeyStore] MUST NOT be called in production (NODE_ENV=production). " +
      "Staging JWKS/KRL endpoints are not suitable for production deployments. " +
      "Use new SiftHttpKeyStore({ jwksUrl, krlUrl }) with your production endpoints instead. " +
      "To suppress this guard in a controlled non-production context, pass { _allowInProduction: true }."
    );
  }
  return new SiftHttpKeyStore({
    jwksUrl: STAGING_JWKS_URL,
    krlUrl: STAGING_KRL_URL,
  });
}
