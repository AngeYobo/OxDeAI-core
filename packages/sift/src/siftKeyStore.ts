// SPDX-License-Identifier: Apache-2.0
/**
 * Sift JWKS + KRL key store for receipt signature verification.
 *
 * Responsibilities:
 *   - JWKS fetch and parse (RFC 8037 OKP / Ed25519)
 *   - KRL fetch and parse (revoked kid set)
 *   - in-memory key cache keyed by `kid`
 *   - refresh-on-unknown-kid (called externally; one retry is the contract)
 *   - fail-closed on any parse or network failure
 *
 * No network calls are made at construction time.  The caller triggers I/O
 * either explicitly via `refresh()` or implicitly via `verifyReceiptWithKeyStore`.
 *
 * The `fetch` option exists for test injection.  Production code leaves it
 * unset, which falls back to `globalThis.fetch`.
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
   * `KeyStoreError` on any network, HTTP, or parse failure.  The in-memory
   * caches are only swapped if both fetches and parses succeed.
   */
  refresh(): Promise<void>;
}

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
 * Invalid entries are silently skipped (ignoring them is safer than partially
 * trusting a malformed entry).  If the response is not a valid JWKS object at
 * all, throws `KeyStoreError("JWKS_FETCH_FAILED", ...)`.
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
      continue; // invalid base64url — skip; do not partially trust
    }

    if (raw.length !== 32) continue; // wrong key size — skip

    result.set(e["kid"] as string, raw);
  }

  return result;
}

// ─── KRL parsing ──────────────────────────────────────────────────────────────

/**
 * Parses a KRL response body into a Set of revoked kid strings.
 *
 * Requires `revoked_kids` to be a present array.  Non-string entries within
 * the array are silently skipped (only known string values enter the revoked
 * set — fail-closed: an unknown format entry cannot accidentally un-revoke a
 * key).  Throws `KeyStoreError("KRL_FETCH_FAILED", ...)` if the top-level
 * shape is not a valid KRL object.
 *
 * ── KRL payload integrity limitation ─────────────────────────────────────────
 * `SiftHttpKeyStore` checks whether a `kid` appears in the fetched KRL, but
 * does NOT verify a cryptographic signature over the KRL payload itself.
 *
 * KRL payload integrity therefore depends on transport security (HTTPS to a
 * trusted endpoint).  A compromised intermediary (e.g. a CDN edge, a man-in-
 * the-middle, or a stale unsigned cache entry) could return a modified KRL
 * that omits specific revoked kids — allowing a revoked key to pass the
 * revocation check.
 *
 * Unknown/revoked kids still fail closed:
 *   - kid in revoked_kids   → REVOKED_KID immediately
 *   - kid not found after refresh → UNKNOWN_KID (no guessing)
 *
 * Production deployments that require cryptographic revocation integrity MUST
 * wait for the Sift protocol to define a KRL signing contract.  This code is
 * structured to accept a verify-after-parse step without further refactoring.
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
    // Non-string entries are silently skipped.
    // Fail-closed: only explicitly known revoked kids enter the set.
  }

  return result;
}

// ─── HTTP-backed implementation ───────────────────────────────────────────────

export interface SiftHttpKeyStoreOptions {
  jwksUrl: string;
  krlUrl: string;
  /**
   * Custom fetch implementation.  Defaults to `globalThis.fetch`.
   * Override in tests to avoid live network calls.
   */
  fetch?: FetchFn;
}

export class SiftHttpKeyStore implements SiftKeyStore {
  private readonly jwksUrl: string;
  private readonly krlUrl: string;
  private readonly fetchFn: FetchFn;

  private keyCache = new Map<string, Uint8Array>();
  private revokedKids = new Set<string>();

  constructor(opts: SiftHttpKeyStoreOptions) {
    this.jwksUrl = opts.jwksUrl;
    this.krlUrl = opts.krlUrl;
    this.fetchFn = opts.fetch ?? globalThis.fetch.bind(globalThis);
  }

  async getPublicKeyByKid(kid: string): Promise<Uint8Array | null> {
    return this.keyCache.get(kid) ?? null;
  }

  async isKidRevoked(kid: string): Promise<boolean> {
    return this.revokedKids.has(kid);
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

    // Parse both; use specific error codes on failure.
    // Both parses must succeed before we swap the caches.
    const newKeys = parseJwks(jwksBody);   // throws JWKS_FETCH_FAILED
    const newRevoked = parseKrl(krlBody);  // throws KRL_FETCH_FAILED

    // Atomic swap — only reached if both parses succeed.
    this.keyCache = newKeys;
    this.revokedKids = newRevoked;
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
 * endpoints.  No network calls are made at construction time.
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
