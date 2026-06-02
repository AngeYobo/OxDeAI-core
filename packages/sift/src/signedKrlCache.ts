// SPDX-License-Identifier: Apache-2.0
/**
 * SignedKrlCache — pluggable last-known-good cache for signed KRL payloads.
 *
 * The cache stores a verified signed KRL envelope so that SiftHttpKeyStore
 * can bootstrap revokedKids on cold start or during network-flap scenarios
 * without accepting an unverified revocation list.
 *
 * ── Trust contract (non-negotiable) ──────────────────────────────────────────
 *
 *   A cached payload is bytes / JSON only. Loading it is NOT acceptance.
 *
 *   Every LKG load MUST re-run the payload through the configured `verifyKrl`
 *   callback with:
 *     - current `now` (for expiry check)
 *     - current `previousKrlVersionByIssuer` (for version regression check)
 *   before any revoked_kids derived from it enter `revokedKids`.
 *
 * ── What is stored ────────────────────────────────────────────────────────────
 *
 *   The full SignedKRLV1 envelope JSON (including signature.sig — required for
 *   re-verification) plus the unix-seconds timestamp when the payload was last
 *   successfully verified.
 *
 *   The cache does NOT store trusted signing keys. It does NOT store JWKS.
 *   It MUST NOT be used to bypass re-verification.
 *
 * ── What is never stored ──────────────────────────────────────────────────────
 *
 *   Unsigned KRLs. Unsigned-fallback KRL payloads must never be written to the
 *   cache. `SiftHttpKeyStore` gates writes on signed verification only.
 *
 * ── No constructor I/O ────────────────────────────────────────────────────────
 *
 *   `SiftHttpKeyStore` never calls `get()` or `set()` during construction.
 *   Cache access happens exclusively inside `refresh()`.
 */

/**
 * Pluggable last-known-good signed-KRL cache.
 *
 * Implementations must be fail-closed: throw on infrastructure failure.
 * SiftHttpKeyStore treats `set()` failures as non-fatal (observable but
 * not blocking). `get()` failures cause the LKG fallback to abort.
 *
 * @public
 */
export interface SignedKrlCache {
  /**
   * Returns the cached payload and when it was last verified, or undefined
   * when no valid cache entry exists (missing file, empty memory store, etc.).
   *
   * The returned payload is raw JSON; it is NOT considered verified.
   * The caller MUST re-verify before use.
   *
   * @throws If the cache cannot be read due to an infrastructure error.
   */
  get(): Promise<{ payload: unknown; verifiedAt: number } | undefined>;

  /**
   * Persists a signed KRL payload that has been cryptographically verified.
   *
   * @param payload   - The full SignedKRLV1 envelope JSON (including signature).
   * @param verifiedAt - Unix seconds when verification succeeded.
   * @throws If the cache cannot be written. SiftHttpKeyStore treats write
   *   failures as non-fatal after the KRL has already been durably watermarked.
   */
  set(payload: unknown, verifiedAt: number): Promise<void>;
}

/**
 * createInMemorySignedKrlCache — in-process last-known-good cache.
 *
 * Each factory call produces an independent store instance.
 * Suitable for:
 *   - Testing
 *   - Single-process deployments that accept losing LKG data on restart
 *
 * NOT suitable for:
 *   - Deployments requiring LKG to survive process restarts
 *
 * For persistent LKG storage, use createFileBackedSignedKrlCache.
 *
 * @public
 */
export function createInMemorySignedKrlCache(): SignedKrlCache {
  let entry: { payload: unknown; verifiedAt: number } | undefined;

  return {
    async get() {
      return entry;
    },

    async set(payload, verifiedAt) {
      entry = { payload, verifiedAt };
    },
  };
}
