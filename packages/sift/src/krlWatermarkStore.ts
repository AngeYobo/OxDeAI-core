// SPDX-License-Identifier: Apache-2.0
/**
 * KrlWatermarkStore - pluggable persistent store for per-issuer krl_version
 * high-watermarks.
 *
 * The watermark records the highest `krl_version` accepted by this keystore for
 * each issuer. Persisting it across process restarts prevents a restart-and-replay
 * attack where an attacker replays an older signed KRL after the in-memory map is
 * cleared.
 *
 * ── Durability tiers ──────────────────────────────────────────────────────────
 *
 *   In-memory (default):
 *     Preserves current Patch-B behavior for callers who do not configure
 *     persistence. Watermark is lost on process restart; restart downgrade
 *     protection is limited to the process lifetime. Suitable for development
 *     and testing.
 *
 *   File-backed (see krlWatermarkStore.file.ts):
 *     Survives process restarts on single-node deployments. Uses atomic
 *     write-then-rename. Single-writer only - not safe for multi-process
 *     or horizontally-scaled deployments.
 *
 *   Database / Redis (caller-supplied):
 *     Full multi-node safety. Implement this interface against any store that
 *     supports atomic compare-and-set or equivalent. The interface is designed
 *     so any backend can implement it.
 *
 * ── Fail-closed contract ──────────────────────────────────────────────────────
 *
 *   All methods must throw on infrastructure failure rather than returning a
 *   permissive result. SiftHttpKeyStore treats any thrown error as a reason
 *   to block the refresh.
 *
 * ── No constructor I/O ────────────────────────────────────────────────────────
 *
 *   SiftHttpKeyStore does not call any KrlWatermarkStore method at construction
 *   time. The store is only accessed during refresh().
 */

/**
 * Pluggable persistent store for per-issuer KRL version high-watermarks.
 *
 * Implementations MUST be fail-closed: throw on infrastructure failure.
 * SiftHttpKeyStore will block the refresh if any method throws.
 *
 * @public
 */
export interface KrlWatermarkStore {
  /**
   * Returns the highest accepted krl_version for the given issuer, or
   * undefined if no version has been recorded for this issuer.
   */
  get(issuer: string): Promise<number | undefined>;

  /**
   * Records the given krl_version as the new high-watermark for the issuer.
   *
   * Implementations MUST ensure the value is durable before resolving.
   * If the new version is lower than the currently stored version (due to
   * concurrent writes or races), implementations SHOULD keep the higher value.
   *
   * @throws If the value cannot be persisted - the caller (SiftHttpKeyStore)
   *   will fail the refresh closed.
   */
  set(issuer: string, krlVersion: number): Promise<void>;

  /**
   * Returns all recorded issuer → krl_version pairs as a plain object.
   * Returns an empty object when no watermarks have been recorded.
   *
   * @throws If the store cannot be read - the caller (SiftHttpKeyStore)
   *   will fail the refresh closed.
   */
  list(): Promise<Record<string, number>>;
}

/**
 * createInMemoryKrlWatermarkStore - default single-process watermark store.
 *
 * Preserves current Patch-B in-memory behavior. Watermarks are lost on
 * process restart. Suitable for development, testing, and deployments that
 * accept the in-process-lifetime-only downgrade protection guarantee.
 *
 * NOT suitable for:
 *   - Deployments requiring restart downgrade protection.
 *   - Multi-process / horizontally-scaled deployments.
 *
 * For persistent watermark storage, use createFileBackedKrlWatermarkStore
 * (single-node) or supply a database-backed KrlWatermarkStore implementation.
 *
 * @public
 */
export function createInMemoryKrlWatermarkStore(): KrlWatermarkStore {
  const store = new Map<string, number>();

  return {
    async get(issuer: string): Promise<number | undefined> {
      return store.get(issuer);
    },

    async set(issuer: string, krlVersion: number): Promise<void> {
      const current = store.get(issuer) ?? 0;
      store.set(issuer, Math.max(current, krlVersion));
    },

    async list(): Promise<Record<string, number>> {
      return Object.fromEntries(store);
    },
  };
}
