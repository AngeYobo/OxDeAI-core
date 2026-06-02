// SPDX-License-Identifier: Apache-2.0
/**
 * File-backed SignedKrlCache — reference implementation for single-node
 * deployments that require last-known-good KRL persistence across restarts.
 *
 * ── File format ───────────────────────────────────────────────────────────────
 *
 *   JSON object with two top-level fields:
 *
 *     {
 *       "verifiedAt": 1712448000,
 *       "payload": { ...SignedKRLV1 envelope... }
 *     }
 *
 *   The full signed envelope is stored (including signature.sig) because
 *   re-verification requires it. Status surfaces NEVER expose the payload,
 *   signature bytes, or trusted signing key material.
 *
 * ── What is NOT stored ───────────────────────────────────────────────────────
 *
 *   Trusted signing keys. The cache stores only the verified payload and
 *   when it was verified. Key material must be provided to SiftHttpKeyStore
 *   via the `verifyKrl` callback configuration — not cached here.
 *
 * ── Atomicity ─────────────────────────────────────────────────────────────────
 *
 *   set() uses write-to-temp-then-rename:
 *     1. Write new content to <filePath>.tmp
 *     2. fsync the temp file
 *     3. rename() — atomic on POSIX (same filesystem)
 *     4. Best-effort directory fsync (Linux; ignored if unsupported)
 *
 * ── Missing file ─────────────────────────────────────────────────────────────
 *
 *   get() returns undefined when the file does not exist. This is the
 *   expected cold-start state; LKG is simply unavailable.
 *
 * ── Malformed file ────────────────────────────────────────────────────────────
 *
 *   get() throws when the file exists but is not valid JSON or does not
 *   contain the expected shape. SiftHttpKeyStore treats this as an LKG
 *   read failure and aborts the fallback path.
 *
 * ── Single-node / single-writer only ─────────────────────────────────────────
 *
 *   Concurrent writes are NOT safe. Intended for single-process deployments.
 */

import { open, rename, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { SignedKrlCache } from "./signedKrlCache.js";

export type { SignedKrlCache };

type CacheFileShape = {
  verifiedAt: number;
  payload: unknown;
};

/**
 * Creates a file-backed SignedKrlCache.
 *
 * @param filePath - Absolute or relative path to the JSON cache file.
 *   The directory must already exist and be writable.
 *
 * @public
 */
export function createFileBackedSignedKrlCache(filePath: string): SignedKrlCache {
  async function readCache(): Promise<CacheFileShape | undefined> {
    let raw: string;
    try {
      raw = await readFile(filePath, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        return undefined; // missing = no LKG available
      }
      throw err;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new Error(
        `Malformed LKG cache file at "${filePath}": ` +
        `content is not valid JSON. Delete or fix the file to recover.`
      );
    }

    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Array.isArray(parsed)
    ) {
      throw new Error(
        `Malformed LKG cache file at "${filePath}": ` +
        `expected a JSON object with verifiedAt and payload fields.`
      );
    }

    const obj = parsed as Record<string, unknown>;

    if (typeof obj["verifiedAt"] !== "number" || !Number.isInteger(obj["verifiedAt"])) {
      throw new Error(
        `Malformed LKG cache file at "${filePath}": ` +
        `"verifiedAt" must be an integer unix timestamp.`
      );
    }

    if (obj["payload"] === undefined) {
      throw new Error(
        `Malformed LKG cache file at "${filePath}": ` +
        `"payload" field is missing.`
      );
    }

    return {
      verifiedAt: obj["verifiedAt"] as number,
      payload: obj["payload"],
    };
  }

  async function atomicWrite(entry: CacheFileShape): Promise<void> {
    const tmpPath = filePath + ".tmp";
    const content = JSON.stringify({ verifiedAt: entry.verifiedAt, payload: entry.payload }, null, 2);

    const fh = await open(tmpPath, "w");
    try {
      await fh.writeFile(content, "utf8");
      await fh.sync();
    } finally {
      await fh.close();
    }

    await rename(tmpPath, filePath);

    try {
      const dirFh = await open(dirname(filePath), "r");
      try {
        await dirFh.sync();
      } catch {
        /* not all platforms support fsync on directories */
      } finally {
        await dirFh.close();
      }
    } catch {
      /* ignore */
    }
  }

  return {
    async get() {
      return readCache();
    },

    async set(payload, verifiedAt) {
      await atomicWrite({ verifiedAt, payload });
    },
  };
}
