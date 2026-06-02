// SPDX-License-Identifier: Apache-2.0
/**
 * File-backed KrlWatermarkStore - reference implementation for single-node
 * deployments that require watermark persistence across process restarts.
 *
 * ── File format ───────────────────────────────────────────────────────────────
 *
 *   JSON object: { "issuer-string": version-integer, ... }
 *   Example: { "krl.issuer": 5, "other.authority.example.com": 12 }
 *
 * ── Atomicity ─────────────────────────────────────────────────────────────────
 *
 *   set() uses write-to-temp-then-rename:
 *     1. Write new content to <filePath>.tmp
 *     2. fsync the temp file
 *     3. rename() - atomic on POSIX (same filesystem)
 *     4. Best-effort directory fsync (Linux; ignored if unsupported)
 *
 *   A process kill between step 2 and step 3 leaves an orphaned .tmp file.
 *   The live path file is unchanged. On the next read the old watermarks
 *   survive - no regression attack is possible from partial writes.
 *
 * ── Single-node / single-writer only ─────────────────────────────────────────
 *
 *   set() performs a read-modify-write cycle that is NOT safe under concurrent
 *   writers. It is intended for single-process deployments only.
 *   Multi-node or multi-process deployments MUST use a database-backed
 *   KrlWatermarkStore that provides atomic compare-and-set or equivalent.
 *
 * ── Missing file ─────────────────────────────────────────────────────────────
 *
 *   list() returns {} when the file does not exist. This is the expected
 *   behavior on first use (cold start with no prior watermarks).
 *
 * ── Malformed file ────────────────────────────────────────────────────────────
 *
 *   list() throws when the file exists but is not valid JSON or does not
 *   contain a plain object of string→integer entries. This is fail-closed:
 *   SiftHttpKeyStore will block the refresh rather than silently accepting
 *   a KRL without knowing the correct version floor. Operators should delete
 *   or fix the malformed file; SiftHttpKeyStore will recover on the next
 *   refresh after the file is corrected.
 */

import { open, rename, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { KrlWatermarkStore } from "./krlWatermarkStore.js";

export type { KrlWatermarkStore };

/**
 * Creates a file-backed KrlWatermarkStore.
 *
 * @param filePath - Absolute or relative path to the JSON watermark file.
 *   The directory must already exist and be writable.
 *
 * @public
 */
export function createFileBackedKrlWatermarkStore(filePath: string): KrlWatermarkStore {
  /**
   * Reads and validates the watermark file.
   * Returns {} on missing file.
   * Throws on I/O errors or malformed content.
   */
  async function readWatermarks(): Promise<Record<string, number>> {
    let raw: string;
    try {
      raw = await readFile(filePath, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        return {}; // missing file = cold start, no prior watermarks
      }
      throw err;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new Error(
        `Malformed KRL watermark file at "${filePath}": ` +
        `content is not valid JSON. Delete or fix the file to recover.`
      );
    }

    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error(
        `Malformed KRL watermark file at "${filePath}": ` +
        `expected a JSON object but got ${Array.isArray(parsed) ? "array" : typeof parsed}.`
      );
    }

    const result: Record<string, number> = {};
    for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof k !== "string" || typeof v !== "number" || !Number.isInteger(v) || v < 0) {
        throw new Error(
          `Malformed KRL watermark file at "${filePath}": ` +
          `entry for issuer "${k}" has an invalid value (expected a non-negative integer, got ${JSON.stringify(v)}).`
        );
      }
      result[k] = v;
    }
    return result;
  }

  /**
   * Writes the watermark map to disk atomically:
   * write to temp file → fsync → rename → best-effort dir fsync.
   */
  async function atomicWrite(watermarks: Record<string, number>): Promise<void> {
    const tmpPath = filePath + ".tmp";
    const content = JSON.stringify(watermarks, null, 2);

    // Write to temp file and fsync.
    const fh = await open(tmpPath, "w");
    try {
      await fh.writeFile(content, "utf8");
      await fh.sync(); // flush data to disk before rename
    } finally {
      await fh.close();
    }

    // Atomic rename (POSIX: atomic same-filesystem; Windows: best-effort).
    await rename(tmpPath, filePath);

    // Best-effort directory fsync so the directory entry is flushed on Linux.
    // Silently ignored if the platform does not support it.
    try {
      const dirFh = await open(dirname(filePath), "r");
      try {
        await dirFh.sync();
      } catch {
        /* not all platforms support fsync on directories; ignore */
      } finally {
        await dirFh.close();
      }
    } catch {
      /* ignore */
    }
  }

  return {
    async get(issuer: string): Promise<number | undefined> {
      const all = await readWatermarks();
      return all[issuer];
    },

    async set(issuer: string, krlVersion: number): Promise<void> {
      // Read-modify-write: always raise the floor, never lower it.
      const current = await readWatermarks();
      current[issuer] = Math.max(current[issuer] ?? 0, krlVersion);
      await atomicWrite(current);
    },

    async list(): Promise<Record<string, number>> {
      return readWatermarks();
    },
  };
}
