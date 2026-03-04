import { appendFile, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";

import { canonicalJson } from "../crypto/hashes.js";
import { decodeCanonicalState, encodeCanonicalState } from "../snapshot/CanonicalCodec.js";
import type { AuditEvent } from "../audit/AuditLog.js";
import type { CanonicalState } from "../types/state.js";
import type { AuditSink, StateStore } from "./types.js";

/** @public */
export class FileStateStore implements StateStore {
  private readonly path: string;

  constructor(path: string) {
    this.path = path;
  }

  async get(): Promise<CanonicalState | null> {
    try {
      const bytes = await readFile(this.path);
      return decodeCanonicalState(Uint8Array.from(bytes));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw error;
    }
  }

  async set(state: CanonicalState): Promise<void> {
    const bytes = encodeCanonicalState(state);
    const dir = dirname(this.path);
    const tmp = `${this.path}.tmp-${randomUUID()}`;

    await mkdir(dir, { recursive: true });
    await writeFile(tmp, bytes);
    await rename(tmp, this.path);
  }
}

/** @public */
export class FileAuditSink implements AuditSink {
  private readonly path: string;
  private readonly mode: "ndjson";
  private queue: Promise<void> = Promise.resolve();

  constructor(path: string, opts?: { mode?: "ndjson" }) {
    this.path = path;
    this.mode = opts?.mode ?? "ndjson";
  }

  append(event: AuditEvent): Promise<void> {
    if (this.mode !== "ndjson") {
      return Promise.reject(new Error(`unsupported audit sink mode: ${this.mode}`));
    }

    // One canonical JSON object per line (NDJSON).
    const line = `${canonicalJson(event)}\n`;

    this.queue = this.queue.then(async () => {
      await mkdir(dirname(this.path), { recursive: true });
      await appendFile(this.path, line, "utf8");
    });

    return this.queue;
  }

  flush(): Promise<void> {
    return this.queue;
  }
}
