import type { AuditEvent, AuditLog } from "./AuditLog.js";
import { sha256HexFromJson } from "../crypto/hashes.js";

export type HashChainedEntry = {
  prev_hash: string;
  event: AuditEvent;
  entry_hash: string;
};

export class HashChainedLog implements AuditLog {
  private entries: HashChainedEntry[] = [];
  private lastHash: string = "0".repeat(64);

  append(event: AuditEvent): void {
    const prev = this.lastHash;
    const entry_hash = sha256HexFromJson({ prev_hash: prev, event });
    this.entries.push({ prev_hash: prev, event, entry_hash });
    this.lastHash = entry_hash;
  }

  getEvents(): readonly AuditEvent[] {
    return this.entries.map((e) => e.event);
  }

  getEntries(): readonly HashChainedEntry[] {
    return this.entries;
  }

  headHash(): string {
    return this.lastHash;
  }
}