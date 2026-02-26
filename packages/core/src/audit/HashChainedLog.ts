import type { AuditEvent } from "./AuditLog.js";
import { sha256HexFromJson } from "../crypto/hashes.js";

type ChainedEntry = {
  event: AuditEvent;
  prev_hash: string;
  hash: string;
};

export class HashChainedLog {
  private chain: ChainedEntry[] = [];
  private head: string = "GENESIS";

  append(event: AuditEvent): string {
    const prev_hash = this.head;
    const hash = sha256HexFromJson({ prev_hash, event });
    this.chain.push({ event, prev_hash, hash });
    this.head = hash;
    return hash;
  }

  /**
   * snapshot(): read-only view of events (defensive copy).
   */
  snapshot(): AuditEvent[] {
    return this.chain.map((e) => JSON.parse(JSON.stringify(e.event)));
  }

  /**
   * headHash(): current head hash (tamper-evident pointer).
   */
  headHash(): string {
    return this.head;
  }

  drain(): AuditEvent[] {
    const out = this.chain.map((e) => structuredClone(e.event));
    this.chain = [];
    return out;
  }

  /**
   * verify(): recompute the chain and ensure hash continuity.
   * Returns false if any link is inconsistent.
   */
  verify(): boolean {
    let prev = "GENESIS";
    for (const e of this.chain) {
      if (e.prev_hash !== prev) return false;
      const expected = sha256HexFromJson({ prev_hash: e.prev_hash, event: e.event });
      if (expected !== e.hash) return false;
      prev = e.hash;
    }
    return prev === this.head;
  }
}
