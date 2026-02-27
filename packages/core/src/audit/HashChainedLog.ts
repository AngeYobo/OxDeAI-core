import { createHash } from "node:crypto";
import type { AuditEvent } from "./AuditLog.js";
import { canonicalJson } from "../crypto/hashes.js";

type ChainedEntry = {
  event: AuditEvent;
  prev_hash: string;
  hash: string;
};

type AuditEntryLike = AuditEvent;

export class HashChainedLog {
  private chain: ChainedEntry[] = [];
  private head: string = "GENESIS";

  private canonicalizeEntry(e: AuditEntryLike): Uint8Array {
    const normalized = {
      ...e,
      // Always include policyId in canonical bytes (null when absent).
      policyId: e.policyId ?? null
    };
    return new TextEncoder().encode(canonicalJson(normalized));
  }

  private computeNextHash(prev_hash: string, event: AuditEntryLike): string {
    const canonicalEvent = this.canonicalizeEntry(event);
    return createHash("sha256")
      .update(prev_hash, "utf8")
      .update("\n", "utf8")
      .update(canonicalEvent)
      .digest("hex");
  }

  append(event: AuditEvent): string {
    const prev_hash = this.head;
    const hash = this.computeNextHash(prev_hash, event);
    this.chain.push({ event, prev_hash, hash });
    this.head = hash;
    return hash;
  }

  /**
   * snapshot(): read-only view of events (defensive copy).
   */
  snapshot(): AuditEvent[] {
    return this.chain.map((e) => structuredClone(e.event));
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
      const expected = this.computeNextHash(e.prev_hash, e.event);
      if (expected !== e.hash) return false;
      prev = e.hash;
    }
    return prev === this.head;
  }
}
