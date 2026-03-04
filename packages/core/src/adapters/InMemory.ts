import type { AuditEvent } from "../audit/AuditLog.js";
import type { CanonicalState } from "../types/state.js";
import type { AuditSink, StateStore } from "./types.js";

/** @public */
export class InMemoryStateStore implements StateStore {
  private state: CanonicalState | null = null;

  get(): CanonicalState | null {
    return this.state === null ? null : structuredClone(this.state);
  }

  set(state: CanonicalState): void {
    this.state = structuredClone(state);
  }
}

/** @public */
export class InMemoryAuditSink implements AuditSink {
  private events: AuditEvent[] = [];

  append(event: AuditEvent): void {
    this.events.push(structuredClone(event));
  }

  drain(): AuditEvent[] {
    const out = this.events.map((e) => structuredClone(e));
    this.events = [];
    return out;
  }
}
