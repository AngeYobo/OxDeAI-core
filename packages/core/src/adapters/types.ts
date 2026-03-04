import type { AuditEvent } from "../audit/AuditLog.js";
import type { CanonicalState } from "../types/state.js";

/** @public */
export type MaybePromise<T> = T | Promise<T>;

/** @public */
export interface StateStore {
  get(): MaybePromise<CanonicalState | null>;
  set(state: CanonicalState): MaybePromise<void>;
}

/** @public */
export interface AuditSink {
  append(event: AuditEvent): MaybePromise<void>;
  flush?(): MaybePromise<void>;
}
