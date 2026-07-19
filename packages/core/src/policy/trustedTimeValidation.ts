// SPDX-License-Identifier: Apache-2.0
/**
 * Shared trusted-time protocol-seconds predicate
 * (docs/spec/core/trusted-time-v1.md §5.1).
 *
 * Internal only, not exported from the package root. `verifyTrustedTime`
 * and `PolicyEngine` both import from here so the numeric domain is defined
 * exactly once. Do not duplicate this predicate elsewhere.
 */

/**
 * True iff `value` is a finite, non-negative, safe-integer unix-seconds or
 * duration-seconds value. Rejects NaN, ±Infinity, non-integers, negatives,
 * and unsafe magnitudes, never coerces.
 */
export function isProtocolSeconds(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

/**
 * Throws if `value` is not a protocol-seconds value. Used at trusted
 * precondition boundaries (constructor config, per-call `evaluationTime`)
 * where a malformed value must refuse evaluation rather than proceed on a
 * coerced or silently-invalid input (spec §5.1).
 */
export function assertProtocolSeconds(value: unknown, label: string): asserts value is number {
  if (!isProtocolSeconds(value)) {
    throw new Error(`${label} must be a finite, non-negative safe integer (unix seconds)`);
  }
}
