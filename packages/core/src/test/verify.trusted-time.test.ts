// SPDX-License-Identifier: Apache-2.0
/**
 * verifyTrustedTime — pure freshness-gate tests (docs/spec/core/trusted-time-v1.md §6).
 *
 * These tests exercise only the standalone verifier. They intentionally do
 * NOT cover replay, velocity, nonce, issuance, expiry, PEP, or engine
 * evaluation order — that is out of scope for this function and is deferred
 * to the integration PR referenced in the spec (§9).
 */
import test from "node:test";
import assert from "node:assert/strict";

import { verifyTrustedTime } from "../policy/verifyTrustedTime.js";
import type { VerifyTrustedTimeInput } from "../policy/verifyTrustedTime.js";

const T0 = 1_730_000_000;

function baseInput(overrides?: Partial<VerifyTrustedTimeInput>): VerifyTrustedTimeInput {
  return {
    intentTimestamp: T0,
    evaluationTime: T0,
    maxClockSkewSeconds: 300,
    maxIntentAgeSeconds: 300,
    ...overrides,
  };
}

// ── Freshness interval ──────────────────────────────────────────────────────

test("verifyTrustedTime: timestamp inside the accepted freshness interval → ALLOW", () => {
  const out = verifyTrustedTime(baseInput({ intentTimestamp: T0 + 30, evaluationTime: T0 }));
  assert.deepEqual(out, { decision: "ALLOW", reasons: [] });
});

test("verifyTrustedTime: timestamp exactly at evaluationTime → ALLOW", () => {
  const out = verifyTrustedTime(baseInput({ intentTimestamp: T0, evaluationTime: T0 }));
  assert.deepEqual(out, { decision: "ALLOW", reasons: [] });
});

// ── Future boundary (inclusive) ─────────────────────────────────────────────

test("verifyTrustedTime: timestamp exactly at evaluationTime + maxClockSkewSeconds → ALLOW (inclusive boundary)", () => {
  const out = verifyTrustedTime(
    baseInput({ evaluationTime: T0, maxClockSkewSeconds: 300, intentTimestamp: T0 + 300 })
  );
  assert.deepEqual(out, { decision: "ALLOW", reasons: [] });
});

test("verifyTrustedTime: timestamp one second beyond the future boundary → INTENT_FRESHNESS_FUTURE", () => {
  const out = verifyTrustedTime(
    baseInput({ evaluationTime: T0, maxClockSkewSeconds: 300, intentTimestamp: T0 + 301 })
  );
  assert.deepEqual(out, { decision: "DENY", reasons: ["INTENT_FRESHNESS_FUTURE"] });
});

// ── Stale boundary (inclusive) ──────────────────────────────────────────────

test("verifyTrustedTime: timestamp exactly at evaluationTime - maxIntentAgeSeconds → ALLOW (inclusive boundary)", () => {
  const out = verifyTrustedTime(
    baseInput({ evaluationTime: T0, maxIntentAgeSeconds: 300, intentTimestamp: T0 - 300 })
  );
  assert.deepEqual(out, { decision: "ALLOW", reasons: [] });
});

test("verifyTrustedTime: timestamp one second before the stale boundary → INTENT_STALE", () => {
  const out = verifyTrustedTime(
    baseInput({ evaluationTime: T0, maxIntentAgeSeconds: 300, intentTimestamp: T0 - 301 })
  );
  assert.deepEqual(out, { decision: "DENY", reasons: ["INTENT_STALE"] });
});

// ── Determinism ──────────────────────────────────────────────────────────────

test("verifyTrustedTime: repeated calls with identical inputs produce deeply identical outputs", () => {
  const input = baseInput({ intentTimestamp: T0 + 301 });
  const first = verifyTrustedTime(input);
  const second = verifyTrustedTime(input);
  const third = verifyTrustedTime(baseInput({ intentTimestamp: T0 + 301 }));
  assert.deepEqual(first, second);
  assert.deepEqual(first, third);
});

// ── Malformed configuration (trusted-caller preconditions) ─────────────────

test("verifyTrustedTime: negative maxClockSkewSeconds throws (config-invalid, refuses to evaluate)", () => {
  assert.throws(
    () => verifyTrustedTime(baseInput({ maxClockSkewSeconds: -1 })),
    /maxClockSkewSeconds/
  );
});

test("verifyTrustedTime: negative maxIntentAgeSeconds throws (config-invalid, refuses to evaluate)", () => {
  assert.throws(
    () => verifyTrustedTime(baseInput({ maxIntentAgeSeconds: -1 })),
    /maxIntentAgeSeconds/
  );
});

test("verifyTrustedTime: NaN maxClockSkewSeconds throws", () => {
  assert.throws(() => verifyTrustedTime(baseInput({ maxClockSkewSeconds: NaN })), /maxClockSkewSeconds/);
});

test("verifyTrustedTime: Infinity maxIntentAgeSeconds throws", () => {
  assert.throws(
    () => verifyTrustedTime(baseInput({ maxIntentAgeSeconds: Infinity })),
    /maxIntentAgeSeconds/
  );
});

test("verifyTrustedTime: non-integer maxClockSkewSeconds throws", () => {
  assert.throws(() => verifyTrustedTime(baseInput({ maxClockSkewSeconds: 1.5 })), /maxClockSkewSeconds/);
});

test("verifyTrustedTime: negative evaluationTime throws", () => {
  assert.throws(() => verifyTrustedTime(baseInput({ evaluationTime: -1 })), /evaluationTime/);
});

test("verifyTrustedTime: NaN evaluationTime throws", () => {
  assert.throws(() => verifyTrustedTime(baseInput({ evaluationTime: NaN })), /evaluationTime/);
});

test("verifyTrustedTime: unsafe-magnitude evaluationTime throws", () => {
  assert.throws(
    () => verifyTrustedTime(baseInput({ evaluationTime: Number.MAX_SAFE_INTEGER + 10 })),
    /evaluationTime/
  );
});

// ── Malformed intentTimestamp (attacker-reachable data) ─────────────────────

test("verifyTrustedTime: NaN intentTimestamp → DENY STATE_INVALID (not a freshness code)", () => {
  const out = verifyTrustedTime(baseInput({ intentTimestamp: NaN }));
  assert.deepEqual(out, { decision: "DENY", reasons: ["STATE_INVALID"] });
});

test("verifyTrustedTime: Infinity intentTimestamp → DENY STATE_INVALID", () => {
  const out = verifyTrustedTime(baseInput({ intentTimestamp: Infinity }));
  assert.deepEqual(out, { decision: "DENY", reasons: ["STATE_INVALID"] });
});

test("verifyTrustedTime: -Infinity intentTimestamp → DENY STATE_INVALID", () => {
  const out = verifyTrustedTime(baseInput({ intentTimestamp: -Infinity }));
  assert.deepEqual(out, { decision: "DENY", reasons: ["STATE_INVALID"] });
});

test("verifyTrustedTime: non-integer intentTimestamp → DENY STATE_INVALID", () => {
  const out = verifyTrustedTime(baseInput({ intentTimestamp: T0 + 0.5 }));
  assert.deepEqual(out, { decision: "DENY", reasons: ["STATE_INVALID"] });
});

test("verifyTrustedTime: negative intentTimestamp → DENY STATE_INVALID", () => {
  const out = verifyTrustedTime(baseInput({ intentTimestamp: -1 }));
  assert.deepEqual(out, { decision: "DENY", reasons: ["STATE_INVALID"] });
});

test("verifyTrustedTime: unsafe-magnitude intentTimestamp → DENY STATE_INVALID", () => {
  const out = verifyTrustedTime(baseInput({ intentTimestamp: Number.MAX_SAFE_INTEGER + 10 }));
  assert.deepEqual(out, { decision: "DENY", reasons: ["STATE_INVALID"] });
});

// ── Input immutability ───────────────────────────────────────────────────────

test("verifyTrustedTime: input object remains unchanged after verification", () => {
  const input = Object.freeze(
    baseInput({ intentTimestamp: T0 + 301, evaluationTime: T0, maxClockSkewSeconds: 300, maxIntentAgeSeconds: 300 })
  );
  const snapshot = { ...input };
  const out = verifyTrustedTime(input);
  assert.deepEqual(input, snapshot);
  assert.equal(out.decision, "DENY");
});

// ── Maximum-magnitude arithmetic (overflow-safe freshness, issue #183) ───────
//
// Freshness is evaluated in DIFFERENCE form (`delta = intentTimestamp -
// evaluationTime`, compared to the tolerances), not the literal spec SUM form
// (`intentTimestamp > evaluationTime + maxClockSkewSeconds`). Because
// `isProtocolSeconds` bounds every operand to `[0, MAX_SAFE_INTEGER]`, `delta`
// is always an exact safe integer, whereas `evaluationTime +
// maxClockSkewSeconds` can exceed 2^53 and lose integer precision. These cases
// pin correct behavior at the safe-integer domain edge and exercise the path
// where a naive sum would form an unsafe intermediate.

const MAX = Number.MAX_SAFE_INTEGER;

test("verifyTrustedTime: intent exactly at the future boundary with evaluationTime near MAX_SAFE_INTEGER → ALLOW", () => {
  // Future boundary = evaluationTime + skew = MAX (exactly representable); inclusive → ALLOW.
  const out = verifyTrustedTime(
    baseInput({ intentTimestamp: MAX, evaluationTime: MAX - 300, maxClockSkewSeconds: 300 })
  );
  assert.deepEqual(out, { decision: "ALLOW", reasons: [] });
});

test("verifyTrustedTime: intent one second beyond the future boundary near MAX_SAFE_INTEGER → INTENT_FRESHNESS_FUTURE", () => {
  // delta = 300, skew = 299 → strictly beyond → deny; all operands are valid safe integers.
  const out = verifyTrustedTime(
    baseInput({ intentTimestamp: MAX, evaluationTime: MAX - 300, maxClockSkewSeconds: 299 })
  );
  assert.deepEqual(out, { decision: "DENY", reasons: ["INTENT_FRESHNESS_FUTURE"] });
});

test("verifyTrustedTime: fresh intent when evaluationTime + maxClockSkewSeconds would exceed MAX_SAFE_INTEGER → ALLOW (no unsafe addition)", () => {
  // evaluationTime + maxClockSkewSeconds = MAX + 999 (beyond the safe range), yet the difference
  // form keeps delta exact, so the intent is correctly within skew. A sum-form implementation that
  // guarded or threw on the unsafe intermediate would regress this case.
  const out = verifyTrustedTime(
    baseInput({ intentTimestamp: MAX, evaluationTime: 1000, maxClockSkewSeconds: MAX - 1 })
  );
  assert.deepEqual(out, { decision: "ALLOW", reasons: [] });
});

test("verifyTrustedTime: stale boundary is exact at maximum magnitude → ALLOW at the boundary, INTENT_STALE beyond", () => {
  const atBoundary = verifyTrustedTime(
    baseInput({ intentTimestamp: MAX - 300, evaluationTime: MAX, maxIntentAgeSeconds: 300 })
  );
  assert.deepEqual(atBoundary, { decision: "ALLOW", reasons: [] });
  const beyond = verifyTrustedTime(
    baseInput({ intentTimestamp: MAX - 301, evaluationTime: MAX, maxIntentAgeSeconds: 300 })
  );
  assert.deepEqual(beyond, { decision: "DENY", reasons: ["INTENT_STALE"] });
});

test("verifyTrustedTime: intent one past MAX_SAFE_INTEGER is out of domain → DENY STATE_INVALID (not a freshness code)", () => {
  // MAX + 1 (= 2^53) is not a safe integer, so it is rejected as malformed data, never evaluated for freshness.
  const out = verifyTrustedTime(
    baseInput({ intentTimestamp: MAX + 1, evaluationTime: MAX - 300, maxClockSkewSeconds: 300 })
  );
  assert.deepEqual(out, { decision: "DENY", reasons: ["STATE_INVALID"] });
});

// ── Validation ordering: trusted preconditions before attacker input (issue #183) ──
//
// Trusted inputs (evaluationTime, config bounds) are validated BEFORE the
// attacker-controlled intentTimestamp. When BOTH a trusted input and the
// intent are malformed, the trusted-precondition failure must surface as a
// throw — never be masked as a data-driven DENY / STATE_INVALID. This pins the
// order: trusted inputs → intent timestamp → freshness.

test("verifyTrustedTime: malformed evaluationTime AND malformed intentTimestamp → throws (trusted precondition precedes STATE_INVALID)", () => {
  assert.throws(
    () => verifyTrustedTime(baseInput({ evaluationTime: NaN, intentTimestamp: NaN })),
    /evaluationTime/
  );
});

test("verifyTrustedTime: malformed config AND malformed intentTimestamp → throws (config precondition precedes STATE_INVALID)", () => {
  assert.throws(
    () => verifyTrustedTime(baseInput({ maxClockSkewSeconds: NaN, intentTimestamp: Infinity })),
    /maxClockSkewSeconds/
  );
});
