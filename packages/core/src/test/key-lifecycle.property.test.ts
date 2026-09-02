// SPDX-License-Identifier: Apache-2.0
/**
 * key-lifecycle.property.test.ts
 *
 * `keyIsActiveAt(key, now)` (packages/core/src/crypto/signatures.ts) is the
 * sole gate for key status/window enforcement, called from
 * `verifyAuthorization`, `verifyDelegation`, `verifyEnvelope`, and
 * `verifySignedKrl`. Before this file, it had no dedicated `node:test`
 * coverage anywhere in the repository — the only existing coverage was the
 * data-driven conformance vector set
 * `packages/conformance/vectors/key-lifecycle-verification.json` (10
 * vectors), run through `packages/conformance/src/validate.ts`, not through
 * this package's own test suite.
 *
 * The truth table below is derived directly from the current implementation
 * and cross-checked against every one of those 10 vectors — it is not
 * invented or normalized:
 *
 *   status === "revoked"                      -> always inactive, regardless
 *                                                 of not_before/not_after
 *                                                 (vector 009: revocation
 *                                                 overrides an otherwise-valid
 *                                                 window)
 *   status ∈ {undefined, "active", "retired"} -> active iff `now` is within
 *                                                 [not_before, not_after]
 *                                                 (an absent bound is
 *                                                 unconstrained on that side)
 *
 * "retired" is deliberately NOT rejected outright — `keyIsActiveAt` treats it
 * identically to "active" for the window check. This is the documented
 * dual-sign-overlap design: vector 007 ("Retired keys are accepted during
 * dual-sign overlap window") expects `ok`, and vector 008 (retired, window
 * closed) expects `AUTH_KEY_INACTIVE`. No ambiguity was found between the
 * implementation, the conformance vectors, and this test.
 */
import test from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { generateKeyPairSync } from "node:crypto";

import { keyIsActiveAt } from "../crypto/signatures.js";
import {
  DEFAULT_MAX_FUTURE_ISSUED_AT_SKEW_SECONDS,
  signAuthorizationEd25519,
  verifyAuthorization,
} from "../verification/index.js";
import type { KeySetKey, KeySet } from "../types/keyset.js";

const NOW = 1_730_000_000;

function key(overrides: Partial<KeySetKey> = {}): KeySetKey {
  return { kid: "k", alg: "Ed25519", public_key: "", ...overrides };
}

// ── 1. Deterministic baseline: one test per conformance vector's mode ───────
// (packages/conformance/vectors/key-lifecycle-verification.json; window
// offsets below mirror that file's KL_PAST/KL_FUTURE = ∓2h relative to its
// own KL_VERIFY_NOW, applied here relative to this file's NOW.)

test("key-lifecycle-001 (active, no time constraints) -> active", () => {
  assert.equal(keyIsActiveAt(key({ status: "active" }), NOW), true);
});

test("key-lifecycle-002 (revoked) -> inactive", () => {
  assert.equal(keyIsActiveAt(key({ status: "revoked" }), NOW), false);
});

test("key-lifecycle-003 (not_before in the future) -> inactive", () => {
  assert.equal(keyIsActiveAt(key({ status: "active", not_before: NOW + 7200 }), NOW), false);
});

test("key-lifecycle-004 (not_after in the past) -> inactive", () => {
  assert.equal(keyIsActiveAt(key({ status: "active", not_after: NOW - 7200 }), NOW), false);
});

test("key-lifecycle-005 (within valid window) -> active", () => {
  assert.equal(
    keyIsActiveAt(key({ status: "active", not_before: NOW - 7200, not_after: NOW + 7200 }), NOW),
    true,
  );
});

test("key-lifecycle-006 (window fully expired) -> inactive", () => {
  assert.equal(
    keyIsActiveAt(key({ status: "active", not_before: NOW - 10_800, not_after: NOW - 7200 }), NOW),
    false,
  );
});

test("key-lifecycle-007 (retired, within window) -> active — dual-sign overlap", () => {
  assert.equal(
    keyIsActiveAt(key({ status: "retired", not_before: NOW - 7200, not_after: NOW + 7200 }), NOW),
    true,
  );
});

test("key-lifecycle-008 (retired, past window) -> inactive — retirement window closed", () => {
  assert.equal(keyIsActiveAt(key({ status: "retired", not_after: NOW - 7200 }), NOW), false);
});

test("key-lifecycle-009 (revoked, otherwise-valid window) -> inactive — revocation overrides window", () => {
  assert.equal(
    keyIsActiveAt(key({ status: "revoked", not_before: NOW - 7200, not_after: NOW + 7200 }), NOW),
    false,
  );
});

// key-lifecycle-010 (wrong kid, known issuer) is a findKeyInKeySets /
// AUTH_KID_UNKNOWN concern, not keyIsActiveAt — out of scope for this file;
// already covered by the conformance suite.

// ── 2. Properties: the full truth table, pure and through verifyAuthorization ──

const TEST_KEYPAIR = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

const FIXED_AUTH = signAuthorizationEd25519(
  {
    auth_id: "f".repeat(64),
    issuer: "issuer-KL",
    audience: "rp-KL",
    intent_hash: "a".repeat(64),
    state_hash: "b".repeat(64),
    policy_id: "c".repeat(64),
    decision: "ALLOW",
    issued_at: NOW - 10,
    expiry: NOW + 3_600,
    kid: "kid-under-test",
  },
  TEST_KEYPAIR.privateKey,
);

const statusArb = fc.constantFrom(undefined, "active" as const, "retired" as const, "revoked" as const);
const boundArb = fc.option(fc.integer({ min: NOW - 10_000, max: NOW + 10_000 }), { nil: undefined });
const nowArb = fc.integer({ min: NOW - 10_000, max: NOW + 10_000 });

function expectedActive(
  status: "active" | "retired" | "revoked" | undefined,
  not_before: number | undefined,
  not_after: number | undefined,
  now: number,
): boolean {
  return (
    status !== "revoked" &&
    (not_before === undefined || now >= not_before) &&
    (not_after === undefined || now <= not_after)
  );
}

test("property: keyIsActiveAt matches the documented status/window contract for any combination", () => {
  fc.assert(
    fc.property(statusArb, boundArb, boundArb, nowArb, (status, not_before, not_after, now) => {
      const k = key({
        ...(status !== undefined ? { status } : {}),
        ...(not_before !== undefined ? { not_before } : {}),
        ...(not_after !== undefined ? { not_after } : {}),
      });
      assert.equal(
        keyIsActiveAt(k, now),
        expectedActive(status, not_before, not_after, now),
        JSON.stringify({ status, not_before, not_after, now }),
      );
    }),
  );
});

test("property: a validly-signed authorization is accepted or rejected exactly per the key-lifecycle contract", () => {
  fc.assert(
    fc.property(statusArb, boundArb, boundArb, nowArb, (status, not_before, not_after, now) => {
      // Isolate the key-lifecycle gate: skip `now` values that would also
      // trip the unrelated AUTH_EXPIRED or AUTH_ISSUED_AT_IMPLAUSIBLE checks
      // on this fixed artifact (verifyAuthorization.ts), so a failure here can
      // only mean the key-lifecycle wiring is wrong. Discovered via an initial
      // run of this property: `now` far enough before `issued_at` trips the
      // (correct, unrelated) future-issued_at-skew check first — see the
      // property-based-testing audit report for the exact counterexample.
      fc.pre(
        now < FIXED_AUTH.expiry &&
        now >= FIXED_AUTH.issued_at - DEFAULT_MAX_FUTURE_ISSUED_AT_SKEW_SECONDS,
      );

      const k = key({
        kid: "kid-under-test",
        public_key: TEST_KEYPAIR.publicKey.toString(),
        ...(status !== undefined ? { status } : {}),
        ...(not_before !== undefined ? { not_before } : {}),
        ...(not_after !== undefined ? { not_after } : {}),
      });
      const keyset: KeySet = { issuer: "issuer-KL", version: "1", keys: [k] };

      const out = verifyAuthorization(FIXED_AUTH, {
        now,
        trustedKeySets: keyset,
        requireSignatureVerification: true,
      });

      if (expectedActive(status, not_before, not_after, now)) {
        assert.equal(
          out.status,
          "ok",
          `expected ok, got ${JSON.stringify({ status, not_before, not_after, now, violations: out.violations })}`,
        );
      } else {
        assert.equal(out.status, "invalid");
        assert.ok(
          out.violations.some((v) => v.code === "AUTH_KEY_INACTIVE"),
          `expected AUTH_KEY_INACTIVE, got ${JSON.stringify(out.violations)}`,
        );
      }
    }),
  );
});
