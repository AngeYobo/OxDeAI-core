// SPDX-License-Identifier: Apache-2.0
/**
 * Sift adapter → packages/guard integration test.
 *
 * Proves that the Sift adapter's receipt verification, intent normalization,
 * state normalization, and authorization construction produce output that is
 * accepted and rejected correctly by the real @oxdeai/guard enforcement path
 * (createPepGatewayExecutor) WITHOUT any bridge re-signing.
 *
 * ── Wire format compatibility (documented, no bridge required) ────────────────
 *
 * The Sift adapter's AuthorizationV1Payload and packages/guard's AuthorizationV1
 * have structural differences that packages/core's verifyAuthorization accepts
 * natively as of the Sift wire format compatibility update:
 *
 *   1. Algorithm casing:
 *        Sift produces: signature.alg = "ed25519" (lowercase, Sift protocol)
 *        Core accepts:  "Ed25519" or "ed25519" — both route to Ed25519 verification.
 *
 *   2. Expiry field name:
 *        Sift produces: expires_at: number
 *        Core accepts:  expiry (primary) or expires_at (fallback)
 *
 *   3. Signature encoding:
 *        Sift produces: base64url-encoded signature bytes
 *        Core accepts:  base64 or base64url (detected by presence of '-' or '_')
 *
 *   4. Signing preimage:
 *        Sift adapter: siftCanonicalJsonBytes(signingPayload) — sorted-keys JSON, ASCII
 *        Core fallback: verifyEd25519Raw uses canonicalJson(payload) — same bytes for ASCII
 *        For ASCII-only content both produce identical SHA-256 digests.
 *
 *   5. State hash binding:
 *        createPepGatewayExecutor does not re-verify state_hash against a live
 *        state snapshot; it is protected by the Ed25519 signature on the
 *        authorization (tampering the hash breaks the signature). This is by design.
 *
 * ── Test matrix ──────────────────────────────────────────────────────────────
 *   ALLOW            — ALLOW receipt → adapter → guard → execution (no bridge)
 *   DENY             — DENY receipt → adapter blocks; guard never called
 *   INTENT_MISMATCH  — valid auth, tampered action → INTENT_HASH_MISMATCH
 *   STATE_TAMPER     — valid auth with state_hash tampered → AUTH_SIGNATURE_INVALID
 *   REPLAY           — same auth used twice → AUTH_REPLAY on second call
 *   BAD_ALG          — unsupported alg "EdDSA" is rejected (AUTH_ALG_UNSUPPORTED)
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createPublicKey } from "node:crypto";
import {
  createPepGatewayExecutor,
  createInMemoryReplayStore,
} from "@oxdeai/guard";
import type { AuthorizationV1, KeySet } from "@oxdeai/core";
import { sha256HexFromJson } from "@oxdeai/core";
import { startTestHarness, type TestContext } from "./harness.js";
import { fetchSiftReceipt } from "../apps/agent/client.js";
import { siftCanonicalJsonHash } from "../shared/canonical.js";

// ─── Test setup ───────────────────────────────────────────────────────────────

const TRANSFER_PARAMS = { amount: 100, destination: "safe_account" };
const TRANSFER_STATE  = { session_active: true, account_status: "active" };

let ctx: TestContext;
let trustedKeySets: readonly KeySet[];
let executeThroughPep: ReturnType<typeof createPepGatewayExecutor>;

before(async () => {
  ctx = await startTestHarness();

  // Derive the adapter's public key and construct a trusted KeySet for the guard.
  const adapterPublicKey = createPublicKey(ctx.adapterPrivateKey);
  const adapterPublicKeyPem = adapterPublicKey
    .export({ type: "spki", format: "pem" })
    .toString();

  trustedKeySets = [
    {
      issuer: "adapter-issuer",
      version: "v1",
      keys: [
        {
          kid: "adapter-key-1",
          alg: "Ed25519",
          public_key: adapterPublicKeyPem,
        },
      ],
    },
  ];

  executeThroughPep = createPepGatewayExecutor({
    expectedAudience: "pep-payments",
    expectedIssuer: "adapter-issuer",
    trustedKeySets,
    internalExecutorToken: "test-token-unused",
    replayStore: createInMemoryReplayStore(),
    executeUpstream: async (_action) => ({ status: 200, body: { ok: true, executed: true } }),
  });
});

after(async () => {
  await ctx.close();
});

// ─── Helper: run the adapter and return raw Sift auth ────────────────────────

async function adaptAllow(): Promise<{ rawAuth: AuthorizationV1; intent: unknown; state: unknown }> {
  const envelope = await fetchSiftReceipt(ctx.mockSiftUrl, "transfer");
  const result = await ctx.adapter.adapt({
    kidAndReceipt: envelope,
    params: TRANSFER_PARAMS,
    state: TRANSFER_STATE,
  });
  assert.ok(result.ok, `Adapter must succeed: ${!result.ok ? `${result.code}: ${result.message}` : ""}`);
  if (!result.ok) throw new Error("adapter failed");

  // Cast raw Sift adapter output directly to AuthorizationV1 — no bridge re-signing.
  // Core's verifyAuthorization accepts the Sift wire format natively:
  //   alg="ed25519" (lowercase), expires_at, base64url signature.
  const rawAuth = result.authorization as unknown as AuthorizationV1;
  return { rawAuth, intent: result.intent, state: result.state };
}

// ─── 1. ALLOW — raw Sift auth passes guard without any bridge ─────────────────

test("GUARD/ALLOW: Sift receipt → adapter → guard → execution succeeds (no bridge)", async () => {
  const { rawAuth, intent } = await adaptAllow();

  const result = await executeThroughPep({ action: intent, authorization: rawAuth });

  assert.equal(result.status, 200, `Guard must allow valid authorization — got ${result.status}: ${result.body.reason ?? ""}`);
  assert.ok(result.body.ok, "Response body must have ok: true");
  assert.ok(result.upstreamCalled, "Upstream executor must have been invoked");
});

// ─── 2. DENY — DENY receipt is blocked at the adapter (guard never called) ───

test("GUARD/DENY: Sift DENY receipt is rejected by the adapter; guard is never reached", async () => {
  const envelope = await fetchSiftReceipt(ctx.mockSiftUrl, "transfer", "DENY");
  const result = await ctx.adapter.adapt({
    kidAndReceipt: envelope,
    params: TRANSFER_PARAMS,
    state: TRANSFER_STATE,
  });

  // The adapter must fail-close on DENY; no authorization is produced.
  assert.equal(result.ok, false, "Adapter must reject a DENY receipt");
  if (result.ok) return;
  assert.equal(result.code, "DENY_DECISION", `Expected DENY_DECISION, got: ${result.code}`);
  // No call to executeThroughPep — execution never reaches the guard.
});

// ─── 3. INTENT_MISMATCH — tampered action produces hash mismatch ──────────────

test("GUARD/INTENT_MISMATCH: tampered action is rejected (intent_hash does not match)", async () => {
  const { rawAuth } = await adaptAllow();

  // Provide a different action — the authorization's intent_hash was computed
  // over the original intent; this tampered version produces a different hash.
  const tamperedAction = { type: "EXECUTE", tool: "transfer", params: { amount: 999_999, destination: "attacker_account" } };

  const result = await executeThroughPep({ action: tamperedAction, authorization: rawAuth });

  assert.equal(result.status, 403, `Tampered action must return 403 — got ${result.status}`);
  assert.ok(
    result.body.reason?.includes("INTENT_HASH_MISMATCH"),
    `Expected INTENT_HASH_MISMATCH, got: ${result.body.reason}`
  );
  assert.equal(result.upstreamCalled, false, "Upstream must not be called on intent hash mismatch");
});

// ─── 4. STATE_TAMPER — modified state_hash breaks the signature ───────────────

test("GUARD/STATE_TAMPER: tampered state_hash invalidates signature (AUTH_SIGNATURE_INVALID)", async () => {
  const { rawAuth, intent } = await adaptAllow();

  // Tamper the state_hash field without re-signing.
  // The signature was computed over the original state_hash; modifying it
  // produces a mismatch that Core's signature verifier catches.
  const tamperedAuth: AuthorizationV1 = {
    ...rawAuth,
    state_hash: "a".repeat(64),  // forged hash — same length, different value
  };

  const result = await executeThroughPep({ action: intent, authorization: tamperedAuth });

  assert.equal(result.status, 403, `Tampered state_hash must return 403 — got ${result.status}`);
  assert.ok(
    result.body.reason?.includes("AUTH_SIGNATURE_INVALID"),
    `Expected AUTH_SIGNATURE_INVALID, got: ${result.body.reason}`
  );
  assert.equal(result.upstreamCalled, false, "Upstream must not be called on signature failure");
});

// ─── 5. REPLAY — same authorization cannot be used twice ─────────────────────

test("GUARD/REPLAY: same authorization is rejected on second use (AUTH_REPLAY)", async () => {
  // Use a fresh PEP executor with its own replay store so this test
  // is isolated from the shared store in the suite-level executor.
  const freshExecutor = createPepGatewayExecutor({
    expectedAudience: "pep-payments",
    expectedIssuer: "adapter-issuer",
    trustedKeySets,
    internalExecutorToken: "test-token-unused",
    replayStore: createInMemoryReplayStore(),
    executeUpstream: async () => ({ status: 200, body: { ok: true, executed: true } }),
  });

  const { rawAuth, intent } = await adaptAllow();

  // First use — must succeed.
  const first = await freshExecutor({ action: intent, authorization: rawAuth });
  assert.equal(first.status, 200, `First use must succeed — got ${first.status}`);

  // Second use with the SAME authorization — must be rejected.
  const second = await freshExecutor({ action: intent, authorization: rawAuth });
  assert.equal(second.status, 403, `Replay must return 403 — got ${second.status}`);
  assert.ok(
    second.body.reason?.includes("AUTH_REPLAY"),
    `Expected AUTH_REPLAY, got: ${second.body.reason}`
  );
  assert.equal(second.upstreamCalled, false, "Upstream must not be called on replay");
});

// ─── 6. BAD_ALG — genuinely unsupported algorithm is still rejected ───────────

test("GUARD/BAD_ALG: unsupported alg 'EdDSA' is rejected (AUTH_ALG_UNSUPPORTED)", async () => {
  const { rawAuth, intent } = await adaptAllow();

  // Inject an unsupported alg into the nested signature object.
  // This documents that the acceptance of "ed25519" is specific and deliberate —
  // arbitrary unknown alg strings are still rejected.
  // Cast through unknown: "EdDSA" is intentionally outside AuthorizationV1's alg union.
  const badAlgAuth = {
    ...(rawAuth as unknown as Record<string, unknown>),
    signature: {
      ...(rawAuth.signature as unknown as Record<string, unknown>),
      alg: "EdDSA",
    },
  } as unknown as AuthorizationV1;

  const result = await executeThroughPep({ action: intent, authorization: badAlgAuth });

  assert.equal(result.status, 403, `Unsupported alg must return 403 — got ${result.status}`);
  assert.ok(
    result.body.reason?.includes("AUTH_ALG_UNSUPPORTED"),
    `Expected AUTH_ALG_UNSUPPORTED, got: ${result.body.reason}`
  );
  assert.equal(result.upstreamCalled, false, "Upstream must not be called on unsupported alg");
});

// ─── 7. STATE_HASH — documents the Sift adapter's state hash strategy ─────────
//
// The authorization artifact cryptographically binds state_hash via the Ed25519
// signature (signature integrity — tested in GUARD/STATE_TAMPER above).
//
// In addition, the state_hash value is computed by a specific algorithm:
//   Sift adapter: state_hash = siftCanonicalJsonHash(normalizedState)
//
// This section proves the algorithm contract and documents the requirement
// for OxDeAIGuard integration: configure computeStateHash: siftCanonicalJsonHash
// so that live-state semantic verification uses the same algorithm as the adapter.

test("GUARD/STATE_HASH/CONTRACT: adapter computes state_hash using siftCanonicalJsonHash", async () => {
  const { rawAuth, state } = await adaptAllow();

  // The adapter commits state_hash = siftCanonicalJsonHash(normalizedState).
  // Verify this is the exact algorithm.
  const expected = siftCanonicalJsonHash(state);
  assert.equal(
    rawAuth.state_hash,
    expected,
    "adapter must use siftCanonicalJsonHash for state_hash binding"
  );
});

test("GUARD/STATE_HASH/DETERMINISM: same state always produces the same state_hash", async () => {
  const { rawAuth: auth1, state: state1 } = await adaptAllow();
  const { rawAuth: auth2, state: state2 } = await adaptAllow();

  // Both calls use the same TRANSFER_STATE → same normalized state → same hash.
  assert.equal(
    auth1.state_hash,
    auth2.state_hash,
    "state_hash must be deterministic for the same input state"
  );
  assert.equal(
    siftCanonicalJsonHash(state1),
    siftCanonicalJsonHash(state2),
    "siftCanonicalJsonHash must be stable across calls with the same state"
  );
});

test("GUARD/STATE_HASH/STRATEGY: correct strategy (siftCanonicalJsonHash) produces hash matching the auth commitment", async () => {
  const { rawAuth, state } = await adaptAllow();

  // Demonstrates that configuring computeStateHash: siftCanonicalJsonHash in
  // OxDeAIGuard would produce the correct hash for state_hash verification.
  const computedWithCorrectStrategy = siftCanonicalJsonHash(state);
  assert.equal(
    computedWithCorrectStrategy,
    rawAuth.state_hash,
    "computeStateHash: siftCanonicalJsonHash produces the hash that matches the authorization's state_hash"
  );
});

test("GUARD/STATE_HASH/SIGNATURE_ONLY: createPepGatewayExecutor relies on signature integrity, not live-state re-verification", async () => {
  // createPepGatewayExecutor verifies state_hash integrity via Ed25519 signature:
  // tampering state_hash without re-signing produces AUTH_SIGNATURE_INVALID (proven in GUARD/STATE_TAMPER).
  // It does NOT re-verify state_hash against live state (no state accessor at the gateway layer).
  //
  // For live-state semantic verification (re-computing hash against current state):
  // use OxDeAIGuard with computeStateHash: siftCanonicalJsonHash configured.
  // Without this option, OxDeAIGuard would use engine.computeStateHash (Core algorithm),
  // which produces a different value than siftCanonicalJsonHash — execution would be blocked.
  //
  // This test documents the boundary: signature integrity ≠ live-state semantic verification.
  const { rawAuth, intent } = await adaptAllow();
  const result = await executeThroughPep({ action: intent, authorization: rawAuth });

  assert.equal(result.status, 200,
    "createPepGatewayExecutor accepts Sift auth when signature is valid — state_hash integrity is signature-protected"
  );
  assert.ok(result.upstreamCalled, "upstream must be called when auth passes all gateway checks");
});
