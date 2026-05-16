// SPDX-License-Identifier: Apache-2.0
/**
 * Sift adapter → packages/guard integration test.
 *
 * Proves that the Sift adapter's receipt verification, intent normalization,
 * state normalization, and authorization construction produce output that is
 * accepted and rejected correctly by the real @oxdeai/guard enforcement path
 * (createPepGatewayExecutor).
 *
 * ── Format bridge (documented mismatches) ─────────────────────────────────────
 *
 * The Sift adapter's AuthorizationV1Payload and packages/guard's AuthorizationV1
 * have the following structural differences that require an explicit bridge:
 *
 *   1. Algorithm casing:
 *        Sift produces: signature.alg = "ed25519" (lowercase, Sift protocol)
 *        Core expects:  signature.alg = "Ed25519" (capitalized)
 *        Impact: Core's verifyAuthorization rejects "ed25519" as AUTH_ALG_UNSUPPORTED.
 *        Bridge: re-sign with Core's signEd25519 (domain-prefixed, "Ed25519" alg).
 *        This bridge is required until the Sift protocol and Core converge on casing.
 *
 *   2. Expiry field name:
 *        Sift produces: expires_at: number
 *        Core expects:  expiry: number
 *        Bridge: add expiry = expires_at; keep expires_at for audit continuity.
 *
 *   3. Intent hash computation:
 *        Sift adapter: siftCanonicalJsonHash(siftIntent) over {type, tool, params}
 *        Core default: sha256HexFromJson(action) over the same object
 *        For ASCII-only content: both produce identical SHA-256 digests.
 *        No custom hashAction is required for the reference example's ASCII params.
 *
 *   4. State hash binding:
 *        createPepGatewayExecutor does not re-verify state_hash against a live
 *        state snapshot; it is protected by the Ed25519 signature on the
 *        authorization (tampering the hash breaks the signature). This is by design:
 *        state_hash re-verification against live state is the responsibility of
 *        OxDeAIGuard (the guard function), which requires a full PolicyEngine setup.
 *
 * ── Test matrix ──────────────────────────────────────────────────────────────
 *   ALLOW            — ALLOW receipt → adapter → bridge → guard → execution
 *   DENY             — DENY receipt → adapter blocks; guard never called
 *   INTENT_MISMATCH  — valid auth, tampered action → INTENT_HASH_MISMATCH
 *   STATE_TAMPER     — valid auth with state_hash tampered → AUTH_SIGNATURE_INVALID
 *   REPLAY           — same auth used twice → AUTH_REPLAY on second call
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createPublicKey } from "node:crypto";
import type { KeyObject } from "node:crypto";
import {
  createPepGatewayExecutor,
  createInMemoryReplayStore,
} from "@oxdeai/guard";
import {
  signEd25519,
  SIGNING_DOMAINS,
} from "@oxdeai/core";
import type { AuthorizationV1, KeySet } from "@oxdeai/core";
import { startTestHarness, type TestContext } from "./harness.js";
import { fetchSiftReceipt } from "../apps/agent/client.js";
import type { AuthorizationV1Payload } from "../shared/types.js";

// ─── Format bridge ────────────────────────────────────────────────────────────

/**
 * Converts a Sift adapter AuthorizationV1Payload to a Core AuthorizationV1.
 *
 * This bridge is required because:
 *   - Sift uses alg "ed25519" (lowercase); Core requires "Ed25519" (capitalized).
 *   - Changing the alg string changes the signing payload bytes, so the
 *     original Sift signature becomes invalid for Core's verifier.
 *   - Resolution: re-sign with Core's signEd25519 using the same adapter key.
 *
 * The resulting authorization retains all semantic bindings from the Sift
 * adapter (same auth_id, intent_hash, state_hash, policy_id, audience, issuer,
 * expiry) but uses Core's signing convention.
 */
function siftAuthToCoreAuth(
  siftAuth: AuthorizationV1Payload,
  adapterPrivateKey: KeyObject
): AuthorizationV1 {
  const privateKeyPem = adapterPrivateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString();

  // Build the unsigned core-format auth. Uses flat alg/kid (no nested sig object).
  // Core's AuthorizationV1 uses 'expiry', not 'expires_at'.
  const unsigned: Omit<AuthorizationV1, "signature"> = {
    auth_id: siftAuth.auth_id,
    issuer: siftAuth.issuer,
    audience: siftAuth.audience,
    decision: "ALLOW",
    intent_hash: siftAuth.intent_hash,
    state_hash: siftAuth.state_hash,
    policy_id: siftAuth.policy_id,
    issued_at: siftAuth.issued_at,
    expiry: siftAuth.expires_at,  // bridge: Core uses 'expiry', Sift uses 'expires_at'
    alg: "Ed25519",               // bridge: Core requires capitalized 'Ed25519'
    kid: siftAuth.signature.kid,
  };

  // Re-sign using Core's domain-prefixed Ed25519 (OXDEAI_AUTH_V1\n + payload).
  const signature = signEd25519(SIGNING_DOMAINS.AUTH_V1, unsigned, privateKeyPem);
  return { ...unsigned, signature };
}

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

// ─── Helper: run the adapter ──────────────────────────────────────────────────

async function adaptAllow(): Promise<{ siftAuth: AuthorizationV1Payload; coreAuth: AuthorizationV1; intent: unknown }> {
  const envelope = await fetchSiftReceipt(ctx.mockSiftUrl, "transfer");
  const result = await ctx.adapter.adapt({
    kidAndReceipt: envelope,
    params: TRANSFER_PARAMS,
    state: TRANSFER_STATE,
  });
  assert.ok(result.ok, `Adapter must succeed: ${!result.ok ? `${result.code}: ${result.message}` : ""}`);
  if (!result.ok) throw new Error("adapter failed");

  const coreAuth = siftAuthToCoreAuth(result.authorization, ctx.adapterPrivateKey);
  return { siftAuth: result.authorization, coreAuth, intent: result.intent };
}

// ─── 1. ALLOW — full Sift → adapter → bridge → guard path ────────────────────

test("GUARD/ALLOW: Sift receipt → adapter → bridge → guard → execution succeeds", async () => {
  const { coreAuth, intent } = await adaptAllow();

  const result = await executeThroughPep({ action: intent, authorization: coreAuth });

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
  const { coreAuth } = await adaptAllow();

  // Provide a different action — the authorization's intent_hash was computed
  // over the original intent; this tampered version produces a different hash.
  const tamperedAction = { type: "EXECUTE", tool: "transfer", params: { amount: 999_999, destination: "attacker_account" } };

  const result = await executeThroughPep({ action: tamperedAction, authorization: coreAuth });

  assert.equal(result.status, 403, `Tampered action must return 403 — got ${result.status}`);
  assert.ok(
    result.body.reason?.includes("INTENT_HASH_MISMATCH"),
    `Expected INTENT_HASH_MISMATCH, got: ${result.body.reason}`
  );
  assert.equal(result.upstreamCalled, false, "Upstream must not be called on intent hash mismatch");
});

// ─── 4. STATE_TAMPER — modified state_hash breaks the signature ───────────────

test("GUARD/STATE_TAMPER: tampered state_hash invalidates signature (AUTH_SIGNATURE_INVALID)", async () => {
  const { coreAuth, intent } = await adaptAllow();

  // Tamper the state_hash field without re-signing.
  // The signature was computed over the original state_hash; modifying it
  // produces a mismatch that Core's signature verifier catches.
  const tamperedAuth: AuthorizationV1 = {
    ...coreAuth,
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

  const { coreAuth, intent } = await adaptAllow();

  // First use — must succeed.
  const first = await freshExecutor({ action: intent, authorization: coreAuth });
  assert.equal(first.status, 200, `First use must succeed — got ${first.status}`);

  // Second use with the SAME authorization — must be rejected.
  const second = await freshExecutor({ action: intent, authorization: coreAuth });
  assert.equal(second.status, 403, `Replay must return 403 — got ${second.status}`);
  assert.ok(
    second.body.reason?.includes("AUTH_REPLAY"),
    `Expected AUTH_REPLAY, got: ${second.body.reason}`
  );
  assert.equal(second.upstreamCalled, false, "Upstream must not be called on replay");
});

// ─── 6. Raw Sift auth rejected — documents the alg casing mismatch ───────────

test("GUARD/FORMAT: raw Sift adapter output fails Core verification (AUTH_ALG_UNSUPPORTED)", async () => {
  const envelope = await fetchSiftReceipt(ctx.mockSiftUrl, "transfer");
  const result = await ctx.adapter.adapt({
    kidAndReceipt: envelope,
    params: TRANSFER_PARAMS,
    state: TRANSFER_STATE,
  });
  assert.ok(result.ok, "Adapter must succeed");
  if (!result.ok) return;

  // Pass the raw Sift auth WITHOUT the bridge. Core's verifyAuthorization
  // receives alg="ed25519" (lowercase) and rejects it as AUTH_ALG_UNSUPPORTED
  // because it expects "Ed25519" (capitalized).
  const rawSiftAuth = result.authorization as unknown as AuthorizationV1;
  const pepResult = await executeThroughPep({ action: result.intent, authorization: rawSiftAuth });

  assert.equal(pepResult.status, 403, `Raw Sift auth must be rejected — got ${pepResult.status}`);
  assert.ok(
    pepResult.body.reason?.includes("AUTH_ALG_UNSUPPORTED"),
    `Expected AUTH_ALG_UNSUPPORTED (alg casing mismatch), got: ${pepResult.body.reason}`
  );
});
