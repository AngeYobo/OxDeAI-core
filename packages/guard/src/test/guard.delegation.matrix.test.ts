// SPDX-License-Identifier: Apache-2.0
/**
 * Delegation matrix — packages/guard
 *
 * Covers cases 7 and 8 of the DelegationV1 test matrix:
 *   CASE-7: Guard integration success — execution callback runs
 *   CASE-8: Guard integration failure — execution callback never runs
 *
 * Complements guard.delegation.test.ts (broader happy-path / edge-case coverage)
 * and delegation.matrix.test.ts in packages/core (cases 1–6, 9).
 *
 * All timestamps are fixed integers.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  PolicyEngine,
  signAuthorizationEd25519,
  createDelegation,
} from "@oxdeai/core";
import type { AuthorizationV1, DelegationV1, KeySet } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";
import { OxDeAIGuard } from "../guard.js";
import {
  OxDeAIAuthorizationError,
  OxDeAIDelegationError,
} from "../errors.js";
import type { ProposedAction, OxDeAIGuardConfig } from "../types.js";

// ── Fixed key material ────────────────────────────────────────────────────────

const KEYS = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

const KEYSET: KeySet = {
  issuer: "pdp-issuer",
  version: "1",
  keys: [{ kid: "k1", alg: "Ed25519", public_key: KEYS.publicKey.toString() }],
};

// ── Trusted timestamps (relative to wall clock) ──────────────────────────────
const T_NOW     = Math.floor(Date.now() / 1000);
const T_ISSUED  = T_NOW - 60;
const T_DEL_EXP = T_NOW + 600;
const T_PAR_EXP = T_NOW + 900;

// ── Fixtures ──────────────────────────────────────────────────────────────────

const PARENT_SCOPE = { tools: ["provision_gpu"], max_amount: 1_000_000n };

function makeParent(overrides?: { expiry?: number; audience?: string }): AuthorizationV1 {
  return signAuthorizationEd25519(
    {
      auth_id:     "f".repeat(64),
      issuer:      "pdp-issuer",
      audience:    overrides?.audience ?? "agent-A",
      intent_hash: "a".repeat(64),
      state_hash:  "b".repeat(64),
      policy_id:   "policy-1",
      decision:    "ALLOW",
      issued_at:   T_ISSUED,
      expiry:      overrides?.expiry ?? T_PAR_EXP,
      kid:         "k1",
    },
    KEYS.privateKey
  );
}

function makeGuard(overrides?: Partial<OxDeAIGuardConfig>) {
  const state = buildState({
    agent_id: "agent-B",
    allow_action_types: ["PROVISION"],
    budget_limit: 1_000_000_000n,
    max_amount_per_action: 1_000_000_000n,
    velocity_max_actions: 1000,
    max_concurrent: 16,
  });
  return OxDeAIGuard({
    engine: new PolicyEngine({ policy_version: "v1", engine_secret: "test-secret-must-be-at-least-32-chars!!" }),
    getState: () => ({ state, version: 0 }),
    setState: () => true,
    trustedKeySets: [KEYSET],
    expectedAudience: "agent-A",
    ...overrides,
  });
}

// Action timestamp is fixed to T_NOW — the guard uses intent.timestamp as `now`
const action: ProposedAction = {
  name: "provision_gpu",
  args: { asset: "a100" },
  estimatedCost: 0,
  resourceType: "gpu",
  context: { agent_id: "agent-B", target: "gpu-pool" },
  timestampSeconds: T_NOW,
};

// ── CASE 7: Guard integration success ────────────────────────────────────────

test("CASE-7a: valid chain with signature verification → execute runs", async () => {
  const parent = makeParent();
  const delegation = createDelegation(
    parent,
    { delegatee: "agent-B", issuer: KEYSET.issuer, scope: { tools: ["provision_gpu"] }, expiry: T_DEL_EXP, kid: "k1" },
    KEYS.privateKey
  );

  const guard = makeGuard();
  let executed = false;

  const result = await guard(
    action,
    async () => { executed = true; return "executed"; },
    { delegation: { delegation, parentAuth: parent, parentScope: PARENT_SCOPE } }
  );

  assert.ok(executed, "execute must be called on valid delegation");
  assert.equal(result, "executed");
});

test("CASE-7b: unsigned delegation is rejected (fail-closed)", async () => {
  const parent = makeParent();
  const delegation = createDelegation(
    parent,
    { delegatee: "agent-B", issuer: KEYSET.issuer, scope: { tools: ["provision_gpu"] }, expiry: T_DEL_EXP, kid: "k1" },
    KEYS.privateKey
  );
  (delegation as any).signature = "";

  const guard = makeGuard();
  await assert.rejects(
    () => guard(action, async () => {}, { delegation: { delegation, parentAuth: parent, parentScope: PARENT_SCOPE } }),
    /signature is required|DELEGATION_SIGNATURE_INVALID|Authorization verification failed/i
  );
});

test("CASE-7c: delegation path does not call setState", async () => {
  const parent = makeParent();
  const delegation = createDelegation(
    parent,
    { delegatee: "agent-B", issuer: KEYSET.issuer, scope: { tools: ["provision_gpu"] }, expiry: T_DEL_EXP, kid: "k1" },
    KEYS.privateKey
  );

  let setStateCalled = false;
  const guard = makeGuard({ setState: () => { setStateCalled = true; return true; } });

  await guard(action, async () => {}, { delegation: { delegation, parentAuth: parent, parentScope: PARENT_SCOPE } });

  assert.ok(!setStateCalled, "setState must NOT be called on delegation path");
});

test("CASE-7d: onDecision fires ALLOW with delegation artifact present", async () => {
  const parent = makeParent();
  const delegation = createDelegation(
    parent,
    { delegatee: "agent-B", issuer: KEYSET.issuer, scope: { tools: ["provision_gpu"] }, expiry: T_DEL_EXP, kid: "k1", delegationId: "d-audit-test" },
    KEYS.privateKey
  );

  let capturedDecision: string | undefined;
  let capturedDelegationId: string | undefined;

  const guard = makeGuard({
    onDecision({ decision, delegation: d }) {
      capturedDecision = decision;
      capturedDelegationId = d?.delegation_id;
    },
  });

  await guard(action, async () => {}, { delegation: { delegation, parentAuth: parent, parentScope: PARENT_SCOPE } });

  assert.equal(capturedDecision, "ALLOW");
  assert.equal(capturedDelegationId, "d-audit-test");
});

test("CASE-7e: beforeExecute is called before execute on delegation path", async () => {
  const parent = makeParent();
  const delegation = createDelegation(
    parent,
    { delegatee: "agent-B", issuer: KEYSET.issuer, scope: { tools: ["provision_gpu"] }, expiry: T_DEL_EXP, kid: "k1" },
    KEYS.privateKey
  );

  const order: string[] = [];
  const guard = makeGuard({
    beforeExecute: () => { order.push("before"); },
  });

  await guard(action, async () => { order.push("execute"); }, { delegation: { delegation, parentAuth: parent, parentScope: PARENT_SCOPE } });

  assert.deepEqual(order, ["before", "execute"]);
});

// ── CASE 8: Guard integration failure — execute must never run ────────────────

test("CASE-8a: expired delegation → OxDeAIDelegationError, execute blocked", async () => {
  const parent = makeParent();
  const delegation = createDelegation(
    parent,
    { delegatee: "agent-B", issuer: KEYSET.issuer, scope: { tools: ["provision_gpu"] }, expiry: T_NOW - 1, kid: "k1" }, // expired
    KEYS.privateKey
  );

  const guard = makeGuard();
  let executed = false;

  await assert.rejects(
    () => guard(action, async () => { executed = true; }, { delegation: { delegation, parentAuth: parent, parentScope: PARENT_SCOPE } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIDelegationError);
      assert.ok(err.violations.length > 0);
      return true;
    }
  );
  assert.ok(!executed);
});

test("CASE-8b: tampered delegation signature → OxDeAIDelegationError, execute blocked", async () => {
  const parent = makeParent();
  const delegation = createDelegation(
    parent,
    { delegatee: "agent-B", issuer: KEYSET.issuer, scope: { tools: ["provision_gpu"] }, expiry: T_DEL_EXP, kid: "k1" },
    KEYS.privateKey
  );
  const tampered: DelegationV1 = { ...delegation, delegatee: "agent-EVIL" };

  const guard = makeGuard();
  let executed = false;

  await assert.rejects(
    () => guard(action, async () => { executed = true; }, { delegation: { delegation: tampered, parentAuth: parent, parentScope: PARENT_SCOPE } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIDelegationError);
      return true;
    }
  );
  assert.ok(!executed);
});

test("CASE-8c: action not in scope.tools → OxDeAIDelegationError, execute blocked", async () => {
  const parent = makeParent();
  const delegation = createDelegation(
    parent,
    { delegatee: "agent-B", issuer: KEYSET.issuer, scope: { tools: ["query_db"] }, expiry: T_DEL_EXP, kid: "k1" },
    KEYS.privateKey
  );

  const guard = makeGuard();
  let executed = false;

  await assert.rejects(
    () => guard(action, async () => { executed = true; }, { delegation: { delegation, parentAuth: parent, parentScope: PARENT_SCOPE } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIDelegationError);
      assert.ok(err.violations.some((v) => v.includes("provision_gpu")));
      return true;
    }
  );
  assert.ok(!executed);
});

test("CASE-8d: parent hash mismatch → OxDeAIDelegationError, execute blocked", async () => {
  const parent = makeParent();
  const otherParent = makeParent({ audience: "agent-OTHER" });
  const delegation = createDelegation(
    parent,
    { delegatee: "agent-B", issuer: KEYSET.issuer, scope: { tools: ["provision_gpu"] }, expiry: T_DEL_EXP, kid: "k1" },
    KEYS.privateKey
  );

  const guard = makeGuard();
  let executed = false;

  // Delegation bound to `parent` but presented with `otherParent`
  await assert.rejects(
    () => guard(action, async () => { executed = true; }, { delegation: { delegation, parentAuth: otherParent, parentScope: PARENT_SCOPE } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIDelegationError);
      return true;
    }
  );
  assert.ok(!executed);
});

test("CASE-8e: OxDeAIDelegationError is catchable as OxDeAIAuthorizationError", async () => {
  const parent = makeParent();
  const delegation = createDelegation(
    parent,
    { delegatee: "agent-B", issuer: KEYSET.issuer, scope: { tools: ["provision_gpu"] }, expiry: T_NOW - 1, kid: "k1" },
    KEYS.privateKey
  );

  const guard = makeGuard();

  await assert.rejects(
    () => guard(action, async () => {}, { delegation: { delegation, parentAuth: parent, parentScope: PARENT_SCOPE } }),
    (err: unknown) => {
      // Existing catch blocks for OxDeAIAuthorizationError remain valid
      assert.ok(err instanceof OxDeAIAuthorizationError, "must be catchable as OxDeAIAuthorizationError");
      assert.ok(err instanceof OxDeAIDelegationError, "and narrowable to OxDeAIDelegationError");
      return true;
    }
  );
});

test("CASE-8f: setState is NOT called when delegation verification fails", async () => {
  const parent = makeParent();
  const delegation = createDelegation(
    parent,
    { delegatee: "agent-B", issuer: KEYSET.issuer, scope: { tools: ["provision_gpu"] }, expiry: T_NOW - 1, kid: "k1" },
    KEYS.privateKey
  );

  let setStateCalled = false;
  const guard = makeGuard({ setState: () => { setStateCalled = true; return true; } });

  await assert.rejects(() => guard(action, async () => {}, { delegation: { delegation, parentAuth: parent, parentScope: PARENT_SCOPE } }));

  assert.ok(!setStateCalled, "setState must not be called when delegation fails");
});
