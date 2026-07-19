// SPDX-License-Identifier: Apache-2.0
/**
 * Delegation path tests for @oxdeai/guard.
 *
 * Covers the guard(action, execute, { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } })
 * execution path introduced in v2.x.
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  PolicyEngine,
  RECOMMENDED_TRUSTED_TIME_PROFILE,
  signAuthorizationEd25519,
  createDelegation,
} from "@oxdeai/core";
import type { AuthorizationV1, DelegationScope, DelegationV1 } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";

import { OxDeAIGuard } from "../guard.js";
import {
  OxDeAIAuthorizationError,
  OxDeAIDelegationError,
} from "../errors.js";
import type { ProposedAction, OxDeAIGuardConfig } from "../types.js";
import { TEST_KEYSET, TEST_KEYPAIR } from "./helpers/fixtures.js";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const T_NOW = Math.floor(Date.now() / 1000);

const PARENT_SCOPE = { tools: ["provision_gpu"], max_amount: 1_000_000n };

function makeParentAuth(overrides?: { expiry?: number; audience?: string }): AuthorizationV1 {
  return signAuthorizationEd25519(
    {
      auth_id: "f".repeat(64),
      issuer: TEST_KEYSET.issuer,
      audience: overrides?.audience ?? "agent-A",
      intent_hash: "a".repeat(64),
      state_hash: "b".repeat(64),
      policy_id: "policy-1",
      decision: "ALLOW",
      issued_at: T_NOW - 60,
      expiry: overrides?.expiry ?? T_NOW + 900,
      kid: "k1",
    },
    TEST_KEYPAIR.privateKey.toString()
  );
}

function makeDelegation(
  parentAuth: AuthorizationV1,
  overrides?: Partial<{ delegatee: string; expiry: number; tools: string[]; max_amount: bigint }>
): DelegationV1 {
  return createDelegation(
    parentAuth,
    {
      delegatee: overrides?.delegatee ?? "agent-B",
      issuer: TEST_KEYSET.issuer,
      scope: {
        tools: overrides?.tools,
        max_amount: overrides?.max_amount,
      },
      expiry: overrides?.expiry ?? T_NOW + 300,
      kid: "k1",
    },
    TEST_KEYPAIR.privateKey.toString()
  );
}

function makeGuardConfig(overrides?: Partial<OxDeAIGuardConfig>): OxDeAIGuardConfig {
  const state = buildState({
    agent_id: "agent-B",
    allow_action_types: ["PROVISION"],
    budget_limit: 1_000_000_000n,
    max_amount_per_action: 1_000_000_000n,
    velocity_max_actions: 1000,
    max_concurrent: 16,
  });
  return {
    engine: new PolicyEngine({
      policy_version: "v1",
      engine_secret: "test-secret-must-be-at-least-32-chars!!",
      authorization_signing_alg: "Ed25519",
      authorization_signing_kid: "k1",
      authorization_issuer: TEST_KEYSET.issuer,
      authorization_audience: "agent-A",
      authorization_ttl_seconds: 600,
      authorization_private_key_pem: TEST_KEYPAIR.privateKey.toString(),
      ...RECOMMENDED_TRUSTED_TIME_PROFILE,
    }),
    getState: () => ({ state, version: 0 }),
    setState: () => true,
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "agent-A",
    ...overrides,
  };
}

const baseAction: ProposedAction = {
  name: "provision_gpu",
  args: { asset: "a100" },
  estimatedCost: 0,
  context: {
    agent_id: "agent-B",
    target: "gpu-pool",
  },
  timestampSeconds: T_NOW,
};

// ── Happy path ────────────────────────────────────────────────────────────────

test("delegation: valid delegation allows execution", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);
  const config = makeGuardConfig({ trustedKeySets: TEST_KEYSET });
  const guard = OxDeAIGuard(config);

  let executed = false;
  const result = await guard(
    baseAction,
    async () => { executed = true; return "ok"; },
    { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } }
  );

  assert.ok(executed, "execute should be called on valid delegation");
  assert.equal(result, "ok");
});

test("delegation: does not call setState", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);
  let setStateCalled = false;

  const config = makeGuardConfig({ setState: () => { setStateCalled = true; return true; } });
  const guard = OxDeAIGuard(config);

  await guard(baseAction, async () => {}, { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } });

  assert.ok(!setStateCalled, "setState must not be called on delegation path");
});

test("delegation: fires onDecision ALLOW hook with delegation field", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);

  let capturedDecision: string | undefined;
  let capturedDelegation: DelegationV1 | undefined;

  const config = makeGuardConfig({
    onDecision({ decision, delegation: d }) {
      capturedDecision = decision;
      capturedDelegation = d;
    },
  });
  const guard = OxDeAIGuard(config);

  await guard(baseAction, async () => {}, { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } });

  assert.equal(capturedDecision, "ALLOW");
  assert.ok(capturedDelegation !== undefined, "delegation should be in onDecision record");
  assert.equal(capturedDelegation!.delegation_id, delegation.delegation_id);
});

test("delegation: calls beforeExecute hook", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);

  const callOrder: string[] = [];
  const config = makeGuardConfig({
    beforeExecute: () => { callOrder.push("beforeExecute"); },
  });
  const guard = OxDeAIGuard(config);

  await guard(
    baseAction,
    async () => { callOrder.push("execute"); },
    { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } }
  );

  assert.deepEqual(callOrder, ["beforeExecute", "execute"]);
});

// ── Scope enforcement ─────────────────────────────────────────────────────────

test("delegation: blocks action not in scope.tools", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth, { tools: ["query_db"] }); // not provision_gpu

  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);
  let executed = false;

  await assert.rejects(
    () => guard(baseAction, async () => { executed = true; }, { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIDelegationError, `expected OxDeAIDelegationError, got ${err}`);
      assert.ok(err.violations.some((v) => v.includes("provision_gpu")));
      return true;
    }
  );
  assert.ok(!executed);
});

test("delegation: allows action in scope.tools", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth, { tools: ["provision_gpu"] });

  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);

  let executed = false;
  await guard(baseAction, async () => { executed = true; }, { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } });
  assert.ok(executed);
});

test("delegation: blocks intent amount exceeding scope.max_amount", async () => {
  const parentAuth = makeParentAuth();
  // max_amount = 0n, action estimatedCost = 1.0 → amount = 1_000_000n
  const delegation = makeDelegation(parentAuth, { max_amount: 0n });

  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);
  let executed = false;

  const expensiveAction: ProposedAction = { ...baseAction, estimatedCost: 1.0 };

  await assert.rejects(
    () => guard(expensiveAction, async () => { executed = true; }, { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIDelegationError);
      assert.ok(err.violations.some((v) => v.includes("max_amount")));
      return true;
    }
  );
  assert.ok(!executed);
});

// ── Chain verification failures ───────────────────────────────────────────────

test("delegation: blocks expired delegation", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth, { expiry: T_NOW - 1 }); // already expired

  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);
  let executed = false;

  await assert.rejects(
    () => guard(baseAction, async () => { executed = true; }, { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIDelegationError);
      assert.ok(err.violations.some((v) => v.toLowerCase().includes("expir")));
      return true;
    }
  );
  assert.ok(!executed);
});

test("delegation: blocks when parent hash mismatches", async () => {
  const parentAuth = makeParentAuth();
  const otherAuth = makeParentAuth({ audience: "agent-X" });
  const delegation = makeDelegation(parentAuth); // bound to parentAuth

  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);
  let executed = false;

  // Present with the wrong parent
  await assert.rejects(
    () => guard(baseAction, async () => { executed = true; }, { delegation: { delegation, parentAuth: otherAuth, parentScope: PARENT_SCOPE } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIDelegationError);
      return true;
    }
  );
  assert.ok(!executed);
});

test("delegation: blocks invalid signature when requireDelegationSignatureVerification", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);
  const tampered = { ...delegation, delegatee: "agent-EVIL" }; // breaks signature

  const config = makeGuardConfig({ trustedKeySets: TEST_KEYSET });
  const guard = OxDeAIGuard(config);
  let executed = false;

  await assert.rejects(
    () => guard(baseAction, async () => { executed = true; }, { delegation: { delegation: tampered, parentAuth, parentScope: PARENT_SCOPE } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIDelegationError);
      return true;
    }
  );
  assert.ok(!executed);
});

test("delegation: blocks when delegation and parentAuth are missing from input", async () => {
  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);

  await assert.rejects(
    () => guard(baseAction, async () => {}, {
      delegation: { delegation: null as unknown as DelegationV1, parentAuth: null as unknown as AuthorizationV1, parentScope: {} }
    }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError);
      return true;
    }
  );
});

// ── OxDeAIDelegationError is-a OxDeAIAuthorizationError ───────────────────────

test("OxDeAIDelegationError is instanceof OxDeAIAuthorizationError", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth, { expiry: T_NOW - 1 });

  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);

  await assert.rejects(
    () => guard(baseAction, async () => {}, { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError, "OxDeAIDelegationError must be catchable as OxDeAIAuthorizationError");
      assert.ok(err instanceof OxDeAIDelegationError, "and also as OxDeAIDelegationError");
      assert.ok(Array.isArray((err as OxDeAIDelegationError).violations));
      return true;
    }
  );
});

// ── parentScope validation ────────────────────────────────────────────────────

test("delegation: missing parentScope blocks before chain verification", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);
  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);
  let executed = false;

  await assert.rejects(
    () => guard(
      baseAction,
      async () => { executed = true; },
      { delegation: { delegation, parentAuth, parentScope: undefined as unknown as DelegationScope } }
    ),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError);
      assert.ok(!(err instanceof OxDeAIDelegationError), "missing parentScope must be OxDeAIAuthorizationError, not delegation error");
      assert.match((err as Error).message, /parent authorization scope/i);
      return true;
    }
  );
  assert.ok(!executed, "execute must not be called when parentScope is missing");
});

test("delegation: malformed parentScope (non-object) blocks before chain verification", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);
  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);
  let executed = false;

  await assert.rejects(
    () => guard(
      baseAction,
      async () => { executed = true; },
      { delegation: { delegation, parentAuth, parentScope: "not-an-object" as unknown as DelegationScope } }
    ),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError);
      assert.ok(!(err instanceof OxDeAIDelegationError));
      assert.match((err as Error).message, /parent authorization scope/i);
      return true;
    }
  );
  assert.ok(!executed, "execute must not be called when parentScope is malformed");
});

test("delegation: malformed parentScope (tools not array) blocks before chain verification", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);
  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);
  let executed = false;

  await assert.rejects(
    () => guard(
      baseAction,
      async () => { executed = true; },
      { delegation: { delegation, parentAuth, parentScope: { tools: "not-an-array" } as unknown as DelegationScope } }
    ),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError);
      assert.ok(!(err instanceof OxDeAIDelegationError));
      assert.match((err as Error).message, /parent authorization scope/i);
      return true;
    }
  );
  assert.ok(!executed, "execute must not be called when parentScope.tools is not an array");
});

test("delegation: valid empty parentScope ({}) is accepted", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);
  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);
  let executed = false;

  // An empty scope ({}) places no restrictions — all tools and amounts allowed.
  await guard(
    baseAction,
    async () => { executed = true; },
    { delegation: { delegation, parentAuth, parentScope: {} } }
  );
  assert.ok(executed, "execute must be called when parentScope is a valid empty object");
});

// ── Standard path unaffected ──────────────────────────────────────────────────

test("standard path: unaffected when no opts.delegation provided", async () => {
  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);

  const result = await guard(baseAction, async () => "standard-ok");
  assert.equal(result, "standard-ok");
});
