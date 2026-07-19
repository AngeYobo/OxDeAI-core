// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE } from "@oxdeai/core";
import type { Authorization, AuthorizationV1, State } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";
import { TEST_KEYSET, TEST_KEYPAIR, signAuth } from "./helpers/fixtures.js";

import { OxDeAIGuard } from "../guard.js";
import { defaultNormalizeAction } from "../normalizeAction.js";
import {
  OxDeAIDenyError,
  OxDeAIAuthorizationError,
  OxDeAINormalizationError,
  OxDeAIGuardConfigurationError,
} from "../errors.js";
import type { ProposedAction, OxDeAIGuardConfig } from "../types.js";

// ── shared test fixtures ──────────────────────────────────────────────────────

const ENGINE_SECRET = "test-secret-must-be-at-least-32-chars!!";
const AGENT_ID = "agent-test-001";

function makeEngine(): PolicyEngine {
  return new PolicyEngine({
    policy_version: "v1",
    engine_secret: ENGINE_SECRET,
    authorization_signing_alg: "Ed25519",
    authorization_signing_kid: "k1",
    authorization_issuer: TEST_KEYSET.issuer,
    authorization_audience: "aud-test",
    authorization_ttl_seconds: 600,
    authorization_private_key_pem: TEST_KEYPAIR.privateKey.toString(),
    ...RECOMMENDED_TRUSTED_TIME_PROFILE,
  });
}

function makeState(): State {
  return buildState({
    agent_id: AGENT_ID,
    allow_action_types: ["PROVISION", "PAYMENT", "PURCHASE", "ONCHAIN_TX"],
    budget_limit: 1_000_000_000n,
    max_amount_per_action: 1_000_000_000n,
    velocity_max_actions: 1000,
    max_concurrent: 16,
  });
}

const baseAction: ProposedAction = {
  name: "provision_gpu",
  args: { asset: "a100", region: "us-east-1" },
  estimatedCost: 0.5,
  resourceType: "gpu",
  context: {
    agent_id: AGENT_ID,
    target: "gpu-pool-us-east-1",
  },
};

/** Minimal stub for Authorization — used only in mock-engine tests. */
const stubAuth: Authorization = {
  authorization_id: "stub-legacy-id",
  intent_hash: "a".repeat(64),
  policy_version: "v1",
  state_snapshot_hash: "b".repeat(64),
  decision: "ALLOW",
  expires_at: 9_999_999_999,
  engine_signature: "stub-sig",
  auth_id: "stub-v1-id",
  issuer: "test-issuer",
  audience: "test-audience",
  state_hash: "b".repeat(64),
  policy_id: "test-policy",
  issued_at: 1_000,
  expiry: 9_999_999_999,
  alg: "HMAC-SHA256",
  kid: "test-kid",
  signature: "stub-sig-v1",
};

// ── helpers ───────────────────────────────────────────────────────────────────

function makeGuardConfig(overrides: Partial<OxDeAIGuardConfig> = {}): OxDeAIGuardConfig {
  let currentState = makeState();
  let currentVersion = 0;
  return {
    engine: makeEngine(),
    getState: () => ({ state: currentState, version: currentVersion }),
    setState: (s, v) => { if (v !== currentVersion) return false; currentState = s; currentVersion++; return true; },
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
    ...overrides,
  };
}

// ── Part 1: default normalizer ────────────────────────────────────────────────

test("defaultNormalizeAction: maps ProposedAction to Intent with required fields", () => {
  const action: ProposedAction = {
    name: "provision_gpu",
    args: { asset: "a100", region: "us-east-1" },
    estimatedCost: 1.5,
    resourceType: "gpu",
    timestampSeconds: 1_700_000_000,
    context: {
      agent_id: "agent-abc",
      target: "gpu-pool",
      intent_id: "fixed-intent-id",
      nonce: 42n,
    },
  };

  const intent = defaultNormalizeAction(action);

  assert.equal(intent.intent_id, "fixed-intent-id");
  assert.equal(intent.agent_id, "agent-abc");
  assert.equal(intent.action_type, "PROVISION");
  assert.equal(intent.amount, 1_500_000n); // 1.5 * 1_000_000
  assert.equal(intent.target, "gpu-pool");
  assert.equal(intent.timestamp, 1_700_000_000);
  assert.equal(intent.nonce, 42n);
  assert.equal(typeof intent.metadata_hash, "string");
  assert.equal(intent.metadata_hash.length, 64); // sha256 hex
  assert.equal(intent.type, "EXECUTE");
});

test("defaultNormalizeAction: infers action_type from resourceType", () => {
  const action: ProposedAction = {
    name: "some_action",
    args: {},
    resourceType: "payment",
    context: { agent_id: "a1" },
  };
  const intent = defaultNormalizeAction(action);
  assert.equal(intent.action_type, "PAYMENT");
});

test("defaultNormalizeAction: infers ONCHAIN_TX from name", () => {
  const action: ProposedAction = {
    name: "onchain_transfer",
    args: {},
    context: { agent_id: "a1" },
  };
  const intent = defaultNormalizeAction(action);
  assert.equal(intent.action_type, "ONCHAIN_TX");
});

test("defaultNormalizeAction: defaults target to action.name when context.target absent", () => {
  const action: ProposedAction = {
    name: "my_action",
    args: {},
    context: { agent_id: "a1" },
  };
  const intent = defaultNormalizeAction(action);
  assert.equal(intent.target, "my_action");
});

test("defaultNormalizeAction: throws OxDeAINormalizationError when agent_id missing", () => {
  const action: ProposedAction = { name: "do_thing", args: {} };
  assert.throws(
    () => defaultNormalizeAction(action),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAINormalizationError);
      assert.ok(err.message.includes("agent_id"));
      return true;
    }
  );
});

test("defaultNormalizeAction: throws when name is empty", () => {
  const action = { name: "", args: {}, context: { agent_id: "a1" } } as ProposedAction;
  assert.throws(
    () => defaultNormalizeAction(action),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAINormalizationError);
      return true;
    }
  );
});

test("defaultNormalizeAction: throws when estimatedCost is negative", () => {
  const action: ProposedAction = {
    name: "bad_action",
    args: {},
    estimatedCost: -1,
    context: { agent_id: "a1" },
  };
  assert.throws(
    () => defaultNormalizeAction(action),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAINormalizationError);
      return true;
    }
  );
});

test("defaultNormalizeAction: metadata_hash is deterministic for same args", () => {
  const args = { z: 2, a: 1, m: "hello" };
  const a1: ProposedAction = { name: "op", args, context: { agent_id: "x" } };
  const a2: ProposedAction = { name: "op", args: { m: "hello", a: 1, z: 2 }, context: { agent_id: "x" } };
  const h1 = defaultNormalizeAction(a1).metadata_hash;
  const h2 = defaultNormalizeAction(a2).metadata_hash;
  assert.equal(h1, h2);
});

// ── Part 2: custom mapActionToIntent ──────────────────────────────────────────

test("guard: uses custom mapActionToIntent when provided", async () => {
  let mapperCalled = false;
  let currentState = makeState();
  let currentVersion = 0;

  const config: OxDeAIGuardConfig = {
    engine: makeEngine(),
    getState: () => ({ state: currentState, version: currentVersion }),
    setState: (s, v) => { if (v !== currentVersion) return false; currentState = s; currentVersion++; return true; },
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
    mapActionToIntent(action) {
      mapperCalled = true;
      // Return a well-formed intent via the default normalizer so the
      // policy engine can evaluate it, but signal that custom code ran.
      return defaultNormalizeAction({
        ...action,
        context: { ...action.context, intent_id: "custom-intent-id" },
      });
    },
  };

  const guard = OxDeAIGuard(config);
  let executed = false;
  await guard(baseAction, async () => { executed = true; });

  assert.ok(mapperCalled, "custom mapper should have been called");
  assert.ok(executed, "execute should have been called");
});

// ── Part 3: DENY blocks execution ─────────────────────────────────────────────

test("guard: DENY throws OxDeAIDenyError and does not call execute", async () => {
  // Kill switch blocks everything.
  const deniedState: State = {
    ...makeState(),
    kill_switch: { global: true, agents: {} },
  };
  let currentState = deniedState;
  let currentVersion = 0;

  const config: OxDeAIGuardConfig = {
    engine: makeEngine(),
    getState: () => ({ state: currentState, version: currentVersion }),
    setState: (s, v) => { if (v !== currentVersion) return false; currentState = s; currentVersion++; return true; },
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
  };

  const guard = OxDeAIGuard(config);
  let executed = false;

  await assert.rejects(
    () => guard(baseAction, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIDenyError, `expected OxDeAIDenyError, got ${err}`);
      assert.ok(Array.isArray(err.reasons));
      assert.ok(err.reasons.length > 0);
      return true;
    }
  );

  assert.ok(!executed, "execute must not be called on DENY");
});

test("guard: DENY fires onDecision hook with DENY decision", async () => {
  const deniedState: State = {
    ...makeState(),
    kill_switch: { global: true, agents: {} },
  };
  let currentState = deniedState;
  let currentVersion = 0;
  let decisionFired = false;
  let capturedDecision: string | undefined;

  const config: OxDeAIGuardConfig = {
    engine: makeEngine(),
    getState: () => ({ state: currentState, version: currentVersion }),
    setState: (s, v) => { if (v !== currentVersion) return false; currentState = s; currentVersion++; return true; },
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
    onDecision({ decision }) {
      decisionFired = true;
      capturedDecision = decision;
    },
  };

  const guard = OxDeAIGuard(config);
  await assert.rejects(() => guard(baseAction, async () => {}));

  assert.ok(decisionFired);
  assert.equal(capturedDecision, "DENY");
});

// ── Part 4: ALLOW executes ────────────────────────────────────────────────────

test("guard: ALLOW executes and returns the result", async () => {
  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);
  const result = await guard(baseAction, async () => "gpu-provisioned");
  assert.equal(result, "gpu-provisioned");
});

test("guard: ALLOW fires onDecision hook with ALLOW decision", async () => {
  let capturedDecision: string | undefined;
  let capturedAuth: AuthorizationV1 | undefined;

  const config = makeGuardConfig({
    onDecision({ decision, authorization }) {
      capturedDecision = decision;
      capturedAuth = authorization;
    },
  });

  const guard = OxDeAIGuard(config);
  await guard(baseAction, async () => "ok");

  assert.equal(capturedDecision, "ALLOW");
  assert.ok(capturedAuth !== undefined, "authorization should be present in ALLOW decision");
});

test("guard: ALLOW calls beforeExecute before execute", async () => {
  const callOrder: string[] = [];

  const config = makeGuardConfig({
    beforeExecute() {
      callOrder.push("beforeExecute");
    },
  });

  const guard = OxDeAIGuard(config);
  await guard(baseAction, async () => { callOrder.push("execute"); });

  assert.deepEqual(callOrder, ["beforeExecute", "execute"]);
});

// ── Part 5: missing authorization blocks execution ────────────────────────────

test("guard: ALLOW without authorization artifact throws OxDeAIAuthorizationError", async () => {
  let currentState = makeState();
  let currentVersion = 0;

  const mockEngine = {
    evaluatePure: () => ({
      decision: "ALLOW" as const,
      reasons: [] as [],
      authorization: undefined as unknown as Authorization,
      nextState: currentState,
    }),
    verifyAuthorization: () => ({ valid: true }),
  } as unknown as PolicyEngine;

  const config: OxDeAIGuardConfig = {
    engine: mockEngine,
    getState: () => ({ state: currentState, version: currentVersion }),
    setState: (s, v) => { if (v !== currentVersion) return false; currentState = s; currentVersion++; return true; },
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
  };

  const guard = OxDeAIGuard(config);
  let executed = false;

  await assert.rejects(
    () => guard(baseAction, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError, `expected OxDeAIAuthorizationError, got ${err}`);
      assert.ok(err.message.includes("authorization artifact"));
      return true;
    }
  );

  assert.ok(!executed, "execute must not be called when authorization is missing");
});

test("guard: ALLOW without nextState throws OxDeAIAuthorizationError", async () => {
  let currentState = makeState();
  let currentVersion = 0;

  const mockEngine = {
    evaluatePure: () => ({
      decision: "ALLOW" as const,
      reasons: [] as [],
      authorization: stubAuth,
      nextState: undefined as unknown as State,
    }),
    verifyAuthorization: () => ({ valid: true }),
  } as unknown as PolicyEngine;

  const config: OxDeAIGuardConfig = {
    engine: mockEngine,
    getState: () => ({ state: currentState, version: currentVersion }),
    setState: (s, v) => { if (v !== currentVersion) return false; currentState = s; currentVersion++; return true; },
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
  };

  const guard = OxDeAIGuard(config);
  let executed = false;

  await assert.rejects(
    () => guard(baseAction, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError);
      assert.ok(err.message.includes("nextState"));
      return true;
    }
  );

  assert.ok(!executed);
});

// ── Part 6: failed verifyAuthorization blocks execution ───────────────────────

test("guard: failed verifyAuthorization throws OxDeAIAuthorizationError", async () => {
  let currentState = makeState();
  let currentVersion = 0;
  // A properly-signed but expired artifact — the strict verifier will reject it with AUTH_EXPIRED.
  const expiredAuth = signAuth({ auth_id: "stub-expired", issued_at: 1_000, expiry: 2_000 });

  const mockEngine = {
    evaluatePure: () => ({
      decision: "ALLOW" as const,
      reasons: [] as [],
      authorization: expiredAuth,
      nextState: currentState,
    }),
  } as unknown as PolicyEngine;

  const config: OxDeAIGuardConfig = {
    engine: mockEngine,
    getState: () => ({ state: currentState, version: currentVersion }),
    setState: (s, v) => { if (v !== currentVersion) return false; currentState = s; currentVersion++; return true; },
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
  };

  const guard = OxDeAIGuard(config);
  let executed = false;

  await assert.rejects(
    () => guard(baseAction, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError, `expected OxDeAIAuthorizationError, got ${err}`);
      assert.ok(err.message.includes("AUTH_EXPIRED"));
      return true;
    }
  );

  assert.ok(!executed, "execute must not be called when verifyAuthorization fails");
});

// ── Part 7: nextState persists on successful execution ────────────────────────

test("guard: setState is called with nextState after successful execution", async () => {
  let storedState: State | undefined;
  const initialState = makeState();
  let storedVersion = 0;

  const config: OxDeAIGuardConfig = {
    engine: makeEngine(),
    getState: () => ({ state: initialState, version: storedVersion }),
    setState: (s, _v) => { storedState = s; storedVersion++; return true; },
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
  };

  const guard = OxDeAIGuard(config);
  await guard(baseAction, async () => "done");

  assert.ok(storedState !== undefined, "setState should have been called");
  // nextState is a well-formed State — it must have the core shape.
  assert.ok(typeof storedState!.policy_version === "string", "nextState must have policy_version");
  assert.ok(storedState!.kill_switch !== undefined, "nextState must have kill_switch");
  assert.ok(storedState!.budget !== undefined, "nextState must have budget");
});

test("guard: setState is NOT called when execution is denied", async () => {
  const deniedState: State = {
    ...makeState(),
    kill_switch: { global: true, agents: {} },
  };
  let setStateCalled = false;
  let currentState = deniedState;
  let currentVersion = 0;

  const config: OxDeAIGuardConfig = {
    engine: makeEngine(),
    getState: () => ({ state: currentState, version: currentVersion }),
    setState: (s, v) => { setStateCalled = true; if (v !== currentVersion) return false; currentState = s; currentVersion++; return true; },
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
  };

  const guard = OxDeAIGuard(config);
  await assert.rejects(() => guard(baseAction, async () => {}));

  assert.ok(!setStateCalled, "setState must not be called on DENY");
});

// ── Part 8: guard configuration errors ───────────────────────────────────────

test("OxDeAIGuard: throws OxDeAIGuardConfigurationError when engine missing", () => {
  assert.throws(
    () => OxDeAIGuard({ engine: null as unknown as PolicyEngine, getState: () => ({ state: makeState(), version: 0 }), setState: () => true, expectedAudience: "aud-test" }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIGuardConfigurationError);
      return true;
    }
  );
});

test("OxDeAIGuard: throws OxDeAIGuardConfigurationError when getState missing", () => {
  assert.throws(
    () => OxDeAIGuard({ engine: makeEngine(), getState: null as unknown as () => { state: State; version: number }, setState: () => true, expectedAudience: "aud-test" }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIGuardConfigurationError);
      return true;
    }
  );
});

// ── Part 9: normalization error propagates correctly ─────────────────────────

test("guard: normalization failure throws OxDeAINormalizationError without executing", async () => {
  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);
  let executed = false;

  const badAction = { name: "do_thing", args: {} } as ProposedAction; // missing agent_id

  await assert.rejects(
    () => guard(badAction, async () => { executed = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAINormalizationError);
      return true;
    }
  );

  assert.ok(!executed);
});

test("guard: custom mapActionToIntent throwing wraps error in OxDeAINormalizationError", async () => {
  const config = makeGuardConfig({
    mapActionToIntent() {
      throw new Error("mapper exploded");
    },
  });
  const guard = OxDeAIGuard(config);

  await assert.rejects(
    () => guard(baseAction, async () => {}),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAINormalizationError);
      assert.ok(err.message.includes("mapper exploded"));
      return true;
    }
  );
});

// ── Part 10: onDecision hook errors are swallowed ─────────────────────────────

test("guard: onDecision hook errors do not propagate", async () => {
  const config = makeGuardConfig({
    onDecision() {
      throw new Error("audit hook exploded");
    },
  });

  const guard = OxDeAIGuard(config);
  // Should not throw despite the hook error.
  const result = await guard(baseAction, async () => "ok");
  assert.equal(result, "ok");
});
