// SPDX-License-Identifier: Apache-2.0
/**
 * Tier 1 secure guard: trusted execution context and trusted-vs-proposer
 * provenance reconciliation (#233).
 *
 * Scenarios:
 *   P-1  depth is required and never defaulted to 0
 *   P-2  context construction validates identity and routing fields
 *   P-3  the runtime brand rejects plain and JSON-round-tripped objects
 *   P-4  TrustedExecutionContext deliberately carries no evaluationTime
 *   P-5  absent proposer claim is filled from trusted context
 *   P-6  present-and-matching claim is recorded distinctly from an absent one
 *   P-7  conflicting claim fails closed with the conflicting fields listed
 *   P-8  comparison is exact: no case folding or trimming
 *   P-9  a route without trusted tool identity records "unverified", not "matched"
 *   P-10 context-only claims (principal_id, adapter_id) are conflict-checked
 *   P-11 multiple conflicts are collected deterministically in declaration order
 *   P-12 attack L: privileged agent_id substitution is rejected by the secure path
 *   P-13 attack M: tool rename is rejected where the route supplies tool identity
 *   P-14 attack M: no closure is claimed where the route supplies no tool identity
 *   P-15 the secure path rejects an unbranded context before any side effect
 *   P-16 a conflict blocks execution and state mutation
 *   P-17 the ALLOW path executes and reports provenance to the audit hook
 *   P-18 a custom mapActionToIntent cannot overwrite a trusted premise
 */
import test from "node:test";
import assert from "node:assert/strict";
import { PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE } from "@oxdeai/core";
import type { Intent, State } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";
import { TEST_KEYSET, TEST_KEYPAIR } from "./helpers/fixtures.js";

import { createSecureGuard } from "../secureGuard.js";
import {
  createTrustedExecutionContext,
  isTrustedExecutionContext,
  type TrustedExecutionContext,
} from "../trustedContext.js";
import { reconcileWithTrustedContext } from "../provenance.js";
import { defaultNormalizeAction } from "../normalizeAction.js";
import {
  OxDeAIProvenanceConflictError,
  OxDeAIAuthorizationError,
  OxDeAIGuardConfigurationError,
} from "../errors.js";
import type { ProposedAction, OxDeAIGuardConfig } from "../types.js";

const ENGINE_SECRET = "test-secret-must-be-at-least-32-chars!!";
const AGENT_ID = "agent-test-001";
const PRIVILEGED_AGENT_ID = "agent-admin-root";

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

function makeGuardConfig(overrides: Partial<OxDeAIGuardConfig> = {}): OxDeAIGuardConfig {
  let currentState = makeState();
  let currentVersion = 0;
  return {
    engine: makeEngine(),
    getState: () => ({ state: currentState, version: currentVersion }),
    setState: (s, v) => {
      if (v !== currentVersion) return false;
      currentState = s;
      currentVersion++;
      return true;
    },
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "aud-test",
    ...overrides,
  };
}

function makeContext(overrides: Partial<TrustedExecutionContext> = {}): TrustedExecutionContext {
  return createTrustedExecutionContext({
    principalId: "principal-1",
    agentId: AGENT_ID,
    adapterId: "adapter-http",
    depth: 0,
    ...overrides,
  });
}

function makeAction(context: Record<string, unknown> = {}): ProposedAction {
  return {
    name: "provision_gpu",
    args: { asset: "a100" },
    estimatedCost: 0.5,
    resourceType: "gpu",
    context: { target: "gpu-pool", ...context },
  };
}

// ── P-1 / P-2: context construction ───────────────────────────────────────────

test("P-1 createTrustedExecutionContext: depth is required and never defaults to 0", () => {
  assert.throws(
    () =>
      createTrustedExecutionContext({
        principalId: "p",
        agentId: "a",
        adapterId: "ad",
      } as unknown as TrustedExecutionContext),
    OxDeAIGuardConfigurationError
  );

  // Explicit 0 is legitimate — the rejection is of a MISSING depth, not of a
  // root call. This is what stops "required" from being read as "non-zero".
  const ctx = createTrustedExecutionContext({
    principalId: "p",
    agentId: "a",
    adapterId: "ad",
    depth: 0,
  });
  assert.equal(ctx.depth, 0);
});

test("P-1b createTrustedExecutionContext: rejects negative and non-integer depth", () => {
  for (const depth of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(
      () => createTrustedExecutionContext({ principalId: "p", agentId: "a", adapterId: "ad", depth }),
      OxDeAIGuardConfigurationError,
      `depth ${String(depth)} must be rejected`
    );
  }
});

test("P-2 createTrustedExecutionContext: identity and routing fields must be non-empty strings", () => {
  const base = { principalId: "p", agentId: "a", adapterId: "ad", depth: 0 };
  for (const field of ["principalId", "agentId", "adapterId"] as const) {
    assert.throws(
      () => createTrustedExecutionContext({ ...base, [field]: "" }),
      OxDeAIGuardConfigurationError,
      `empty ${field} must be rejected`
    );
  }
});

// ── P-3: the brand ────────────────────────────────────────────────────────────

test("P-3 brand: a plain object with identical fields is not a trusted context", () => {
  const real = makeContext();
  assert.equal(isTrustedExecutionContext(real), true);

  const lookalike = {
    principalId: "principal-1",
    agentId: AGENT_ID,
    adapterId: "adapter-http",
    depth: 0,
  };
  assert.equal(isTrustedExecutionContext(lookalike), false);

  // A context that has been through request JSON loses the brand: the brand is
  // a non-enumerable symbol, so it does not survive serialization. This is the
  // property that makes "not constructed from request JSON" checkable.
  const roundTripped = JSON.parse(JSON.stringify(real)) as unknown;
  assert.equal(isTrustedExecutionContext(roundTripped), false);
});

// ── P-4: evaluationTime is deliberately absent ────────────────────────────────

test("P-4 TrustedExecutionContext carries no evaluationTime", () => {
  const ctx = makeContext();
  assert.equal(
    Object.prototype.hasOwnProperty.call(ctx, "evaluationTime"),
    false,
    "trusted time is captured at the evaluation boundary, not carried on the context; " +
      "a context that carried a timestamp could be reused as a time capsule"
  );
});

// ── P-5 .. P-11: reconciliation ───────────────────────────────────────────────

function normalized(context: Record<string, unknown> = {}): Intent {
  return defaultNormalizeAction(makeAction({ agent_id: AGENT_ID, ...context }));
}

test("P-5 reconcile: absent proposer claim is filled from trusted context", () => {
  const intent = defaultNormalizeAction(makeAction({ agent_id: AGENT_ID }));
  delete (intent as unknown as Record<string, unknown>)["tool"];
  const ctx = makeContext({ tool: "provision_gpu" });

  const { intent: merged, provenance } = reconcileWithTrustedContext(intent, ctx, {
    target: "gpu-pool",
  });

  assert.equal(merged.tool, "provision_gpu");
  assert.equal(provenance["tool"], "absent");
});

test("P-6 reconcile: a matching claim is recorded distinctly from an absent one", () => {
  const ctx = makeContext({ tool: "provision_gpu" });
  const intent = normalized({ tool: "provision_gpu" });
  intent.tool = "provision_gpu";

  const { intent: merged, provenance } = reconcileWithTrustedContext(intent, ctx, {
    target: "gpu-pool",
    tool: "provision_gpu",
  });

  assert.equal(merged.tool, "provision_gpu");
  assert.equal(
    provenance["tool"],
    "matched",
    "a trusted fill and a correct proposer assertion must not be indistinguishable"
  );
  assert.equal(provenance["agent_id"], "matched");
});

test("P-7 reconcile: a conflicting claim fails closed and names the field", () => {
  const ctx = makeContext();
  const intent = normalized();
  intent.agent_id = PRIVILEGED_AGENT_ID;

  let caught: unknown;
  try {
    reconcileWithTrustedContext(intent, ctx, { target: "gpu-pool" });
  } catch (e) {
    caught = e;
  }

  assert.ok(caught instanceof OxDeAIProvenanceConflictError);
  assert.deepEqual(caught.fields, ["agent_id"]);
  assert.equal(caught.provenance["agent_id"], "conflict");
});

test("P-8 reconcile: comparison is exact — case differences are conflicts", () => {
  const ctx = makeContext({ tool: "provision_gpu" });
  const intent = normalized();
  intent.tool = "PROVISION_GPU";

  assert.throws(
    () => reconcileWithTrustedContext(intent, ctx, { target: "gpu-pool" }),
    OxDeAIProvenanceConflictError,
    "no case folding: a near-match is how a rename bypass re-enters"
  );
});

test("P-9 reconcile: no trusted tool identity records unverified, not matched", () => {
  const ctx = makeContext(); // route supplies no tool
  const intent = normalized();
  intent.tool = "attacker_chosen_name";

  const { intent: merged, provenance } = reconcileWithTrustedContext(intent, ctx, {
    target: "gpu-pool",
  });

  assert.equal(merged.tool, "attacker_chosen_name", "the claim is retained, not overwritten");
  assert.equal(
    provenance["tool"],
    "unverified",
    "a route with no tool identity must not look like a verified match"
  );
});

test("P-10 reconcile: context-only claims are conflict-checked", () => {
  const ctx = makeContext();
  const intent = normalized();

  assert.throws(
    () =>
      reconcileWithTrustedContext(intent, ctx, {
        target: "gpu-pool",
        principal_id: "principal-someone-else",
      }),
    OxDeAIProvenanceConflictError
  );

  assert.throws(
    () =>
      reconcileWithTrustedContext(intent, ctx, {
        target: "gpu-pool",
        adapter_id: "adapter-other",
      }),
    OxDeAIProvenanceConflictError
  );
});

test("P-11 reconcile: multiple conflicts are collected in declaration order", () => {
  const ctx = makeContext({ tool: "provision_gpu" });
  const intent = normalized();
  intent.agent_id = PRIVILEGED_AGENT_ID;
  intent.tool = "other_tool";

  let caught: unknown;
  try {
    reconcileWithTrustedContext(intent, ctx, {
      target: "gpu-pool",
      adapter_id: "adapter-other",
    });
  } catch (e) {
    caught = e;
  }

  assert.ok(caught instanceof OxDeAIProvenanceConflictError);
  assert.deepEqual(
    caught.fields,
    ["agent_id", "tool", "adapter_id"],
    "the same conflicting request must always report the same ordered set"
  );
});

// ── P-12 .. P-18: secure guard end to end ─────────────────────────────────────

test("P-12 attack L: privileged agent_id substitution is rejected by the secure path", async () => {
  let executed = false;
  const secure = createSecureGuard(makeGuardConfig());
  const ctx = makeContext(); // authenticated principal maps to AGENT_ID

  await assert.rejects(
    () =>
      secure(ctx, makeAction({ agent_id: PRIVILEGED_AGENT_ID }), async () => {
        executed = true;
        return "done";
      }),
    OxDeAIProvenanceConflictError
  );

  assert.equal(executed, false, "L: execution must not occur on a substituted agent_id");
});

test("P-13 attack M: tool rename is rejected where the route supplies tool identity", async () => {
  let executed = false;
  const secure = createSecureGuard(makeGuardConfig());
  const ctx = makeContext({ tool: "provision_gpu" });

  await assert.rejects(
    () =>
      secure(ctx, makeAction({ agent_id: AGENT_ID, tool: "unlisted_tool_name" }), async () => {
        executed = true;
        return "done";
      }),
    OxDeAIProvenanceConflictError
  );

  assert.equal(executed, false, "M: a renamed tool must not reach execution");
});

test("P-14 attack M: no closure is claimed where the route supplies no tool identity", async () => {
  const records: Array<Record<string, unknown>> = [];
  const secure = createSecureGuard(
    makeGuardConfig({ onDecision: (r) => { records.push(r as unknown as Record<string, unknown>); } })
  );
  const ctx = makeContext(); // no trusted tool

  await secure(ctx, makeAction({ agent_id: AGENT_ID, tool: "attacker_chosen_name" }), async () => "ok");

  const provenance = records[0]?.["provenance"] as Record<string, string> | undefined;
  assert.equal(
    provenance?.["tool"],
    "unverified",
    "M is closed only for routes with authoritative tool identity; this route has none"
  );
});

test("P-15 secure guard: an unbranded context is rejected before any side effect", async () => {
  let executed = false;
  let stateWritten = false;
  const secure = createSecureGuard(
    makeGuardConfig({
      setState: () => {
        stateWritten = true;
        return true;
      },
    })
  );

  const forged = {
    principalId: "principal-1",
    agentId: AGENT_ID,
    adapterId: "adapter-http",
    depth: 0,
  } as unknown as TrustedExecutionContext;

  await assert.rejects(
    () =>
      secure(forged, makeAction({ agent_id: AGENT_ID }), async () => {
        executed = true;
        return "done";
      }),
    OxDeAIAuthorizationError
  );

  assert.equal(executed, false);
  assert.equal(stateWritten, false);
});

test("P-16 secure guard: a conflict blocks execution and state mutation", async () => {
  let executed = false;
  let stateWritten = false;
  const secure = createSecureGuard(
    makeGuardConfig({
      setState: () => {
        stateWritten = true;
        return true;
      },
    })
  );

  await assert.rejects(
    () =>
      secure(makeContext(), makeAction({ agent_id: PRIVILEGED_AGENT_ID }), async () => {
        executed = true;
        return "done";
      }),
    OxDeAIProvenanceConflictError
  );

  assert.equal(executed, false, "rejection precedes execution");
  assert.equal(stateWritten, false, "rejection precedes state mutation");
});

test("P-17 secure guard: ALLOW executes and reports provenance to the audit hook", async () => {
  const records: Array<Record<string, unknown>> = [];
  const secure = createSecureGuard(
    makeGuardConfig({ onDecision: (r) => { records.push(r as unknown as Record<string, unknown>); } })
  );

  const result = await secure(
    makeContext({ tool: "provision_gpu" }),
    makeAction({ agent_id: AGENT_ID }),
    async () => "executed"
  );

  assert.equal(result, "executed");
  assert.equal(records.length, 1);
  assert.equal(records[0]?.["decision"], "ALLOW");

  const provenance = records[0]?.["provenance"] as Record<string, string> | undefined;
  assert.ok(provenance, "the secure path must report provenance");
  assert.equal(provenance["agent_id"], "matched");
  assert.equal(provenance["tool"], "absent", "tool was filled from the trusted route");
  assert.equal(provenance["depth"], "absent");
});

test("P-18 secure guard: a custom mapActionToIntent cannot overwrite a trusted premise", async () => {
  let executed = false;
  // A deployment-supplied normalizer that returns a privileged agent_id.
  // Reconciliation runs on its OUTPUT, so this is a conflict rather than a
  // successful substitution.
  const secure = createSecureGuard(
    makeGuardConfig({
      mapActionToIntent: (action) => {
        const intent = defaultNormalizeAction({
          ...action,
          context: { ...action.context, agent_id: AGENT_ID },
        });
        intent.agent_id = PRIVILEGED_AGENT_ID;
        return intent;
      },
    })
  );

  await assert.rejects(
    () =>
      secure(makeContext(), makeAction({ agent_id: AGENT_ID }), async () => {
        executed = true;
        return "done";
      }),
    OxDeAIProvenanceConflictError
  );

  assert.equal(executed, false);
});
