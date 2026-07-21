// SPDX-License-Identifier: Apache-2.0
/**
 * scenario.ts - Deterministic delegation demo scenario runner.
 *
 * Two-agent flow:
 *
 *   Agent A (principal):
 *     1. Requests real PolicyEngine authorization for provision_gpu (100 units)
 *     2. Creates DelegationV1 to Agent B: scope { tools: ["provision_gpu"], max_amount: 30 units }
 *
 *   Agent B (delegated):
 *     3. Action 1: provision_gpu, 20 units → ALLOW (within delegation scope)
 *     4. Action 2: provision_gpu, 50 units → DENY  (exceeds delegation max_amount)
 *
 * Key invariant demonstrated:
 *   Agent A has authority up to 100 units. Delegation to B is capped at 30.
 *   Agent B cannot exceed 30 units even though Agent A could authorize 100.
 *   Authority flows without amplification.
 *
 * Agent B's actions are verified locally — no engine call, no state mutation.
 * The scope check (50 > 30) is enforced at the delegation boundary.
 *
 * No mocked decisions. Real engine evaluation for Agent A's parent auth.
 * Real delegation chain verification for Agent B.
 */

import type { AuthorizationV1 } from "@oxdeai/core";
import { createDelegation } from "@oxdeai/core";
import { OxDeAIGuard, OxDeAIDelegationError } from "@oxdeai/guard";
import type { State } from "@oxdeai/core";
import {
  engine,
  makeState,
  buildParentIntent,
  buildChildIntent,
  AGENT_A,
  AGENT_B,
  AGENT_A_PRIVATE_KEY_PEM,
  DELEGATION_MAX_AMOUNT,
  CHILD_ACTION_1_AMOUNT,
  CHILD_ACTION_2_AMOUNT,
  CHILD_ACTION_1_UNITS,
  CHILD_ACTION_2_UNITS,
  PARENT_AMOUNT,
} from "./policy.js";

// ── Step types ─────────────────────────────────────────────────────────────────

export type AgentId = "A" | "B";
export type AgentStepType = "thought" | "propose" | "execute" | "blocked" | "delegate";

export interface AgentLogEntry {
  agentId: AgentId;
  type: AgentStepType;
  label: string;
  detail?: string;
}

export interface AuthDecision {
  agentId: AgentId;
  authType: "engine" | "delegation";
  tool: string;
  args: Record<string, string | number>;
  /** For engine auth: the auth_id */
  authId?: string;
  /** For delegation: the delegation_id */
  delegationId?: string;
  /** Human-readable scope summary */
  scopeSummary?: string;
  /** Amount proposed (whole units, for display) */
  amountUnits: number;
  /** Delegation max (whole units) — for child actions */
  maxUnits?: number;
  decision: "ALLOW" | "DENY";
  reason: string;
  executionStatus: "executed" | "blocked_before_execution" | "not_applicable";
}

export interface ScenarioStep {
  agent: AgentLogEntry;
  auth?: AuthDecision;
  stateAfter?: {
    parentAuthGranted: boolean;
    delegationActive: boolean;
    delegationScope: string;
  };
}

// ── Scenario runner ────────────────────────────────────────────────────────────

export async function runScenario(): Promise<ScenarioStep[]> {
  const steps: ScenarioStep[] = [];
  let state: State = makeState();
  const ts = Math.floor(Date.now() / 1000);

  // ── Step 1: Agent A receives task ──────────────────────────────────────────
  steps.push({
    agent: {
      agentId: "A",
      type: "thought",
      label: "Task received: provision GPU cluster for compute workload",
      detail: "Orchestrating sub-agent B to handle individual GPU requests",
    },
  });

  // ── Step 2: Agent A requests engine authorization ──────────────────────────
  const parentNonce = 100n;
  const parentIntent = buildParentIntent(ts, parentNonce);

  let parentAuth: AuthorizationV1 | undefined;
  let parentDecision: "ALLOW" | "DENY" = "DENY" as "ALLOW" | "DENY";
  let parentReason = "unknown";
  let parentAuthId: string | undefined;

  const guardA = OxDeAIGuard({
    engine,
    getState: () => ({ state, version: 0 }),
    setState: (s) => { state = s; return true; },
    expectedAudience: AGENT_A,
    mapActionToIntent: () => parentIntent,
    beforeExecute(_action, authorization) {
      parentDecision = "ALLOW";
      parentReason = "within budget · tool allowed · state consistent";
      parentAuthId = authorization.auth_id;
      parentAuth = authorization;
    },
  });

  try {
    await guardA(
      { name: "provision_gpu", args: { cluster: "gpu-a100-001", units: CHILD_ACTION_1_UNITS + CHILD_ACTION_2_UNITS }, context: { agent_id: AGENT_A } },
      async () => "parent-provision-receipt"
    );
  } catch {
    parentDecision = "DENY";
    parentReason = "engine denied";
  }

  steps.push({
    agent: {
      agentId: "A",
      type: "propose",
      label: `Requesting engine authorization: provision_gpu · ${PARENT_AMOUNT / 1_000_000n} units`,
      detail: `agent: ${AGENT_A}  ·  scope: up to ${PARENT_AMOUNT / 1_000_000n} units  ·  policy: v1.0.0`,
    },
    auth: {
      agentId: "A",
      authType: "engine",
      tool: "provision_gpu",
      args: { units: Number(PARENT_AMOUNT / 1_000_000n), target: "compute-pool" },
      authId: parentAuthId,
      amountUnits: Number(PARENT_AMOUNT / 1_000_000n),
      decision: parentDecision,
      reason: parentReason,
      executionStatus: parentDecision === "ALLOW" ? "executed" : "blocked_before_execution",
    },
    stateAfter: {
      parentAuthGranted: parentDecision === "ALLOW",
      delegationActive: false,
      delegationScope: "—",
    },
  });

  if (!parentAuth) {
    // Engine denied parent auth — scenario ends early
    steps.push({
      agent: {
        agentId: "A",
        type: "blocked",
        label: "Cannot delegate: parent authorization denied",
        detail: "Engine evaluation failed — no delegation possible without parent auth",
      },
    });
    return steps;
  }

  // ── Step 3: Agent A creates delegation for Agent B ─────────────────────────
  const delegationExpiry = ts + 300; // 5 minutes, <= parent expiry (ts + 300s)

  const delegation = createDelegation(
    parentAuth,
    {
      delegatee: AGENT_B,
      scope: {
        tools: ["provision_gpu"],
        max_amount: DELEGATION_MAX_AMOUNT,
      },
      expiry: delegationExpiry,
      kid: "agent-a-demo-key",
    },
    AGENT_A_PRIVATE_KEY_PEM
  );

  steps.push({
    agent: {
      agentId: "A",
      type: "delegate",
      label: `Delegating to Agent B: max ${DELEGATION_MAX_AMOUNT / 1_000_000n} units · tool: provision_gpu`,
      detail: `delegation_id: ${delegation.delegation_id.slice(0, 22)}…  ·  parent_auth: ${parentAuthId?.slice(0, 12)}…`,
    },
    auth: {
      agentId: "A",
      authType: "delegation",
      tool: "provision_gpu",
      args: { delegatee: AGENT_B, max_amount: Number(DELEGATION_MAX_AMOUNT / 1_000_000n) },
      delegationId: delegation.delegation_id,
      scopeSummary: `tools: [provision_gpu]  ·  max: ${DELEGATION_MAX_AMOUNT / 1_000_000n} units`,
      amountUnits: Number(DELEGATION_MAX_AMOUNT / 1_000_000n),
      decision: "ALLOW",
      reason: "delegation issued  ·  scope strictly narrower than parent",
      executionStatus: "not_applicable",
    },
    stateAfter: {
      parentAuthGranted: true,
      delegationActive: true,
      delegationScope: `${DELEGATION_MAX_AMOUNT / 1_000_000n} units · provision_gpu`,
    },
  });

  // ── Step 4: Agent B action 1 — expect ALLOW (20 ≤ 30) ────────────────────
  const childNonce1 = 201n;
  const childIntent1 = buildChildIntent(AGENT_B, CHILD_ACTION_1_AMOUNT, ts, childNonce1);

  let child1Decision: "ALLOW" | "DENY" = "DENY" as "ALLOW" | "DENY";
  let child1Reason = "unknown";

  const guardB1 = OxDeAIGuard({
    engine,
    getState: () => ({ state, version: 0 }),
    setState: (s) => { state = s; return true; },
    expectedAudience: AGENT_A,
    mapActionToIntent: () => childIntent1,
    beforeExecute() {
      child1Decision = "ALLOW";
      child1Reason = `amount ${CHILD_ACTION_1_UNITS} ≤ delegation max ${DELEGATION_MAX_AMOUNT / 1_000_000n}  ·  tool allowed`;
    },
  });

  try {
    await guardB1(
      { name: "provision_gpu", args: { units: CHILD_ACTION_1_UNITS, tier: "a100" }, context: { agent_id: AGENT_B } },
      async () => "child-provision-receipt-1",
      { delegation: { delegation, parentAuth, parentScope: { tools: ["provision_gpu"], max_amount: PARENT_AMOUNT } } }
    );
  } catch (err) {
    child1Decision = "DENY";
    child1Reason = err instanceof OxDeAIDelegationError
      ? err.violations.join("  ·  ")
      : (err instanceof Error ? err.message : "unknown error");
  }

  steps.push({
    agent: {
      agentId: "B",
      type: "propose",
      label: `Agent B: provision_gpu · ${CHILD_ACTION_1_UNITS} units`,
      detail: `delegated action  ·  amount: ${CHILD_ACTION_1_UNITS} of ${DELEGATION_MAX_AMOUNT / 1_000_000n} max  ·  using parent delegation`,
    },
    auth: {
      agentId: "B",
      authType: "delegation",
      tool: "provision_gpu",
      args: { units: CHILD_ACTION_1_UNITS, tier: "a100" },
      delegationId: delegation.delegation_id,
      amountUnits: CHILD_ACTION_1_UNITS,
      maxUnits: Number(DELEGATION_MAX_AMOUNT / 1_000_000n),
      decision: child1Decision,
      reason: child1Reason,
      executionStatus: child1Decision === "ALLOW" ? "executed" : "blocked_before_execution",
    },
  });

  if (child1Decision === "ALLOW") {
    steps.push({
      agent: {
        agentId: "B",
        type: "execute",
        label: `GPU provisioned · ${CHILD_ACTION_1_UNITS} units executed`,
        detail: "receipt: child-provision-receipt-1  ·  within delegation scope",
      },
    });
  }

  // ── Step 5: Agent B action 2 — expect DENY (50 > 30) ──────────────────────
  const childNonce2 = 202n;
  const childIntent2 = buildChildIntent(AGENT_B, CHILD_ACTION_2_AMOUNT, ts + 1, childNonce2);

  let child2Decision: "ALLOW" | "DENY" = "ALLOW" as "ALLOW" | "DENY";
  let child2Reason = "unknown";

  const guardB2 = OxDeAIGuard({
    engine,
    getState: () => ({ state, version: 0 }),
    setState: (s) => { state = s; return true; },
    expectedAudience: AGENT_A,
    mapActionToIntent: () => childIntent2,
    beforeExecute() {
      child2Decision = "ALLOW"; // should not be reached
      child2Reason = "unexpectedly allowed";
    },
  });

  try {
    await guardB2(
      { name: "provision_gpu", args: { units: CHILD_ACTION_2_UNITS, tier: "a100" }, context: { agent_id: AGENT_B } },
      async () => "child-provision-receipt-2",
      { delegation: { delegation, parentAuth, parentScope: { tools: ["provision_gpu"], max_amount: PARENT_AMOUNT } } }
    );
  } catch (err) {
    child2Decision = "DENY";
    if (err instanceof OxDeAIDelegationError) {
      // Find the scope violation message
      const scopeMsg = err.violations.find(v => v.includes("max_amount")) ?? err.violations[0];
      child2Reason = scopeMsg
        ? `amount ${CHILD_ACTION_2_UNITS} exceeds delegation max_amount ${DELEGATION_MAX_AMOUNT / 1_000_000n}`
        : err.violations.join("  ·  ");
    } else {
      child2Reason = err instanceof Error ? err.message : "unknown error";
    }
  }

  steps.push({
    agent: {
      agentId: "B",
      type: "propose",
      label: `Agent B: provision_gpu · ${CHILD_ACTION_2_UNITS} units`,
      detail: `delegated action  ·  amount: ${CHILD_ACTION_2_UNITS} vs max: ${DELEGATION_MAX_AMOUNT / 1_000_000n}  ·  scope violation expected`,
    },
    auth: {
      agentId: "B",
      authType: "delegation",
      tool: "provision_gpu",
      args: { units: CHILD_ACTION_2_UNITS, tier: "a100" },
      delegationId: delegation.delegation_id,
      amountUnits: CHILD_ACTION_2_UNITS,
      maxUnits: Number(DELEGATION_MAX_AMOUNT / 1_000_000n),
      decision: child2Decision,
      reason: child2Reason,
      executionStatus: child2Decision === "ALLOW" ? "executed" : "blocked_before_execution",
    },
  });

  steps.push({
    agent: {
      agentId: "B",
      type: "blocked",
      label: "Blocked at delegation boundary  ·  tool not invoked",
      detail: `${CHILD_ACTION_2_UNITS} > ${DELEGATION_MAX_AMOUNT / 1_000_000n} max_amount  ·  Agent A retained authority over ${PARENT_AMOUNT / 1_000_000n - DELEGATION_MAX_AMOUNT / 1_000_000n} units`,
    },
    stateAfter: {
      parentAuthGranted: true,
      delegationActive: true,
      delegationScope: `${DELEGATION_MAX_AMOUNT / 1_000_000n} units · provision_gpu`,
    },
  });

  return steps;
}
