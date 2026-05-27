// SPDX-License-Identifier: Apache-2.0
/**
 * scenario.ts - Deterministic demo scenario runner.
 *
 * The same charge_wallet proposal is evaluated twice by the real OxDeAI engine:
 *
 *   1. charge_wallet(user_123, 10) → ALLOW
 *      State is consistent: no prior side effect recorded for this intent.
 *      Side effect is committed. State updates.
 *
 *   2. charge_wallet(user_123, 10) → DENY
 *      Same intent. Same tool. Same agent. Same capability.
 *      State is no longer consistent: side effect is already recorded.
 *      Engine denies before execution. Tool is never invoked.
 *
 * This demonstrates authorization semantics:
 *   (intent + current state + policy) → ALLOW or DENY
 * Not replay detection. The same logical proposal produces a different
 * authorization decision because the state changed after the first execution.
 *
 * No mocked decisions. Real policy evaluation on every call.
 */

import type { AuthorizationV1, State } from "@oxdeai/core";
import { OxDeAIGuard, OxDeAIDenyError } from "@oxdeai/guard";
import { engine, makeState, buildChargeIntent, AGENT_ID, WALLET_START } from "./policy.js";

// ── Step types ────────────────────────────────────────────────────────────────

export type AgentStepType = "thought" | "propose" | "execute" | "blocked";

export interface AgentLogEntry {
  type: AgentStepType;
  label: string;
  detail?: string;
}

export interface AuthDecision {
  tool: string;
  args: Record<string, string | number>;
  /** Stable across both calls - proves this is the same logical proposal, not a new one */
  intentId: string;
  /** Human-readable description of the intended effect */
  intentSummary: string;
  stateSnapshot: Record<string, string | number | boolean>;
  policyCheck: string;
  decision: "ALLOW" | "DENY";
  reason: string;
  /** Whether the tool was actually invoked after this decision */
  executionStatus: "executed" | "blocked_before_execution";
  authId?: string;
}

export interface ScenarioStep {
  agent: AgentLogEntry;
  auth?: AuthDecision;
  /** State chip values to update after this step renders */
  stateAfter?: {
    walletBalance: string;
    alreadyCharged: boolean;
  };
}

// ── Scenario runner ───────────────────────────────────────────────────────────

export async function runScenario(): Promise<ScenarioStep[]> {
  const steps: ScenarioStep[] = [];
  let state: State = makeState();
  const ts = Math.floor(Date.now() / 1000);
  // Single stable intent reused across both calls.
  // Only the state changes between evaluations — not the proposal.
  const chargeIntent = buildChargeIntent(ts);

  // ── Step 1: Agent receives task ──────────────────────────────────────────
  steps.push({
    agent: {
      type: "thought",
      label: "Task received",
      detail: "Charge user_123 wallet 10 units for completed order #42",
    },
  });

  // ── Step 2: First proposal - expect ALLOW ────────────────────────────────
  let firstDecision: "ALLOW" | "DENY" = "DENY" as "ALLOW" | "DENY";
  let firstReason = "unknown";
  let firstAuthId: string | undefined;

  const guard1 = OxDeAIGuard({
    engine,
    getState: () => ({ state, version: 0 }),
    setState: (s) => { state = s; return true; },
    expectedAudience: AGENT_ID,
    // chargeIntent is identical for both calls — only state differs
    mapActionToIntent: () => chargeIntent,
    beforeExecute(_action: unknown, authorization: AuthorizationV1) {
      firstAuthId = authorization.auth_id;
      firstDecision = "ALLOW";
      firstReason = "state consistent · no prior side effect recorded for this intent";
    },
  });

  try {
    await guard1(
      { name: "charge_wallet", args: { user: "user_123", amount: 10 }, context: { agent_id: AGENT_ID } },
      async () => "charge-receipt-001"
    );
  } catch (err) {
    if (err instanceof OxDeAIDenyError) {
      const reasons = [...(err as OxDeAIDenyError).reasons];
      firstDecision = "DENY";
      firstReason = reasons.join(", ");
    } else {
      throw err;
    }
  }

  steps.push({
    agent: {
      type: "propose",
      label: "Proposing charge_wallet(user_123, 10)",
      detail: "intent: charge-user123-order42  ·  logical operation: charge order #42",
    },
    auth: {
      tool: "charge_wallet",
      args: { user: "user_123", amount: 10 },
      intentId: "charge-user123-order42",
      intentSummary: "charge wallet · user_123 · 10 units",
      stateSnapshot: {
        wallet_balance: `${WALLET_START}.00`,
        side_effect_committed: false,
        agent_budget: "ample",
      },
      policyCheck: "allowed_action: ✓  ·  intent_bound: ✓  ·  state_consistent: ✓",
      decision: firstDecision,
      reason: firstReason,
      executionStatus: firstDecision === "ALLOW" ? "executed" : "blocked_before_execution",
      authId: firstAuthId,
    },
  });

  // ── Step 3: Execution (side effect) ─────────────────────────────────────
  if (firstDecision === "ALLOW") {
    steps.push({
      agent: {
        type: "execute",
        label: "Execution: wallet charged 10 units",
        detail: "receipt: charge-receipt-001 · side effect committed",
      },
      stateAfter: {
        walletBalance: `${WALLET_START - 10}.00`,
        alreadyCharged: true,
      },
    });
  }

  // ── Step 4: Agent uncertainty / retry ────────────────────────────────────
  steps.push({
    agent: {
      type: "thought",
      label: "Network timeout - uncertain if charge completed",
      detail: "Same intent · state has changed since first execution",
    },
  });

  // ── Step 5: Second proposal - expect DENY (same intent, state now inconsistent) ──
  let secondDecision: "ALLOW" | "DENY" = "DENY" as "ALLOW" | "DENY";
  let secondReason = "unknown";

  const guard2 = OxDeAIGuard({
    engine,
    getState: () => ({ state, version: 0 }),
    setState: (s) => { state = s; return true; },
    expectedAudience: AGENT_ID,
    mapActionToIntent: () => chargeIntent,
    beforeExecute() {
      secondDecision = "ALLOW"; // should not be reached
      secondReason = "unexpectedly allowed";
    },
  });

  try {
    await guard2(
      { name: "charge_wallet", args: { user: "user_123", amount: 10 }, context: { agent_id: AGENT_ID } },
      async () => "charge-receipt-002" // never called on DENY
    );
  } catch (err) {
    if (err instanceof OxDeAIDenyError) {
      secondDecision = "DENY";
      secondReason = "state inconsistent · side effect already committed for this intent";
    } else {
      throw err;
    }
  }

  steps.push({
    agent: {
      type: "propose",
      label: "Proposing charge_wallet(user_123, 10) [retry]",
      detail: "intent: charge-user123-order42  ·  same logical proposal",
    },
    auth: {
      tool: "charge_wallet",
      args: { user: "user_123", amount: 10 },
      intentId: "charge-user123-order42",         // same - identical logical proposal
      intentSummary: "charge wallet · user_123 · 10 units",  // same
      stateSnapshot: {
        wallet_balance: `${WALLET_START - 10}.00`,
        side_effect_committed: true,              // state changed after first execution
        agent_budget: "ample",
      },
      policyCheck: "allowed_action: ✓  ·  intent_bound: ✓  ·  state_consistent: ✗",
      decision: secondDecision,
      reason: secondReason,
      executionStatus: secondDecision === "ALLOW" ? "executed" : "blocked_before_execution",
    },
  });

  // ── Step 6: Blocked ──────────────────────────────────────────────────────
  steps.push({
    agent: {
      type: "blocked",
      label: "Blocked at authorization boundary",
      detail: `Tool not invoked  ·  side effect never occurred  ·  wallet: ${WALLET_START - 10}.00`,
    },
    stateAfter: {
      walletBalance: `${WALLET_START - 10}.00`,
      alreadyCharged: true,
    },
  });

  return steps;
}
