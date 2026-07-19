// SPDX-License-Identifier: Apache-2.0
/**
 * pep.ts - Policy Enforcement Point (PEP)
 *
 * The execution boundary. The tool MUST NOT run without a valid Authorization.
 *
 * Flow:
 *   1. Build intent from proposed tool call
 *   2. Ask PDP: evaluatePure(intent, state)
 *   3. DENY  → print denial, return - tool does not execute
 *   4. ALLOW → verify Authorization present (invariant check)
 *   5. Execute tool with Authorization in hand
 *   6. Commit nextState from PDP for next evaluation
 *
 * The PEP is deliberately thin. It enforces, never decides.
 */

import type { AuthorizationV1, State } from "@oxdeai/core";
import { engine, buildProvisionIntent, gpuCost } from "./policy.js";

// ── Mocked tool ───────────────────────────────────────────────────────────────
// In production: real infrastructure API call.
// Here: deterministic mock that returns a stable instance ID (demo mode).

let _instanceCounter = 0;

function provision_gpu(asset: string, region: string): string {
  // This function body only runs when the PEP has confirmed authorization.
  return `${asset}-${region}-demo-${++_instanceCounter}`;
}

// ── Result types ──────────────────────────────────────────────────────────────

export type GuardedResult =
  | { allowed: true;  instanceId: string; authorization: AuthorizationV1; nextState: State }
  | { allowed: false; reasons: string[] };

// ── PEP: guarded tool call ────────────────────────────────────────────────────

export function guardedProvision(
  asset:            string,
  region:           string,
  state:            State,
  timestampSeconds: number,
  log:              (msg: string) => void
): GuardedResult {

  const cost = gpuCost(asset, region);

  // ── Step 1: Build intent ─────────────────────────────────────────────────
  const intent = buildProvisionIntent(asset, region, timestampSeconds);

  // ── Step 2: PDP evaluation (pre-execution boundary) ──────────────────────
  const result = engine.evaluatePure(intent, state, timestampSeconds);

  if (result.decision === "DENY") {
    // Tool does not execute. State is unchanged.
    const reasons = result.reasons ?? ["unknown"];
    log(`   provision_gpu(${asset}, ${region})  cost=${cost}  nonce=${intent.nonce}  → DENY   ${reasons.join(", ")}`);
    return { allowed: false, reasons };
  }

  // ── Step 3: PEP enforcement - Authorization MUST be present ─────────────
  // If evaluatePure returns ALLOW without an Authorization, that is a
  // protocol violation - throw rather than silently proceeding.
  const authorization = result.authorization;
  if (!authorization) {
    throw new Error(
      `PEP invariant violated: ALLOW with no Authorization for ${intent.intent_id}`
    );
  }

  // ── Step 4: Execute tool (only after Authorization confirmed) ────────────
  const instanceId = provision_gpu(asset, region);
  log(`   provision_gpu(${asset}, ${region})  cost=${cost}  nonce=${intent.nonce}  → ALLOW  auth=${authorization.auth_id.slice(0, 12)}...  instance=${instanceId}`);

  // nextState from PDP must be used for the next evaluation.
  // Never mutate state directly - always use result.nextState.
  const nextState = result.nextState;
  if (!nextState) {
    throw new Error(`PDP returned ALLOW but no nextState for ${intent.intent_id}`);
  }

  return { allowed: true, instanceId, authorization, nextState };
}