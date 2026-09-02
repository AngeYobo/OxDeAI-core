// SPDX-License-Identifier: Apache-2.0
/**
 * Property-based sweep over `reconcileWithTrustedContext`'s field table
 * (#233), complementing the deterministic per-field examples in
 * `guard.provenance.test.ts` (P-1..P-25).
 *
 * The field table in `packages/guard/src/provenance.ts` reconciles exactly
 * seven fields today: `agent_id`, `tool`, `depth` (all three have an `Intent`
 * representation and are conflict-checked plus applied), and `principal_id`,
 * `tenant_id`, `adapter_id`, `route_classification` (context-only,
 * conflict-checked but never applied to the intent). This file does not
 * change or add to that set — it sweeps it.
 *
 * Two properties:
 *   1. any single field, made to conflict with its trusted value, fails
 *      closed and names exactly that field — never zero, never more than one;
 *   2. an arbitrary MIX of matching and conflicting fields still reports
 *      exactly the conflicting subset — a matching field can never mask an
 *      independent conflicting field, and a conflicting field can never leak
 *      onto an unrelated matching one.
 *
 * Uses this package's existing seeded-PRNG property-testing convention
 * (mulberry32 / PBT_CASES / PBT_SEED), matching guard.property.test.ts and
 * guard.delegation.property.test.ts. `fast-check` is a real dependency of
 * @oxdeai/core but not of @oxdeai/guard, so it is not used here.
 */
import test from "node:test";
import assert from "node:assert/strict";

import type { Intent } from "@oxdeai/core";
import { createTrustedExecutionContext, type TrustedExecutionContext } from "../trustedContext.js";
import { reconcileWithTrustedContext } from "../provenance.js";
import { defaultNormalizeAction } from "../normalizeAction.js";
import { OxDeAIProvenanceConflictError } from "../errors.js";
import type { ProposedAction } from "../types.js";

// ── PRNG (identical convention to guard.property.test.ts) ────────────────────

const DEFAULT_CASES = Number(process.env.PBT_CASES ?? "100");
const BASE_SEED = Number(process.env.PBT_SEED ?? "20260315");
const ONLY_SEED = process.env.PBT_ONLY_SEED ? Number(process.env.PBT_ONLY_SEED) : undefined;

function mulberry32(seed: number): () => number {
  let t = seed >>> 0;
  return () => {
    t += 0x6d2b79f5;
    let r = Math.imul(t ^ (t >>> 15), 1 | t);
    r ^= r + Math.imul(r ^ (r >>> 7), 61 | r);
    return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
  };
}

function randInt(rng: () => number, min: number, max: number): number {
  return Math.floor(rng() * (max - min + 1)) + min;
}

function pick<T>(rng: () => number, values: readonly T[]): T {
  return values[randInt(rng, 0, values.length - 1)]!;
}

function shuffle<T>(rng: () => number, input: readonly T[]): T[] {
  const out = [...input];
  for (let i = out.length - 1; i > 0; i--) {
    const j = randInt(rng, 0, i);
    [out[i], out[j]] = [out[j], out[i]!]!;
  }
  return out;
}

function seeds(): number[] {
  if (ONLY_SEED !== undefined) return [ONLY_SEED];
  const out: number[] = [];
  for (let i = 0; i < DEFAULT_CASES; i++) out.push(BASE_SEED + i);
  return out;
}

// ── fixtures ──────────────────────────────────────────────────────────────────

function makeAction(context: Record<string, unknown> = {}): ProposedAction {
  return {
    name: "provision_gpu",
    args: { asset: "a100" },
    estimatedCost: 0.5,
    resourceType: "gpu",
    context: { target: "gpu-pool", ...context },
  };
}

type FieldName =
  | "agent_id" | "tool" | "depth"
  | "principal_id" | "tenant_id" | "adapter_id" | "route_classification";

const FIELD_NAMES: readonly FieldName[] = [
  "agent_id", "tool", "depth", "principal_id", "tenant_id", "adapter_id", "route_classification",
];

// Distinct per field, so accidental cross-field equality can never mask a conflict.
const BASELINE = {
  agent_id: "agent-baseline",
  tool: "baseline-tool",
  depth: 3,
  principal_id: "principal-baseline",
  tenant_id: "tenant-baseline",
  adapter_id: "adapter-baseline",
  route_classification: "route-baseline",
} as const satisfies Record<FieldName, string | number>;

function baselineContext(): TrustedExecutionContext {
  return createTrustedExecutionContext({
    principalId: BASELINE.principal_id,
    agentId: BASELINE.agent_id,
    adapterId: BASELINE.adapter_id,
    tool: BASELINE.tool,
    routeClassification: BASELINE.route_classification,
    tenantId: BASELINE.tenant_id,
    depth: BASELINE.depth,
  });
}

/**
 * A proposer intent + action.context that matches every field's baseline
 * trusted value exactly. `tool` and `depth` have no mapping from
 * `ProposedAction` in `defaultNormalizeAction` (confirmed by inspection —
 * neither field is populated by the default normalizer), so they are set
 * directly on the produced `Intent`, mirroring the existing convention in
 * guard.provenance.test.ts (e.g. `intent.tool = "provision_gpu"`).
 */
function baselineIntentAndContext(): { intent: Intent; actionContext: Record<string, unknown> } {
  const intent = defaultNormalizeAction(makeAction({ agent_id: BASELINE.agent_id }));
  intent.tool = BASELINE.tool;
  intent.depth = BASELINE.depth;

  const actionContext: Record<string, unknown> = {
    target: "gpu-pool",
    principal_id: BASELINE.principal_id,
    adapter_id: BASELINE.adapter_id,
    route_classification: BASELINE.route_classification,
    tenant_id: BASELINE.tenant_id,
  };
  return { intent, actionContext };
}

/** Mutate the PROPOSER-side claim for exactly one field away from its baseline. */
function withConflictingClaim(
  intent: Intent,
  actionContext: Record<string, unknown>,
  field: FieldName,
  rng: () => number,
): { intent: Intent; actionContext: Record<string, unknown> } {
  const conflictingString = () => `attacker-${randInt(rng, 100_000, 999_999)}`;
  switch (field) {
    case "agent_id":
      return { intent: { ...intent, agent_id: conflictingString() }, actionContext };
    case "tool":
      return { intent: { ...intent, tool: conflictingString() }, actionContext };
    case "depth":
      return { intent: { ...intent, depth: BASELINE.depth + 1 + randInt(rng, 0, 100) }, actionContext };
    case "principal_id":
      return { intent, actionContext: { ...actionContext, principal_id: conflictingString() } };
    case "tenant_id":
      return { intent, actionContext: { ...actionContext, tenant_id: conflictingString() } };
    case "adapter_id":
      return { intent, actionContext: { ...actionContext, adapter_id: conflictingString() } };
    case "route_classification":
      return { intent, actionContext: { ...actionContext, route_classification: conflictingString() } };
  }
}

// ── properties ────────────────────────────────────────────────────────────────

test("property: any single security-relevant field conflicting with its trusted value fails closed, naming exactly that field", () => {
  for (const seed of seeds()) {
    const rng = mulberry32(seed);
    const field = pick(rng, FIELD_NAMES);
    const ctx = baselineContext();
    const base = baselineIntentAndContext();
    const { intent, actionContext } = withConflictingClaim(base.intent, base.actionContext, field, rng);

    let caught: unknown;
    try {
      reconcileWithTrustedContext(intent, ctx, actionContext);
    } catch (e) {
      caught = e;
    }

    assert.ok(
      caught instanceof OxDeAIProvenanceConflictError,
      `seed=${seed} field=${field} expected a provenance conflict, got ${caught instanceof Error ? caught.constructor.name : String(caught)}`,
    );
    assert.deepEqual(caught.fields, [field], `seed=${seed} field=${field} exactly this field must be named`);
    assert.equal(caught.provenance[field], "conflict");

    for (const other of FIELD_NAMES) {
      if (other !== field) {
        assert.notEqual(
          caught.provenance[other], "conflict",
          `seed=${seed} field=${field} unrelated field ${other} must not itself read conflict`,
        );
      }
    }
  }
});

test("property: a matching field never masks an independent conflicting field (mixed multi-field cases)", () => {
  for (const seed of seeds()) {
    const rng = mulberry32(seed);
    const conflictCount = randInt(rng, 1, FIELD_NAMES.length);
    const conflictSet = new Set(shuffle(rng, FIELD_NAMES).slice(0, conflictCount));

    const ctx = baselineContext();
    let { intent, actionContext } = baselineIntentAndContext();
    for (const field of FIELD_NAMES) {
      if (conflictSet.has(field)) {
        ({ intent, actionContext } = withConflictingClaim(intent, actionContext, field, rng));
      }
    }

    let caught: unknown;
    try {
      reconcileWithTrustedContext(intent, ctx, actionContext);
    } catch (e) {
      caught = e;
    }

    assert.ok(
      caught instanceof OxDeAIProvenanceConflictError,
      `seed=${seed} conflictSet=${[...conflictSet]} expected a provenance conflict`,
    );
    assert.deepEqual(
      new Set(caught.fields),
      conflictSet,
      `seed=${seed} exactly the deliberately-conflicting fields must be reported: ` +
        `expected [${[...conflictSet]}], got [${caught.fields}]`,
    );
    assert.equal(caught.fields.length, conflictSet.size, `seed=${seed} no field may be reported twice`);

    for (const field of conflictSet) {
      assert.equal(caught.provenance[field], "conflict");
    }
    for (const field of FIELD_NAMES) {
      if (!conflictSet.has(field)) {
        assert.notEqual(
          caught.provenance[field], "conflict",
          `seed=${seed} matching field ${field} must not be reported as conflicting`,
        );
      }
    }
  }
});
