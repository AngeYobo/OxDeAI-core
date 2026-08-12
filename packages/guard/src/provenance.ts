// SPDX-License-Identifier: Apache-2.0
import type { Intent } from "@oxdeai/core";
import type { TrustedExecutionContext } from "./trustedContext.js";
import { OxDeAIProvenanceConflictError } from "./errors.js";

/**
 * Provenance modes for an evaluator input.
 *
 * The boundary is expressed in terms of how a premise was obtained, not in
 * terms of one specific source, so that further modes attach without
 * restructuring:
 *
 *  - `declared`  — proposer-controlled claim; never authoritative.
 *  - `derived`   — obtained from authenticated or trusted enforcement context.
 *  - `read`      — obtained from an authoritative provider with explicit
 *                  version/freshness semantics. NOT implemented here.
 *  - `attested`  — independently verifiable statement from an accepted
 *                  authority. NOT implemented here.
 *
 * The governing rule, which further modes must preserve:
 *
 * ```text
 * declared never overrides derived, read, or attested.
 * ```
 *
 * This module implements `declared` and `derived` only. A later `read` or
 * `attested` premise attaches as an additional resolver on {@link ProvenanceField},
 * consulted ahead of `declared` in precedence order; nothing here assumes the
 * enforcement context is the only non-declared source.
 *
 * @public
 */

/**
 * How a non-declared premise related to the proposer's corresponding claim.
 *
 * Recorded per field so that an audit reader can distinguish a value the guard
 * filled in from one the proposer asserted. Without this, a derived fill and a
 * proposer assertion that happened to be correct look identical after the fact.
 *
 *  - `"absent"`     — the proposer made no claim; the non-declared premise was used.
 *  - `"matched"`    — the proposer's claim was present and exactly equal to the
 *                     non-declared premise, which was used regardless.
 *  - `"conflict"`   — the proposer's claim contradicted the non-declared premise.
 *                     Fails closed; never reaches evaluation.
 *  - `"unverified"` — the proposer made a claim for which NO non-declared premise
 *                     exists, so nothing could be checked. The claim is retained
 *                     as-is. **This is not a verified value** — see the note on
 *                     attack M in {@link reconcileWithTrustedContext}.
 *
 * @public
 */
export type ClaimProvenance = "absent" | "matched" | "conflict" | "unverified";

/** Per-field provenance outcome for one evaluation. @public */
export type ProvenanceRecord = Readonly<Record<string, ClaimProvenance>>;

/** @public */
export type ReconciliationOptions = {
  /**
   * Field names whose value the guard supplied to the normalizer because the
   * proposer omitted them, and which therefore must not audit as a proposer
   * `matched` claim.
   *
   * Needed because `defaultNormalizeAction` requires `context.agent_id` and
   * throws before reconciliation can run, so "absent claim → fill from the
   * derived premise" is not reachable end-to-end for identity unless the guard
   * supplies the premise up front. The claim is still compared, so a normalizer
   * that returns something else still fails closed.
   */
  readonly synthesized?: ReadonlySet<string>;
};

/** @public */
export type ReconciliationResult = {
  /** Intent with trusted premises applied. Proposer claims never override. */
  readonly intent: Intent;
  readonly provenance: ProvenanceRecord;
};

/**
 * One row of the premise-vs-claim comparison.
 *
 * Declaring the boundary as a table rather than a chain of per-field `if`
 * statements keeps the rule in one place and lets later structured-argument
 * provenance work reuse the same seam instead of re-deriving it.
 *
 * Extensibility: `derived` is the only non-declared resolver today. A `read`
 * premise (authoritative provider with version/freshness semantics) or an
 * `attested` premise (independently verifiable statement) attaches as a sibling
 * resolver consulted ahead of `declared`, without changing the comparison rule
 * or the recorded outcomes. Nothing below assumes the enforcement context is the
 * only possible source of a non-declared premise.
 */
type ProvenanceField = {
  /** Key under which the outcome is recorded. */
  readonly name: string;
  /**
   * `derived` premise — obtained from the authenticated/trusted enforcement
   * context. `undefined` when this route supplies none.
   */
  readonly derived: (ctx: TrustedExecutionContext) => string | number | undefined;
  /** `declared` claims for this field, from every source that can carry one. */
  readonly claims: (intent: Intent, context: Record<string, unknown> | undefined) => unknown[];
  /**
   * Apply the resolved premise to the intent. Omitted for fields that have no
   * representation in `Intent` — those are conflict-checked only and are
   * deliberately not wired into policy-module evaluation.
   */
  readonly apply?: (intent: Record<string, unknown>, premise: string | number) => void;
};

function claimsOf(...values: unknown[]): unknown[] {
  return values.filter((v) => v !== undefined && v !== null);
}

const FIELDS: readonly ProvenanceField[] = [
  {
    name: "agent_id",
    derived: (ctx) => ctx.agentId,
    claims: (intent, context) => claimsOf(intent.agent_id, context?.["agent_id"]),
    apply: (intent, premise) => {
      intent["agent_id"] = premise;
    },
  },
  {
    name: "tool",
    derived: (ctx) => ctx.tool,
    claims: (intent, context) => claimsOf(intent.tool, context?.["tool"]),
    apply: (intent, premise) => {
      intent["tool"] = premise;
    },
  },
  {
    name: "depth",
    derived: (ctx) => ctx.depth,
    claims: (intent, context) => claimsOf(intent.depth, context?.["depth"]),
    apply: (intent, premise) => {
      intent["depth"] = premise;
    },
  },
  // Fields with no `Intent` representation: conflict-checked only. A proposer
  // that asserts one of these in `action.context` must not be able to state
  // something the trusted context contradicts, even though nothing downstream
  // consumes the value yet.
  {
    name: "principal_id",
    derived: (ctx) => ctx.principalId,
    claims: (_intent, context) => claimsOf(context?.["principal_id"]),
  },
  {
    name: "tenant_id",
    derived: (ctx) => ctx.tenantId,
    claims: (_intent, context) => claimsOf(context?.["tenant_id"]),
  },
  {
    name: "adapter_id",
    derived: (ctx) => ctx.adapterId,
    claims: (_intent, context) => claimsOf(context?.["adapter_id"]),
  },
  {
    name: "route_classification",
    derived: (ctx) => ctx.routeClassification,
    claims: (_intent, context) => claimsOf(context?.["route_classification"]),
  },
];

/**
 * Merge a proposer's normalized intent with server-created trusted context.
 *
 * The rule, applied uniformly to every field in the table:
 *
 * ```text
 * declared absent            → fill from the non-declared premise
 * declared present, equal    → use the non-declared premise
 * declared present, differs  → fail closed
 * no non-declared premise    → retain the claim, record it as unverified
 * ```
 *
 * `derived` is the only non-declared mode implemented here; the rule is written
 * so that a later `read` or `attested` premise obeys it unchanged.
 *
 * Comparison is exact deterministic equality. No case folding, trimming, or
 * implicit normalization is applied: two spellings that a downstream system
 * might treat as equivalent are a conflict here, because silently accepting a
 * near-match is how a rename bypass re-enters.
 *
 * Reconciliation runs on the OUTPUT of the configured `mapActionToIntent`.
 * A deployment-supplied normalizer returns a full `Intent`, so applying trusted
 * premises beforehand would let a custom normalizer overwrite them.
 *
 * **Attack coverage.** With a trusted `agentId` this closes per-agent limit
 * inheritance by self-declared `agent_id` (case L). Tool-rename bypass (case M)
 * is closed ONLY for routes that supply an authoritative `tool`; where the route
 * has no tool identity, the proposer's tool name is recorded `"unverified"` and
 * no closure should be claimed. Default-deny tool semantics remain out of scope.
 *
 * All conflicting fields are collected before throwing, in declaration order, so
 * the same conflicting request always reports the same deterministic set.
 */
export function reconcileWithTrustedContext(
  intent: Intent,
  ctx: TrustedExecutionContext,
  actionContext: Record<string, unknown> | undefined,
  options?: ReconciliationOptions
): ReconciliationResult {
  const merged: Record<string, unknown> = { ...(intent as unknown as Record<string, unknown>) };
  const provenance: Record<string, ClaimProvenance> = {};
  const conflicts: string[] = [];
  const synthesized = options?.synthesized;

  for (const field of FIELDS) {
    const premise = field.derived(ctx);
    const claims = field.claims(intent, actionContext);
    const wasSynthesized = synthesized?.has(field.name) === true;

    if (premise === undefined) {
      provenance[field.name] = claims.length > 0 ? "unverified" : "absent";
      continue;
    }

    if (claims.length === 0) {
      provenance[field.name] = "absent";
      field.apply?.(merged, premise);
      continue;
    }

    // Exact equality against every source that carried a claim.
    //
    // A synthesized field is still compared: the guard supplied the premise to
    // the normalizer, so the normalizer is expected to echo it back exactly. A
    // deviation means the normalizer substituted an identity of its own, which
    // must fail closed rather than being silently overwritten.
    const conflicting = claims.some((claim) => claim !== premise);
    if (conflicting) {
      provenance[field.name] = "conflict";
      conflicts.push(field.name);
      continue;
    }

    // The record describes the PROPOSER's claim, not the normalizer's echo of a
    // guard-supplied premise. A synthesized field the proposer never claimed
    // audits as `absent`, so a trusted fill is not reported as a match the
    // proposer earned.
    provenance[field.name] = wasSynthesized ? "absent" : "matched";
    field.apply?.(merged, premise);
  }

  if (conflicts.length > 0) {
    throw new OxDeAIProvenanceConflictError(conflicts, Object.freeze({ ...provenance }));
  }

  return {
    intent: merged as unknown as Intent,
    provenance: Object.freeze(provenance),
  };
}
