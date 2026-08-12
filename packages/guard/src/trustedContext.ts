// SPDX-License-Identifier: Apache-2.0
import { OxDeAIGuardConfigurationError } from "./errors.js";

/**
 * Runtime brand for a guard-constructed trusted execution context.
 *
 * ⚠️ MISUSE RESISTANCE ONLY — NOT AUTHENTICATION.
 *
 * The brand proves that a context object was produced by
 * {@link createTrustedExecutionContext} inside this process, and nothing more.
 * It exists so that a value deserialized from request JSON cannot be passed to
 * the secure guard as if it were trusted context: a type-only brand is erased
 * at compile time and would let `JSON.parse(body).ctx` through unnoticed.
 *
 * It is NOT cryptographic provenance and it is NOT a caller credential. A
 * privileged in-process caller that can reach the builder can still manufacture
 * a branded context. The real trust root is the authenticated principal and the
 * protected routing data used to construct the context — the brand only ensures
 * that construction actually happened.
 */
const TRUSTED_CONTEXT_BRAND: unique symbol = Symbol("oxdeai.guard.trustedExecutionContext");

/**
 * Server-created execution context for the Tier 1 secure guard path.
 *
 * Constructed by the PEP *after* authentication and protected route resolution.
 * It must never be deserialized from proposer-controlled request JSON; see
 * `docs/architecture/decisions/tier1-evaluator-input-provenance.md`.
 *
 * ⚠️ `evaluationTime` is deliberately ABSENT from this type.
 *
 * The Tier 1 ADR's illustrative context shape lists `evaluationTime` alongside
 * the identity and routing fields. That is superseded here on purpose: trusted
 * time is captured by the secure guard at the actual evaluation boundary,
 * immediately before evaluation, rather than carried on the context.
 *
 * Authentication establishes *who* and *where*; `evaluationTime` establishes
 * *when this specific decision is being made*. If the context carried a
 * timestamp, a context constructed once could be reused as a time capsule for
 * later decisions, and freshness would silently describe context construction
 * rather than the evaluation it gates. **Do not add `evaluationTime` to this
 * type** — capture it at the evaluation boundary instead.
 *
 * @public
 */
export type TrustedExecutionContext = {
  /** Authenticated, deployment-local principal identifier. */
  readonly principalId: string;
  /** Authenticated tenant namespace. Required when the deployment is multi-tenant. */
  readonly tenantId?: string;
  /** Effective agent identity, mapped from the authenticated principal. */
  readonly agentId: string;
  /** Execution adapter fixed before authorization; the same adapter must execute. */
  readonly adapterId: string;
  /**
   * Tool identity derived from the trusted route.
   *
   * Optional because not every route can supply an authoritative tool identity
   * yet. When absent, a proposer-supplied tool name is retained but is NOT
   * verified — see {@link ClaimProvenance} `"unverified"`.
   */
  readonly tool?: string;
  /**
   * Security-relevant action classification derived from the trusted route.
   *
   * Carried and conflict-checked as trusted routing context. It is deliberately
   * NOT wired into policy-module evaluation: making this classification
   * load-bearing is a separate reviewed decision. `intent.action_type` remains
   * a separate, proposer-controlled concept.
   */
  readonly routeClassification?: string;
  /** Recursion depth derived from the protected execution chain. Never defaulted. */
  readonly depth: number;
};

type BrandedTrustedExecutionContext = TrustedExecutionContext & {
  readonly [TRUSTED_CONTEXT_BRAND]: true;
};

function requireString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new OxDeAIGuardConfigurationError(
      `TrustedExecutionContext.${field} must be a non-empty string. Context construction failed.`
    );
  }
  return value;
}

function optionalString(value: unknown, field: string): string | undefined {
  if (value === undefined) return undefined;
  return requireString(value, field);
}

/**
 * Construct a branded {@link TrustedExecutionContext}.
 *
 * Every field is validated at construction so that an invalid context fails
 * here — before evaluation, authorization issuance, state mutation, or
 * execution — rather than producing a weaker decision later.
 *
 * `depth` is REQUIRED and is never defaulted. A missing trusted depth fails
 * context construction rather than silently representing the call as a root
 * call: defaulting to `0` would hand every nested call the recursion budget of
 * a root call while looking like trusted depth.
 *
 * @public
 */
export function createTrustedExecutionContext(
  input: TrustedExecutionContext
): TrustedExecutionContext {
  if (typeof input !== "object" || input === null) {
    throw new OxDeAIGuardConfigurationError(
      "TrustedExecutionContext input must be an object. Context construction failed."
    );
  }

  const principalId = requireString(input.principalId, "principalId");
  const agentId = requireString(input.agentId, "agentId");
  const adapterId = requireString(input.adapterId, "adapterId");
  const tenantId = optionalString(input.tenantId, "tenantId");
  const tool = optionalString(input.tool, "tool");
  const routeClassification = optionalString(input.routeClassification, "routeClassification");

  const depth = input.depth;
  if (typeof depth !== "number" || !Number.isSafeInteger(depth) || depth < 0) {
    throw new OxDeAIGuardConfigurationError(
      "TrustedExecutionContext.depth is required and must be a non-negative safe integer " +
        "derived from the protected execution chain. It is never defaulted: a missing depth " +
        "would silently represent a nested call as a root call. Context construction failed."
    );
  }

  const context: TrustedExecutionContext = {
    principalId,
    agentId,
    adapterId,
    depth,
    ...(tenantId === undefined ? {} : { tenantId }),
    ...(tool === undefined ? {} : { tool }),
    ...(routeClassification === undefined ? {} : { routeClassification }),
  };

  Object.defineProperty(context, TRUSTED_CONTEXT_BRAND, {
    value: true,
    enumerable: false,
    writable: false,
    configurable: false,
  });

  return Object.freeze(context);
}

/**
 * True only for a context produced by {@link createTrustedExecutionContext}.
 *
 * Non-enumerable, so the brand does not appear in JSON, `Object.keys`, or
 * structured clones — a round-tripped context loses its brand and is rejected.
 */
export function isTrustedExecutionContext(
  value: unknown
): value is TrustedExecutionContext {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as Partial<BrandedTrustedExecutionContext>)[TRUSTED_CONTEXT_BRAND] === true
  );
}
