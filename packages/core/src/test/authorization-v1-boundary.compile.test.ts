// SPDX-License-Identifier: Apache-2.0
/**
 * authorization-v1-boundary.compile.test.ts
 *
 * Compile-time regression guard for the public AuthorizationV1 artifact
 * boundary (P0-4, resolved in #102 / #103; reconciliation tracked in #186).
 *
 * The public engine surface — `AuthorizationV1` and the ALLOW branch of
 * `EvaluateOutput` / `EvaluatePureOutput` — exposes the canonical `auth_id`
 * identifier and MUST NOT statically expose the legacy `authorization_id`
 * alias. Reading `.authorization_id` off any of these public types is exactly
 * the TS2339 that motivated migrating the artifact-identifier reads to
 * `auth_id`.
 *
 * The assertions below are conditional types. If a future change re-widens a
 * public authorization back to the legacy-carrying `Authorization` type (or
 * re-adds `authorization_id` to `AuthorizationV1`), the guarded type flips to
 * "LEAK" and the corresponding `const` initializer stops type-checking, so
 * `tsc` fails under both `pnpm --filter @oxdeai/core typecheck` and the build
 * (`noEmitOnError`). This turns a silent boundary regression into a hard error.
 *
 * Scope note: legacy fields are still physically present on the runtime object
 * by design; that is covered separately by public-artifact-boundary.test.ts,
 * which proves `toPublicAuthorizationV1()` strips them from every signing/hash
 * surface. This file guards the *static type* contract only.
 */
import test from "node:test";
import assert from "node:assert/strict";

import type { AuthorizationV1, EvaluateOutput, EvaluatePureOutput } from "@oxdeai/core";

// The `authorization` payload carried by each public ALLOW result.
type AllowEvaluateAuth = Extract<EvaluateOutput, { decision: "ALLOW" }>["authorization"];
type AllowEvaluatePureAuth = Extract<EvaluatePureOutput, { decision: "ALLOW" }>["authorization"];

test("AuthorizationV1 boundary: public types expose auth_id and hide authorization_id (compile-time guard)", () => {
  // Positive: the canonical identifier is present and typed as string on the
  // public type. Breaks if `auth_id` is removed or retyped.
  const authIdIsString: AuthorizationV1["auth_id"] extends string ? true : never = true;

  // Negative: the legacy alias must NOT be a key of any public authorization
  // surface. Each of these is "ok" today; it becomes "LEAK" — and fails to
  // compile — if `authorization_id` re-enters the public type.
  const noLegacyOnV1: "authorization_id" extends keyof AuthorizationV1 ? "LEAK" : "ok" = "ok";
  const noLegacyOnEvaluate: "authorization_id" extends keyof AllowEvaluateAuth ? "LEAK" : "ok" = "ok";
  const noLegacyOnEvaluatePure: "authorization_id" extends keyof AllowEvaluatePureAuth ? "LEAK" : "ok" = "ok";

  assert.equal(authIdIsString, true);
  assert.equal(noLegacyOnV1, "ok");
  assert.equal(noLegacyOnEvaluate, "ok");
  assert.equal(noLegacyOnEvaluatePure, "ok");

  // Runtime sanity: a well-typed public authorization identifies itself via
  // `auth_id`, and the clean public shape carries no `authorization_id` key.
  const auth: AuthorizationV1 = {
    auth_id: "a".repeat(64),
    issuer: "issuer-A",
    audience: "rp-A",
    intent_hash: "b".repeat(64),
    state_hash: "c".repeat(64),
    policy_id: "d".repeat(64),
    decision: "ALLOW",
    issued_at: 1_000_000,
    expiry: 1_000_060,
    alg: "Ed25519",
    kid: "k1",
    signature: "sig",
  };

  assert.equal(typeof auth.auth_id, "string");
  assert.equal((auth as Record<string, unknown>)["authorization_id"], undefined);
});
