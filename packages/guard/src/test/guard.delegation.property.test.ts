// SPDX-License-Identifier: Apache-2.0
/**
 * Property-based tests for the delegation execution path in @oxdeai/guard.
 *
 * Uses the same seeded-PRNG approach as guard.property.test.ts:
 *   - mulberry32 PRNG, fully deterministic given a seed
 *   - PBT_CASES env var controls iteration count (default 50)
 *   - PBT_SEED   env var overrides the base seed
 *   - PBT_ONLY_SEED env var runs a single seed for focused debugging
 *
 * Test IDs: G-D1, G-D2.
 *
 * Key invariants under test:
 *   G-D1: For any tool in the delegation scope, a matching action is allowed
 *         and execute is called. setState is NEVER called on the delegation path.
 *   G-D2: Any structurally invalid delegation (expired, tampered, or out-of-scope
 *         action) always triggers fail-closed behavior:
 *         - OxDeAIDelegationError is thrown
 *         - execute is never called
 *         - setState is never called
 */

import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import { PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE, signAuthorizationEd25519, createDelegation } from "@oxdeai/core";
import type { AuthorizationV1, DelegationV1, KeySet } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";

import { OxDeAIGuard } from "../guard.js";
import { OxDeAIDelegationError } from "../errors.js";
import type { ProposedAction, OxDeAIGuardConfig } from "../types.js";

// ── PRNG ──────────────────────────────────────────────────────────────────────

const DEFAULT_CASES = Number(process.env.PBT_CASES ?? "50");
const BASE_SEED = Number(process.env.PBT_SEED ?? "20260319");
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
  return values[randInt(rng, 0, values.length - 1)];
}

function seeds(): number[] {
  if (ONLY_SEED !== undefined) return [ONLY_SEED];
  const out: number[] = [];
  for (let i = 0; i < DEFAULT_CASES; i++) out.push(BASE_SEED + i);
  return out;
}

// ── Fixed timestamps ───────────────────────────────────────────────────────────

const T_NOW     = Math.floor(Date.now() / 1000);
const T_ISSUED  = T_NOW - 60;    // parent issued_at
const T_DEL_EXP = T_NOW + 600;   // valid delegation expiry
const T_PAR_EXP = T_NOW + 900;   // parent expiry

// ── Fixed key material ────────────────────────────────────────────────────────

const KEYS = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

const KEYSET: KeySet = {
  issuer: "parent-agent",
  version: "1",
  keys: [{ kid: "k1", alg: "Ed25519", public_key: KEYS.publicKey.toString() }],
};

const TOOL_POOL = [
  "provision_gpu",
  "query_db",
  "send_payment",
  "transfer_tokens",
  "buy_storage",
  "mint_nft",
  "onchain_tx",
] as const;

// ── Helpers ───────────────────────────────────────────────────────────────────

const PARENT_SCOPE = { tools: [...TOOL_POOL], max_amount: 1_000_000n };

function makeParentAuth(expiry = T_PAR_EXP): AuthorizationV1 {
  return signAuthorizationEd25519(
    {
      auth_id: "f".repeat(64),
      issuer: KEYSET.issuer,
      audience: "parent-agent",
      intent_hash: "a".repeat(64),
      state_hash: "b".repeat(64),
      policy_id: "policy-1",
      decision: "ALLOW",
      issued_at: T_ISSUED,
      expiry,
      kid: "k1",
    },
    KEYS.privateKey
  );
}

function makeDelegation(
  parent: AuthorizationV1,
  tools: string[],
  expiry: number
): DelegationV1 {
  return createDelegation(
    parent,
    {
      delegatee: "child-agent",
      scope: { tools, max_amount: 1_000_000n },
      expiry,
      kid: "k1",
      issuedAt: T_ISSUED,
      audience: "child-agent",
      issuer: KEYSET.issuer,
    },
    KEYS.privateKey
  );
}

function makeGuardConfig(overrides?: Partial<OxDeAIGuardConfig>): OxDeAIGuardConfig {
  return {
    engine: new PolicyEngine({
      policy_version: "v1-test",
      engine_secret: "test-secret-must-be-at-least-32-chars!!",
      ...RECOMMENDED_TRUSTED_TIME_PROFILE,
    }),
    getState: () => ({ state: buildState({ agent_id: "child-agent", allow_action_types: ["PROVISION"] }), version: 0 }),
    setState: () => true,
    trustedKeySets: [KEYSET],
    expectedAudience: "parent-agent",
    ...overrides,
  };
}

function makeAction(toolName: string, timestampSeconds = T_NOW): ProposedAction {
  return {
    name: toolName,
    args: { asset: "test" },
    estimatedCost: 0,
    context: {
      agent_id: "child-agent",
      target: "resource-pool",
    },
    timestampSeconds,
  };
}

// ── G-D1: any tool in scope → execute called, setState NOT called ─────────────

test("G-D1: any action matching delegation scope.tools is allowed; setState is never called", async () => {
  const parent = makeParentAuth();

  for (const seed of seeds()) {
    const rng = mulberry32(seed);
    // Pick any tool from the pool — that becomes both the scope and the action name.
    const toolName = pick(rng, TOOL_POOL);
    const delegation = makeDelegation(parent, [toolName], T_DEL_EXP);

    let executeCalled = false;
    let setStateCalled = false;

    const config = makeGuardConfig({ setState: () => { setStateCalled = true; return true; } });
    const guard = OxDeAIGuard(config);
    const action = makeAction(toolName, T_NOW);

    const result = await guard(
      action,
      async () => { executeCalled = true; return "executed"; },
      { delegation: { delegation, parentAuth: parent, parentScope: PARENT_SCOPE } }
    );

    assert.ok(
      executeCalled,
      `G-D1 seed=${seed} tool=${toolName}: execute must be called for in-scope action`
    );
    assert.equal(
      result,
      "executed",
      `G-D1 seed=${seed} tool=${toolName}: guard must return execute() result`
    );
    assert.ok(
      !setStateCalled,
      `G-D1 seed=${seed} tool=${toolName}: setState must NOT be called on delegation path`
    );
  }
});

// ── G-D2: fail-closed coverage for multiple invalid delegation classes ─────────
//
// Randomly picks one of three invalid delegation classes per seed:
//
//   Case 0 — Expired delegation:
//     delegation.expiry < action.timestampSeconds (T_NOW).
//     Guard uses intent.timestamp as `now` for verifyDelegationChain.
//     Produces: DELEGATION_EXPIRED.
//
//   Case 1 — Tampered signature:
//     A valid delegation is created, then delegation.delegatee is mutated
//     post-signing. verifyDelegationChain detects the signature mismatch.
//     Produces: DELEGATION_SIGNATURE_INVALID.
//
//   Case 2 — Out-of-scope action:
//     The delegation scope allows [scopeTool], but the action requests [otherTool].
//     Guard-level scope enforcement blocks before execute.
//     Produces: "action is not permitted by delegation scope.tools [...]"
//
// All three cases must:
//   - throw OxDeAIDelegationError
//   - never call execute
//   - never call setState

test("G-D2: any invalid delegation class always blocks execution (fail-closed)", async () => {
  const parent = makeParentAuth();

  // Two fixed tools: one inside scope, one outside.
  const scopeTool  = "provision_gpu";
  const outsideTool = "query_db";

  for (const seed of seeds()) {
    const rng = mulberry32(seed);
    const invalidClass = randInt(rng, 0, 2);

    let delegation: DelegationV1;
    let action: ProposedAction;
    let caseLabel: string;

    if (invalidClass === 0) {
      // Case 0: delegation expired at action time.
      const expiry = T_NOW - randInt(rng, 1, 999);
      delegation = makeDelegation(parent, [scopeTool], expiry);
      action = makeAction(scopeTool, T_NOW);
      caseLabel = `expired(expiry=${expiry})`;

    } else if (invalidClass === 1) {
      // Case 1: tampered field (delegatee mutated after signing).
      // This changes a field covered by the Ed25519 signature →
      // verifyDelegationChain will detect DELEGATION_SIGNATURE_INVALID.
      const valid = makeDelegation(parent, [scopeTool], T_DEL_EXP);
      delegation = { ...valid, delegatee: "evil-agent" };
      action = makeAction(scopeTool, T_NOW);
      caseLabel = "tampered(delegatee)";

    } else {
      // Case 2: out-of-scope action. The delegation grants [scopeTool] but
      // the action requests [outsideTool]. Guard scope check fires post-chain.
      delegation = makeDelegation(parent, [scopeTool], T_DEL_EXP);
      action = makeAction(outsideTool, T_NOW);
      caseLabel = `out-of-scope(action=${outsideTool},scope=${scopeTool})`;
    }

    let executeCalled = false;
    let setStateCalled = false;

    const config = makeGuardConfig({ setState: () => { setStateCalled = true; return true; } });
    const guard = OxDeAIGuard(config);

    await assert.rejects(
      async () => {
        await guard(
          action,
          async () => { executeCalled = true; },
          { delegation: { delegation, parentAuth: parent, parentScope: PARENT_SCOPE } }
        );
      },
      (err: unknown) => err instanceof OxDeAIDelegationError,
      `G-D2 seed=${seed} ${caseLabel}: expected OxDeAIDelegationError`
    );

    assert.ok(
      !executeCalled,
      `G-D2 seed=${seed} ${caseLabel}: execute must NOT be called`
    );
    assert.ok(
      !setStateCalled,
      `G-D2 seed=${seed} ${caseLabel}: setState must NOT be called`
    );
  }
});

// ── G-D3: delegation presented with wrong parent authorization fails closed ────
//
// DelegationV1 binds cryptographically to a specific parent AuthorizationV1 via:
//   parent_auth_hash = SHA-256(canonicalJson(parentAuth))
//
// Presenting a structurally valid, non-expired delegation alongside ANY different
// parent — even one with the same audience, policy_id, and expiry — must be
// rejected with DELEGATION_PARENT_HASH_MISMATCH.
//
// Why this matters (cross-context replay protection):
//   A delegation is issued under a specific policy evaluation context (parent A).
//   If guard accepted a different parent B without verifying the hash binding,
//   an attacker who holds a valid delegation for context A could reuse it
//   under context B — a different state snapshot, different budget period, or
//   a re-evaluated policy — and bypass whatever controls B was meant to enforce.
//   The parent_auth_hash is the tamper-evident anchor that prevents this.
//
// Per-seed, parent B varies only in auth_id (≠ A's auth_id) so the test
// exercises different wrong-parent scenarios rather than a single fixture.

test("G-D3: delegation presented with wrong parent authorization is rejected (DELEGATION_PARENT_HASH_MISMATCH)", async () => {
  const parentA = makeParentAuth();
  const scopeTool = "provision_gpu";

  // All lowercase hex chars except "f" (the char used by parentA's auth_id).
  // Using a different char each seed ensures no single wrong-parent fixture
  // is tested exclusively.
  const HEX_CHARS_NOT_F = "0123456789abcde";

  for (const seed of seeds()) {
    const rng = mulberry32(seed);
    const wrongChar = HEX_CHARS_NOT_F[randInt(rng, 0, HEX_CHARS_NOT_F.length - 1)];

    // Parent B: structurally valid, non-expired, same audience/policy_id/expiry
    // as A — only auth_id differs. This isolates the parent_auth_hash check and
    // prevents other chain violations (delegator, policy, expiry) from firing first.
    // Must carry .scope so the guard does not short-circuit before verifyDelegationChain.
    const parentBAuth = signAuthorizationEd25519(
      {
        auth_id: wrongChar.repeat(64),
        issuer: KEYSET.issuer,
        audience: "parent-agent",
        intent_hash: "a".repeat(64),
        state_hash: "b".repeat(64),
        policy_id: "policy-1",
        decision: "ALLOW",
        issued_at: T_ISSUED,
        expiry: T_PAR_EXP,
        kid: "k1",
      },
      KEYS.privateKey
    );
    const parentB = parentBAuth;

    // Delegation is cryptographically bound to parentA via parent_auth_hash.
    const delegation = makeDelegation(parentA, [scopeTool], T_DEL_EXP);

    let executeCalled = false;
    let setStateCalled = false;

    const config = makeGuardConfig({ setState: () => { setStateCalled = true; return true; } });
    const guard = OxDeAIGuard(config);

    await assert.rejects(
      async () => {
        await guard(
          makeAction(scopeTool, T_NOW),
          async () => { executeCalled = true; },
          { delegation: { delegation, parentAuth: parentB, parentScope: { tools: [scopeTool], max_amount: 1_000_000n } } }   // ← wrong parent
        );
      },
      (err: unknown) => {
        // Guard surfaces violation messages (v.message ?? v.code) rather than
        // structured codes. Match the message string for DELEGATION_PARENT_HASH_MISMATCH.
        if (!(err instanceof OxDeAIDelegationError)) return false;
        return err.violations.some(v => v.includes("parent_auth_hash does not match"));
      },
      `G-D3 seed=${seed} wrongChar=${wrongChar}: expected OxDeAIDelegationError with DELEGATION_PARENT_HASH_MISMATCH`
    );

    assert.ok(
      !executeCalled,
      `G-D3 seed=${seed}: execute must NOT be called on parent hash mismatch`
    );
    assert.ok(
      !setStateCalled,
      `G-D3 seed=${seed}: setState must NOT be called on parent hash mismatch`
    );
  }
});
