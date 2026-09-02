// examples/non-bypassable-openclaw/state-boundary.mjs
//
// Exercises OxDeAIGuard's own state_hash binding check (guard.ts step 6c),
// via config.computeStateHash. The shared PEP gateway in ../non-bypassable-demo
// has no live-state concept at all (see pep-gateway.mjs / packages/guard/src/gateway.ts):
// it only checks signature, audience, intent_hash, and replay. state_hash
// binding is enforced by OxDeAIGuard itself, so this check runs in-process
// against a real OxDeAIGuard instance rather than through the HTTP gateway.
//
// AuthorizationV1 is produced fresh by engine.evaluatePure and never mutated:
// it stays signature-valid throughout. Only the live state the boundary
// hashes for its own re-check is changed, via computeStateHash, so the
// authorization's committed state_hash (real state) and the boundary's
// recomputed hash (tampered clone) diverge. That is the state-binding
// invariant, exercised with the exact code guard.ts defines for it.

import { PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE } from "../../packages/core/dist/index.js";
import { OxDeAIGuard } from "../../packages/guard/dist/index.js";
import { generateKeyPairSync } from "node:crypto";

const AGENT = "openclaw-state-agent";
const ISSUER = "openclaw-state-issuer";
const KID = "openclaw-state-k1";

function state() {
  return {
    policy_version: "v1",
    period_id: "p1",
    kill_switch: { global: false, agents: {} },
    allowlists: { action_types: ["PAYMENT"], assets: [], targets: ["charge"] },
    budget: { budget_limit: { [AGENT]: 10_000_000n }, spent_in_period: { [AGENT]: 0n } },
    max_amount_per_action: { [AGENT]: 5_000_000n },
    velocity: { config: { window_seconds: 60, max_actions: 100 }, counters: {} },
    replay: { window_seconds: 3600, max_nonces_per_agent: 256, nonces: {} },
    concurrency: { max_concurrent: { [AGENT]: 5 }, active: {}, active_auths: {} },
    recursion: { max_depth: { [AGENT]: 5 } },
    tool_limits: { window_seconds: 60, max_calls: { [AGENT]: 10 }, calls: {} },
  };
}

/**
 * Runs one OxDeAIGuard call whose live-state hash (as the boundary computes
 * it) does not match what the freshly issued, unmodified, signature-valid
 * authorization committed to. Returns the boundaryFailure code the guard
 * reports and whether execute() ran.
 */
export async function checkStateBinding() {
  const keys = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  const keySet = {
    issuer: ISSUER,
    version: "1",
    keys: [{ kid: KID, alg: "Ed25519", public_key: keys.publicKey.toString() }],
  };
  const engine = new PolicyEngine({
    policy_version: "v1",
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 60,
    authorization_audience: AGENT,
    authorization_issuer: ISSUER,
    authorization_signing_alg: "Ed25519",
    authorization_signing_kid: KID,
    authorization_private_key_pem: keys.privateKey.toString(),
    ...RECOMMENDED_TRUSTED_TIME_PROFILE,
  });

  const live = state();
  let boundaryFailure;
  let executed = false;

  const guard = OxDeAIGuard({
    engine,
    getState: () => ({ state: live, version: 0 }),
    setState: () => true,
    expectedAudience: AGENT,
    trustedKeySets: [keySet],
    // The tamper: hash a mutated clone instead of the real live state, so
    // the boundary's own recomputed state_hash cannot match the
    // authorization's, even though the authorization is untouched.
    computeStateHash: (s) => engine.computeStateHash({ ...s, kill_switch: { ...s.kill_switch, global: true } }),
    onBoundaryEvent(evt) {
      boundaryFailure = evt.boundaryFailure;
    },
  });

  try {
    await guard(
      {
        name: "charge",
        args: { amount: 1 },
        estimatedCost: 1,
        resourceType: "PAYMENT",
        context: { agent_id: AGENT, target: "charge" },
      },
      async () => {
        executed = true;
      }
    );
  } catch {
    // Rejection is expected; boundaryFailure carries the exact reason.
  }

  return { boundaryFailure, executed };
}
