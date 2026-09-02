// examples/non-bypassable-openclaw/agent.mjs
// How to run: pnpm -C examples/non-bypassable-openclaw start
//
// Simulates an OpenClaw agent issuing actions through the shared PEP gateway
// and protected upstream from ../non-bypassable-demo. Only the agent side is
// OpenClaw-driven; the gateway, upstream, and signing fixture are reused
// as-is so the demo proves the same enforcement boundary, not a fork of it.

import { hashAction, makeAuthorization } from "../non-bypassable-demo/auth-fixture.mjs";
import { checkStateBinding } from "./state-boundary.mjs";

const fetchFn =
  globalThis.fetch ??
  ((...args) => import("node-fetch").then(({ default: f }) => f(...args)));

const GATEWAY_URL = "http://localhost:8787/execute";
const DIRECT_URL  = "http://localhost:8788/charge";

const action = {
  type: "EXECUTE",
  tool: "payments.charge",
  params: { amount: "500", currency: "USD", user_id: "user_123" },
};

const intentHash = hashAction(action);

async function postJson(url, body) {
  const res = await fetchFn(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, body: json };
}

async function scenario(name, action_, auth) {
  const res = await postJson(GATEWAY_URL, { action: action_, authorization: auth });
  console.log(`SCENARIO: ${name}`, res.status, res.body);
  return res;
}

async function main() {
  const allowAuth = makeAuthorization({ action, authId: "auth-allow-1", intentHash });
  await scenario("ALLOW", action, allowAuth);

  // Intent/action mutation: the auth was signed against `action`; the
  // upstream request now carries a mutated action, so the gateway's
  // recomputed intent_hash no longer matches authorization.intent_hash.
  const mutatedAction = { ...action, params: { ...action.params, amount: "999999" } };
  await scenario("INTENT_MUTATION", mutatedAction, allowAuth);

  // Signature tamper: mutate state_hash after signing. state_hash is part of
  // the Ed25519 signing payload, so this breaks the signature rather than
  // the live-state binding check (see STATE_MUTATION below).
  const tamperedAuth = makeAuthorization({ action, authId: "auth-tamper-1", intentHash });
  tamperedAuth.state_hash = "0".repeat(64);
  await scenario("SIGNATURE_TAMPER", action, tamperedAuth);

  // State mutation: the AuthorizationV1 above is untouched and signature
  // valid. What changes is the live state OxDeAIGuard hashes when it
  // re-verifies the state_hash binding (guard.ts step 6c). The PEP gateway
  // used for the scenarios above has no live-state concept at all, so this
  // exercises OxDeAIGuard directly, in-process.
  const stateResult = await checkStateBinding();
  console.log("SCENARIO: STATE_MUTATION", stateResult);

  // Replay: reuse the already-consumed ALLOW authorization.
  await scenario("REPLAY", action, allowAuth);

  // Direct bypass: no internal executor token.
  const bypass = await postJson(DIRECT_URL, action.params);
  console.log("SCENARIO: BYPASS", bypass.status, bypass.body, "(expected 403)");
}

main().catch((err) => {
  console.error("unexpected error", err);
  process.exit(1);
});
