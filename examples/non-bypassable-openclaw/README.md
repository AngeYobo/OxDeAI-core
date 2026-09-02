# Non-bypassable Execution Boundary - OpenClaw

## Status
Non-normative (developer demo)

## What it shows
- OpenClaw agent calls the PEP Gateway with a properly signed AuthorizationV1.
- Gateway enforces ALLOW, intent binding, signature integrity, and replay.
- OxDeAIGuard enforces live-state binding (state_hash) in-process; the PEP
  gateway itself has no live-state concept (see Notes).
- Direct upstream call (no token) returns 403.
- No valid authorization, no execution path.

## Run
Prereqs: Node 20+, pnpm 9+, repo deps installed.

```bash
export UPSTREAM_EXECUTOR_TOKEN=demo-internal-token

pnpm -C examples/non-bypassable-openclaw upstream &
pnpm -C examples/non-bypassable-openclaw gateway &
sleep 2
pnpm -C examples/non-bypassable-openclaw agent
```

Expected:

* ALLOW: executed (valid signature, intent hash matches, state hash matches)
* INTENT_MUTATION: blocked with reason `INTENT_HASH_MISMATCH` (action mutated after signing)
* SIGNATURE_TAMPER: blocked with reason `AUTH_SIGNATURE_INVALID` (`state_hash` field tampered after signing, breaks the signature)
* STATE_MUTATION: blocked with `boundaryFailure` `STATE_HASH_MISMATCH` (authorization untouched and signature valid; the live state OxDeAIGuard hashes for its own re-check no longer matches)
* REPLAY: blocked with reason `AUTH_REPLAY` (auth_id already consumed by ALLOW)
* BYPASS: rejected (403, no internal token)

Run the deterministic regression suite instead of the manual flow above with:

```bash
pnpm -C examples/non-bypassable-openclaw test
```

It asserts the exact reason for each denial, not just that a denial occurred.

## Notes
- Reuses the existing protected upstream, PEP gateway, and signed authorization
  fixture from `../non-bypassable-demo`; only the agent side is OpenClaw-driven.
- Uses native `fetch` when available (falls back to `node-fetch` lazily if needed).
- The authorization fixture is a real Ed25519-signed `AuthorizationV1` with a
  complete field set (issuer, kid, policy_id, state_hash, intent_hash, expiry,
  nonce, capability, audience). It is not a reduced or fabricated object.
- `state-boundary.mjs` runs the STATE_MUTATION scenario against a real
  in-process `OxDeAIGuard`, not the HTTP PEP gateway. `packages/guard/src/gateway.ts`
  (`createPepGatewayHttpServer`) checks signature, audience, intent_hash, and
  replay only; it has no live-state or state_hash comparison. State_hash
  binding is `OxDeAIGuard`'s own check (guard.ts step 6c), triggered here via
  `computeStateHash` hashing a mutated clone of the live state, so the
  authorization itself stays unmodified and signature-valid throughout.
