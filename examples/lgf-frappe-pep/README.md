# OxDeAI PEP - LGF Frappe Helpdesk PoC

Minimal OxDeAI Policy Enforcement Point for the LGF-managed Frappe Helpdesk PoC.

Protected action: `frappe.helpdesk.create_ticket`

Core invariant: **No valid authorization → no execution path.**

## Endpoints

* `GET /healthz` - container health
* `POST /authorize` - evaluate policy, issue AuthorizationV1 for allowed actions
* `POST /execute` - verify AuthorizationV1, call Frappe if valid (enforce mode only)

## Graceful shutdown

The runtime now installs explicit `SIGTERM` and `SIGINT` handlers.

On shutdown request it:

* logs a structured, non-secret shutdown event
* stops accepting new HTTP connections
* closes active HTTP connections through the existing `server.shutdown()` path
* disconnects an owned Redis replay client when `REPLAY_STORE=redis`
* exits cleanly on successful shutdown

This is operational hardening for the sidecar runtime. It does not change authorization semantics.

## Quick start

See [LIVE_VALIDATION.md](LIVE_VALIDATION.md) for local build, run, and validation instructions.

## Live Redis replay integration test

This example includes a live Redis integration test for the PEP replay persistence path.

What it proves:

* first execution succeeds once with `REPLAY_STORE=redis`
* replayed `AuthorizationV1` is denied with `AUTH_REPLAY`
* the target-platform adapter is not called on replay
* the Redis replay key uses the configured prefix
* the Redis replay key has a positive bounded TTL
* Redis outage fails closed with `REPLAY_STORE_UNAVAILABLE`

What it does **not** require:

* live Frappe
* LGF infrastructure
* API keys or secrets
* signing-key files on disk

The test uses the real PEP server plus a fake Frappe adapter that counts side effects.

Run locally:

```bash
docker compose -f examples/lgf-frappe-pep/docker-compose.redis.yml up -d redis
REDIS_URL=redis://127.0.0.1:6379 pnpm -C examples/lgf-frappe-pep test:redis
docker compose -f examples/lgf-frappe-pep/docker-compose.redis.yml down
```

The replay backend is one implementation detail behind the PEP boundary. Redis here is used only to validate replay persistence behavior.

Current CI note: this live Redis test is designed to run locally today. Service-container or CI Compose wiring can be added later without changing the test contract.

## LGF deployment

See [LGF_DEPLOYMENT.md](LGF_DEPLOYMENT.md) for the LGF Platform Layer sidecar deployment model, responsibility boundaries, runtime configuration contract, and failure behavior.

## Related issues

* #141 - PoC definition
* #142 - Boundary contract documentation
* #143 - PEP container implementation
* #148 - Pluggable replay persistence
* #149 - LGF Platform Layer sidecar documentation
