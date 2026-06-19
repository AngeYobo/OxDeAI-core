# OxDeAI PEP - LGF Frappe Helpdesk PoC

Minimal OxDeAI Policy Enforcement Point for the LGF-managed Frappe Helpdesk PoC.

Protected action: `frappe.helpdesk.create_ticket`

Core invariant: **No valid authorization → no execution path.**

## Endpoints

* `GET /healthz` - container health
* `POST /authorize` - evaluate policy, issue AuthorizationV1 for allowed actions
* `POST /execute` - verify AuthorizationV1, call Frappe if valid (enforce mode only)

## Quick start

See [LIVE_VALIDATION.md](LIVE_VALIDATION.md) for local build, run, and validation instructions.

## LGF deployment

See [LGF_DEPLOYMENT.md](LGF_DEPLOYMENT.md) for the LGF Platform Layer sidecar deployment model, responsibility boundaries, runtime configuration contract, and failure behavior.

## Related issues

* #141 - PoC definition
* #142 - Boundary contract documentation
* #143 - PEP container implementation
* #148 - Pluggable replay persistence
* #149 - LGF Platform Layer sidecar documentation
