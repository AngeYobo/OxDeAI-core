# LGF-managed Frappe Helpdesk PoC

Status: Draft  
Related issue: #141  
Scope: external interoperability PoC  
Protected action: `frappe.helpdesk.create_ticket`

## Purpose

This PoC validates OxDeAI as a deployable execution authorization boundary inside an externally managed runtime.

LGF manages the deployment environment. OxDeAI manages execution authorization.

The invariant under test is:

> No valid authorization -> no execution path.

## Boundary Summary

The PoC uses an LGF-managed Frappe / ERPNext bench with Helpdesk installed.

The protected action is narrow by design:

```text
frappe.helpdesk.create_ticket
```

The goal is not to protect all of Frappe, all of ERPNext, or all OpenWebUI tool calls. The goal is to prove that one side-effecting business action cannot execute unless an OxDeAI AuthorizationV1 artifact is valid at the PEP boundary.

## Responsibility Split

### LGF responsibilities

LGF owns:

* host provisioning assumptions
* bench lifecycle
* reverse proxy routing
* TLS termination
* bench service topology
* bench start, stop, repair, backup, and update operations
* network ingress policy
* Frappe / ERPNext / Helpdesk deployment

### OxDeAI responsibilities

OxDeAI owns:

* action canonicalization
* AuthorizationV1 issuance
* AuthorizationV1 verification
* replay protection
* audience validation
* expiry validation
* intent hash binding
* fail-closed execution enforcement
* PEP decision logging
* protected-action adapter rules

### Frappe responsibilities

Frappe owns:

* Helpdesk application behavior
* ticket persistence
* Frappe REST API semantics
* Frappe user and API credential model

## Deployment Shape

```text
OpenWebUI / agent / caller
        |
        | HTTPS + declared caller identity
        v
OxDeAI PEP
        |
        | verifies AuthorizationV1
        | checks replay / expiry / audience / intent hash
        v
Frappe adapter
        |
        | holds Frappe API credential
        v
LGF-managed Frappe Helpdesk
```

The Frappe API credential must be held only by the PEP or its trusted adapter.

If the caller can create the Helpdesk ticket directly through the main Frappe route without passing through the PEP, the PoC fails.

## Known LGF Bench State

The initial external test environment used:

```text
LGF base domain: lgf.oxdeai.dev
Frappe bench hostname: frappe.lgf.oxdeai.dev
Helpdesk route: https://frappe.lgf.oxdeai.dev/helpdesk/dashboard
```

Helpdesk was confirmed installed and reachable.

This environment is a private evaluation environment and is not part of the public protocol surface.

## Two-phase Flow

The PoC uses a two-phase flow.

### Phase 1: authorize

Endpoint:

```text
POST /authorize
```

The caller submits a proposed action envelope.

The PEP/PDP evaluates:

```text
intent + state + policy
```

If the decision is `ALLOW`, it emits an AuthorizationV1 artifact.

If the decision is `DENY`, it emits no executable authorization artifact.

No Frappe action is executed during `/authorize`.

### Phase 2: execute

Endpoint:

```text
POST /execute
```

The caller submits the same action envelope plus the AuthorizationV1 artifact.

The PEP verifies:

* signature
* trusted issuer / key
* audience
* expiry
* replay status
* intent hash
* action binding
* protected action name

Only after verification succeeds may the adapter call Frappe.

## Minimal Action Envelope

```json
{
  "source_bench": "openwebui-dev",
  "target_bench": "frappe",
  "agent_or_tool_context": "erp-assistant",
  "user_identity": "user@example.com",
  "session_id": "example-session",
  "action": {
    "type": "EXECUTE",
    "tool": "frappe.helpdesk.create_ticket",
    "params": {
      "subject": "OxDeAI PoC ticket",
      "description": "Created through the OxDeAI execution boundary PoC.",
      "priority": "Low"
    }
  }
}
```

## Minimal Policy

Initial policy for the PoC:

```text
ALLOW priority = Low
ALLOW priority = Medium
DENY  priority = Urgent
```

This is intentionally simple. The purpose is boundary validation, not business policy completeness.

## Expected Decisions

| Case                                      | Expected result |
| ----------------------------------------- | --------------- |
| Valid authorization                       | Ticket created  |
| Missing authorization                     | DENY, no ticket |
| Invalid signature                         | DENY, no ticket |
| Expired authorization                     | DENY, no ticket |
| Replayed authorization                    | DENY, no ticket |
| Wrong audience                            | DENY, no ticket |
| Modified payload after authorization      | DENY, no ticket |
| Policy-denied priority                    | DENY, no ticket |
| Direct Frappe call without PEP credential | No ticket       |

## PEP Modes

The PoC supports two modes.

### Observe mode

Observe mode may log what would have happened, but it is not a security boundary.

Observe mode must not be described as protected execution.

### Enforce mode

Enforce mode is the boundary proof.

Protected execution must fail closed if the authorization is missing, invalid, expired, replayed, wrong-audience, or intent-mismatched.

## Credential Isolation Requirement

The Frappe credential capable of creating Helpdesk tickets must not be available to:

* OpenWebUI
* the agent runtime
* the browser client
* the caller
* unprotected scripts
* public environment variables
* committed repository files

The credential belongs only to the PEP runtime or trusted adapter.

## Logging Requirements

Each decision should log:

* correlation id
* action name
* expected audience
* authorization id
* intent hash
* policy id
* decision
* reason code
* execution result
* Frappe ticket id if executed

Logs must not expose secrets.

## Non-goals

This PoC does not claim:

* production readiness
* full Frappe protection
* full ERPNext protection
* full OpenWebUI governance
* LGF protocol changes
* OxDeAI protocol changes
* general-purpose Frappe authorization
* issuer/verifier separation
* full live-state Profile C verification

## Acceptance Criteria

The PoC is complete when:

* the LGF-managed Frappe bench is reachable
* Helpdesk is installed
* the PEP exposes `/authorize`, `/execute`, and `/healthz`
* `/authorize` emits AuthorizationV1 only for allowed actions
* `/execute` creates one Helpdesk ticket with valid authorization
* invalid authorization creates no ticket
* replayed authorization creates no ticket
* expired authorization creates no ticket
* wrong-audience authorization creates no ticket
* modified payload creates no ticket
* policy-denied action creates no ticket
* no caller outside the PEP holds a Frappe ticket-creation credential
* direct bypass attempts fail
* observe mode is visibly marked as non-enforcing
* enforce mode fails closed

## Current PoC Status

Initial LGF/Frappe environment validation is complete.

Confirmed:

* LGF installed
* Frappe bench created
* HTTPS bench route active
* Helpdesk installed
* Helpdesk dashboard reachable
* Frappe backend, frontend, queues, scheduler, websocket, Redis, and MariaDB running

Known LGF observations from setup:

* `verify-operational` reported rendered `.env` hash drift after update and repair
* after enabling bench HTTPS, generated host reverse proxy upstream used HTTPS toward the local Frappe backend even though Frappe listens internally over HTTP
* manually changing the upstream from `https://127.0.0.1:8080` to `http://127.0.0.1:8080` made the HTTPS Helpdesk route return `200`

These observations are LGF environment notes, not OxDeAI protocol changes.
