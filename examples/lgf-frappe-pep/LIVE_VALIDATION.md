# Live Validation Guide - LGF Frappe Helpdesk PEP

Note: this guide is for live Frappe validation. It is separate from the local live Redis replay integration test, which does **not** require Frappe, LGF infrastructure, or secrets.

For the Redis replay persistence test, use:

```bash
docker compose -f examples/lgf-frappe-pep/docker-compose.redis.yml up -d redis
REDIS_URL=redis://127.0.0.1:6379 pnpm -C examples/lgf-frappe-pep test:redis
docker compose -f examples/lgf-frappe-pep/docker-compose.redis.yml down
```

Protected action: `frappe.helpdesk.create_ticket`

Core invariant: **No valid authorization → no execution path.**

Target environment:

```text
Frappe URL: https://frappe.lgf.oxdeai.dev
Helpdesk:   https://frappe.lgf.oxdeai.dev/helpdesk/dashboard
```

Expected total tickets created by this validation: **exactly one**.

## Prerequisites

- Docker installed locally.
- Network access to `https://frappe.lgf.oxdeai.dev`.
- A Frappe API key/secret pair with HD Ticket creation permission.
- `curl` and `jq` available.

## 1. Build the container

From the repo root:

```bash
docker build -f examples/lgf-frappe-pep/Dockerfile -t oxdeai-pep-frappe:local .
```

No secrets are involved in this step.

## 2. Generate a signing key

```bash
node -e "
  const { generateKeyPairSync } = require('crypto');
  const { privateKey } = generateKeyPairSync('ed25519');
  console.log(privateKey.export({ type: 'pkcs8', format: 'pem' }));
" > /tmp/pep-signing-key.pem
```

This key stays in `/tmp`, outside the repo. Never commit it.

## 3. Create the runtime env file

Copy the template to `/tmp` (outside the repo tree):

```bash
cp examples/lgf-frappe-pep/.env.live.example /tmp/.env.pep.live
```

Edit `/tmp/.env.pep.live` and fill in:

- `FRAPPE_API_KEY` - your real Frappe API key
- `FRAPPE_API_SECRET` - your real Frappe API secret

Remove the `SIGNING_PRIVATE_KEY_PEM` line from the env file - the signing key
will be passed separately via `docker run -e` to preserve real newlines.

**Never commit `/tmp/.env.pep.live` or any file containing real credentials.**

## 4. Start the container (enforce mode)

```bash
docker run --rm -p 3000:3000 \
  --env-file /tmp/.env.pep.live \
  -e "SIGNING_PRIVATE_KEY_PEM=$(cat /tmp/pep-signing-key.pem)" \
  oxdeai-pep-frappe:local
```

The startup log will show a redacted config summary (secrets masked with `***`).

## 5. Validate healthz

```bash
curl -s http://localhost:3000/healthz | jq .
```

Expected:

```json
{ "ok": true, "status": "healthy", "mode": "enforce" }
```

## 6. Authorize an allowed action

```bash
AUTH_RESPONSE=$(curl -s -X POST http://localhost:3000/authorize \
  -H 'Content-Type: application/json' \
  -d '{
    "source_bench": "openwebui-dev",
    "target_bench": "frappe",
    "agent_or_tool_context": "erp-assistant",
    "user_identity": "validation@oxdeai.dev",
    "session_id": "live-validation-001",
    "action": {
      "type": "EXECUTE",
      "tool": "frappe.helpdesk.create_ticket",
      "params": {
        "subject": "OxDeAI live validation ticket",
        "description": "Created through the OxDeAI PEP boundary during live validation.",
        "priority": "Low"
      }
    }
  }')

echo "$AUTH_RESPONSE" | jq '{ ok, decision, mode, auth_id, intent_hash, policy_id }'
```

Expected: `decision: "ALLOW"`, `authorization` present in full response.

Confirm no ticket was created - `/authorize` never calls Frappe.

## 7. Execute with valid authorization

```bash
ENVELOPE='{
  "source_bench": "openwebui-dev",
  "target_bench": "frappe",
  "agent_or_tool_context": "erp-assistant",
  "user_identity": "validation@oxdeai.dev",
  "session_id": "live-validation-001",
  "action": {
    "type": "EXECUTE",
    "tool": "frappe.helpdesk.create_ticket",
    "params": {
      "subject": "OxDeAI live validation ticket",
      "description": "Created through the OxDeAI PEP boundary during live validation.",
      "priority": "Low"
    }
  }
}'

AUTHORIZATION=$(echo "$AUTH_RESPONSE" | jq '.authorization')

EXEC_RESPONSE=$(curl -s -X POST http://localhost:3000/execute \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --argjson envelope "$ENVELOPE" --argjson authorization "$AUTHORIZATION" \
    '{ envelope: $envelope, authorization: $authorization }')")

echo "$EXEC_RESPONSE" | jq '{ ok, decision, mode, auth_id, frappe_ticket_id }'
```

Expected: `decision: "ALLOW"`, `frappe_ticket_id` present (e.g., `"HD-TICKET-00001"`).

**This is the only step that creates a Frappe ticket.**

## 8. DENY - policy-denied priority (Urgent)

```bash
curl -s -X POST http://localhost:3000/authorize \
  -H 'Content-Type: application/json' \
  -d '{
    "source_bench": "openwebui-dev",
    "target_bench": "frappe",
    "agent_or_tool_context": "erp-assistant",
    "user_identity": "validation@oxdeai.dev",
    "session_id": "live-validation-002",
    "action": {
      "type": "EXECUTE",
      "tool": "frappe.helpdesk.create_ticket",
      "params": {
        "subject": "Should not exist",
        "description": "This ticket must not be created.",
        "priority": "Urgent"
      }
    }
  }' | jq .
```

Expected: HTTP 403, `decision: "DENY"`, `reason: "POLICY_DENIED_PRIORITY"`, no `authorization`.

## 9. DENY - missing authorization

```bash
curl -s -X POST http://localhost:3000/execute \
  -H 'Content-Type: application/json' \
  -d '{
    "envelope": {
      "source_bench": "openwebui-dev",
      "target_bench": "frappe",
      "agent_or_tool_context": "erp-assistant",
      "user_identity": "validation@oxdeai.dev",
      "session_id": "live-validation-003",
      "action": {
        "type": "EXECUTE",
        "tool": "frappe.helpdesk.create_ticket",
        "params": {
          "subject": "No auth ticket",
          "description": "Must not be created.",
          "priority": "Low"
        }
      }
    }
  }' | jq .
```

Expected: HTTP 403, `decision: "DENY"`, `reason: "INVALID_REQUEST"`.

## 10. DENY - replayed authorization

Re-run the exact same `/execute` call from step 7 (same `$AUTHORIZATION`):

```bash
curl -s -X POST http://localhost:3000/execute \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --argjson envelope "$ENVELOPE" --argjson authorization "$AUTHORIZATION" \
    '{ envelope: $envelope, authorization: $authorization }')" \
  | jq '{ ok, decision, reason }'
```

Expected: HTTP 403, `reason` contains `AUTH_REPLAY`.

## 11. DENY - modified payload (intent hash mismatch)

Get a fresh authorization, then modify the envelope before executing:

```bash
FRESH_AUTH=$(curl -s -X POST http://localhost:3000/authorize \
  -H 'Content-Type: application/json' \
  -d '{
    "source_bench": "openwebui-dev",
    "target_bench": "frappe",
    "agent_or_tool_context": "erp-assistant",
    "user_identity": "validation@oxdeai.dev",
    "session_id": "live-validation-004",
    "action": {
      "type": "EXECUTE",
      "tool": "frappe.helpdesk.create_ticket",
      "params": {
        "subject": "Original subject",
        "description": "Original description.",
        "priority": "Low"
      }
    }
  }')

FRESH_AUTHORIZATION=$(echo "$FRESH_AUTH" | jq '.authorization')

TAMPERED_ENVELOPE='{
  "source_bench": "openwebui-dev",
  "target_bench": "frappe",
  "agent_or_tool_context": "erp-assistant",
  "user_identity": "validation@oxdeai.dev",
  "session_id": "live-validation-004",
  "action": {
    "type": "EXECUTE",
    "tool": "frappe.helpdesk.create_ticket",
    "params": {
      "subject": "TAMPERED subject",
      "description": "Original description.",
      "priority": "Low"
    }
  }
}'

curl -s -X POST http://localhost:3000/execute \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --argjson envelope "$TAMPERED_ENVELOPE" --argjson authorization "$FRESH_AUTHORIZATION" \
    '{ envelope: $envelope, authorization: $authorization }')" \
  | jq '{ ok, decision, reason }'
```

Expected: HTTP 403, `reason: "INTENT_HASH_MISMATCH"`.

## 12. Observe mode validation

Stop the enforce-mode container. Start in observe mode:

```bash
docker run --rm -p 3000:3000 \
  --env-file /tmp/.env.pep.live \
  -e "SIGNING_PRIVATE_KEY_PEM=$(cat /tmp/pep-signing-key.pem)" \
  -e "OXDEAI_MODE=observe" \
  oxdeai-pep-frappe:local
```

Run the authorize + execute sequence:

```bash
OBS_AUTH=$(curl -s -X POST http://localhost:3000/authorize \
  -H 'Content-Type: application/json' \
  -d '{
    "source_bench": "openwebui-dev",
    "target_bench": "frappe",
    "agent_or_tool_context": "erp-assistant",
    "user_identity": "validation@oxdeai.dev",
    "session_id": "live-validation-observe",
    "action": {
      "type": "EXECUTE",
      "tool": "frappe.helpdesk.create_ticket",
      "params": {
        "subject": "Observe mode ticket",
        "description": "Must NOT be created.",
        "priority": "Low"
      }
    }
  }')

echo "$OBS_AUTH" | jq '{ ok, decision, mode }'

OBS_AUTHORIZATION=$(echo "$OBS_AUTH" | jq '.authorization')

curl -s -X POST http://localhost:3000/execute \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --argjson envelope '{
    "source_bench": "openwebui-dev",
    "target_bench": "frappe",
    "agent_or_tool_context": "erp-assistant",
    "user_identity": "validation@oxdeai.dev",
    "session_id": "live-validation-observe",
    "action": {
      "type": "EXECUTE",
      "tool": "frappe.helpdesk.create_ticket",
      "params": {
        "subject": "Observe mode ticket",
        "description": "Must NOT be created.",
        "priority": "Low"
      }
    }
  }' --argjson authorization "$OBS_AUTHORIZATION" \
    '{ envelope: $envelope, authorization: $authorization }')" \
  | jq '{ ok, decision, mode, frappe_ticket_id }'
```

Expected:

- `/authorize`: `decision: "ALLOW"`, `mode: "observe"`
- `/execute`: `decision: "ALLOW"`, `mode: "observe"`, no `frappe_ticket_id`
- Container log: `executed: false`
- No ticket created in Frappe

## 13. Verify final ticket count

After all cases, confirm exactly one ticket exists with the validation subject:

```bash
# Replace <key>:<secret> with your Frappe API credentials.
# Do NOT paste this command with real credentials into any public location.
curl -s "https://frappe.lgf.oxdeai.dev/api/resource/HD%20Ticket?\
filters=[[\"subject\",\"like\",\"%OxDeAI live validation%\"]]&\
fields=[\"name\",\"subject\",\"priority\",\"creation\"]&limit_page_length=100" \
  -H "Authorization: token <key>:<secret>" \
  | jq '{ count: (.data | length), tickets: [.data[] | {name, subject, priority}] }'
```

Expected: count = 1, matching the ticket from step 7.

## Evidence to capture for the GitHub issue

Safe to include:

| Evidence | Example |
|----------|---------|
| `healthz` response | `{ "ok": true, "status": "healthy", "mode": "enforce" }` |
| `/authorize` summary | `{ "ok": true, "decision": "ALLOW", "auth_id": "...", "policy_id": "..." }` |
| `/execute` summary | `{ "ok": true, "decision": "ALLOW", "frappe_ticket_id": "HD-TICKET-00001" }` |
| DENY responses (full body) | `{ "ok": false, "decision": "DENY", "reason": "..." }` |
| Container startup log | Redacted config - credentials shown as `***` |
| Decision log lines | No secrets by design |
| Frappe ticket name/count | Ticket name is not a secret |
| Final ticket count | Just a number |

**Must NOT include:**

| Evidence | Why |
|----------|-----|
| Raw `authorization` JSON | Valid (short-lived) bearer artifact |
| `SIGNING_PRIVATE_KEY_PEM` | Can forge authorizations |
| `FRAPPE_API_KEY` / `FRAPPE_API_SECRET` | Direct Frappe access without PEP |
| `.env.live` file contents | Contains all secrets |
| `docker run` command with `-e` values | Exposes credentials in args |
| Full `docker inspect` / `env` / `printenv` | Exposes all env vars |
| LGF license keys or internal infra values | LGF-private |
| Shell history with credentials | Same |
