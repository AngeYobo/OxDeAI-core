// SPDX-License-Identifier: Apache-2.0
import { randomUUID } from "node:crypto";
import { sha256HexFromJson, signAuthorizationEd25519 } from "@oxdeai/core";
import type { AuthorizationV1 } from "@oxdeai/core";
import type { PepConfig } from "./config.js";
import type { ActionEnvelope, PepResponse, DecisionLog } from "./types.js";
import { evaluatePolicy, POLICY_ID } from "./policy.js";

function parseEnvelope(body: unknown): ActionEnvelope | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return null;
  const b = body as Record<string, unknown>;
  if (typeof b["source_bench"] !== "string") return null;
  if (typeof b["target_bench"] !== "string") return null;
  if (typeof b["agent_or_tool_context"] !== "string") return null;
  if (typeof b["user_identity"] !== "string") return null;
  if (typeof b["session_id"] !== "string") return null;
  const action = b["action"];
  if (typeof action !== "object" || action === null) return null;
  const a = action as Record<string, unknown>;
  if (a["type"] !== "EXECUTE") return null;
  if (typeof a["tool"] !== "string") return null;
  const params = a["params"];
  if (typeof params !== "object" || params === null) return null;
  const p = params as Record<string, unknown>;
  if (typeof p["subject"] !== "string") return null;
  if (typeof p["description"] !== "string") return null;
  if (typeof p["priority"] !== "string") return null;
  return body as ActionEnvelope;
}

export function handleAuthorize(config: PepConfig) {
  return (body: unknown): { status: number; body: PepResponse; log: DecisionLog } => {
    const correlationId = randomUUID();
    const now = Math.floor(Date.now() / 1000);

    const envelope = parseEnvelope(body);
    if (!envelope) {
      const log: DecisionLog = {
        correlation_id: correlationId,
        action: "unknown",
        expected_audience: config.expectedAudience,
        auth_id: null,
        intent_hash: null,
        policy_id: POLICY_ID,
        mode: config.mode,
        decision: "DENY",
        reason: "INVALID_ENVELOPE",
        executed: false,
        frappe_ticket_id: null,
        timestamp: new Date(now * 1000).toISOString(),
      };
      return {
        status: 400,
        body: { ok: false, decision: "DENY", mode: config.mode, reason: "INVALID_ENVELOPE" },
        log,
      };
    }

    const intentHash = sha256HexFromJson(envelope.action);
    const policyResult = evaluatePolicy(envelope);

    if (policyResult.decision === "DENY") {
      const log: DecisionLog = {
        correlation_id: correlationId,
        action: envelope.action.tool,
        expected_audience: config.expectedAudience,
        auth_id: null,
        intent_hash: intentHash,
        policy_id: POLICY_ID,
        mode: config.mode,
        decision: "DENY",
        reason: policyResult.reason,
        executed: false,
        frappe_ticket_id: null,
        timestamp: new Date(now * 1000).toISOString(),
      };
      return {
        status: 403,
        body: { ok: false, decision: "DENY", mode: config.mode, reason: policyResult.reason },
        log,
      };
    }

    const stateHash = sha256HexFromJson({});
    const authId = randomUUID();
    const expiry = now + config.authorizationTtlSeconds;
    const privateKeyPem = config.signingPrivateKey.export({ type: "pkcs8", format: "pem" }) as string;

    const authorization: AuthorizationV1 = signAuthorizationEd25519(
      {
        auth_id: authId,
        issuer: config.issuer,
        audience: config.expectedAudience,
        intent_hash: intentHash,
        state_hash: stateHash,
        policy_id: POLICY_ID,
        decision: "ALLOW",
        issued_at: now,
        expiry,
        kid: config.signingKid,
        nonce: randomUUID(),
      },
      privateKeyPem,
    );

    const log: DecisionLog = {
      correlation_id: correlationId,
      action: envelope.action.tool,
      expected_audience: config.expectedAudience,
      auth_id: authId,
      intent_hash: intentHash,
      policy_id: POLICY_ID,
      mode: config.mode,
      decision: "ALLOW",
      reason: "POLICY_ALLOWED",
      executed: false,
      frappe_ticket_id: null,
      timestamp: new Date(now * 1000).toISOString(),
    };

    return {
      status: 200,
      body: {
        ok: true,
        decision: "ALLOW",
        mode: config.mode,
        auth_id: authId,
        intent_hash: intentHash,
        policy_id: POLICY_ID,
        authorization,
      },
      log,
    };
  };
}
