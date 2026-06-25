// SPDX-License-Identifier: Apache-2.0
import type { AuthorizationV1 } from "@oxdeai/core";

export type ActionEnvelope = {
  source_bench: string;
  target_bench: string;
  agent_or_tool_context: string;
  user_identity: string;
  session_id: string;
  action: {
    type: "EXECUTE";
    tool: string;
    params: {
      subject: string;
      description: string;
      priority: string;
      [key: string]: unknown;
    };
  };
};

export type AuthorizeRequest = ActionEnvelope;

export type ExecuteRequest = {
  envelope: ActionEnvelope;
  authorization: AuthorizationV1;
};

export type PepResponse =
  | {
      ok: true;
      decision: "ALLOW";
      mode: "enforce" | "observe";
      auth_id: string;
      intent_hash: string;
      policy_id: string;
      authorization?: AuthorizationV1;
      frappe_ticket_id?: string;
    }
  | {
      ok: false;
      decision: "DENY";
      mode: "enforce" | "observe";
      reason: string;
    };

export type DecisionLog = {
  correlation_id: string;
  action: string;
  expected_audience: string;
  auth_id: string | null;
  intent_hash: string | null;
  policy_id: string;
  mode: "enforce" | "observe";
  decision: "ALLOW" | "DENY";
  reason: string;
  executed: boolean;
  frappe_ticket_id: string | null;
  timestamp: string;
};
