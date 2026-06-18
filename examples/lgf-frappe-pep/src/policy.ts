// SPDX-License-Identifier: Apache-2.0
import { sha256HexFromJson } from "@oxdeai/core";
import type { ActionEnvelope } from "./types.js";

export const PROTECTED_ACTION = "frappe.helpdesk.create_ticket";

const ALLOWED_PRIORITIES = new Set(["Low", "Medium"]);
const DENIED_PRIORITIES = new Set(["Urgent"]);

const POLICY_DESCRIPTOR = {
  name: "lgf-frappe-helpdesk-poc-v1",
  protected_action: PROTECTED_ACTION,
  allowed_priorities: [...ALLOWED_PRIORITIES].sort(),
  denied_priorities: [...DENIED_PRIORITIES].sort(),
};

export const POLICY_ID = sha256HexFromJson(POLICY_DESCRIPTOR);

export type PolicyResult =
  | { decision: "ALLOW"; reason: string }
  | { decision: "DENY"; reason: string };

export function evaluatePolicy(envelope: ActionEnvelope): PolicyResult {
  if (envelope.action.tool !== PROTECTED_ACTION) {
    return { decision: "DENY", reason: "UNSUPPORTED_ACTION" };
  }

  const priority = envelope.action.params.priority;

  if (DENIED_PRIORITIES.has(priority)) {
    return { decision: "DENY", reason: "POLICY_DENIED_PRIORITY" };
  }

  if (ALLOWED_PRIORITIES.has(priority)) {
    return { decision: "ALLOW", reason: "POLICY_ALLOWED" };
  }

  return { decision: "DENY", reason: "UNKNOWN_PRIORITY" };
}
