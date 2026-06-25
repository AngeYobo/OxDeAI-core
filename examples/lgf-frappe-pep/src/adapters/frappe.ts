// SPDX-License-Identifier: Apache-2.0
import type {
  PlatformAdapter,
  PlatformExecutionContext,
  PlatformExecutionResult,
} from "./platform.js";

export type FrappeHttpAdapterOptions = {
  baseUrl: string;
  apiKey: string;
  apiSecret: string;
};

export type FrappeCreateTicketParams = {
  subject: string;
  description: string;
  priority: string;
};

export const FRAPPE_CREATE_TICKET_ACTION = "frappe.helpdesk.create_ticket";

function isFrappeCreateTicketParams(payload: unknown): payload is FrappeCreateTicketParams {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) return false;
  const p = payload as Record<string, unknown>;
  return typeof p["subject"] === "string"
    && typeof p["description"] === "string"
    && typeof p["priority"] === "string";
}

export function createFrappePlatformAdapter(options: FrappeHttpAdapterOptions): PlatformAdapter {
  const doctype = encodeURIComponent("HD Ticket");

  return {
    name: "frappe",
    async execute(
      action: string,
      payload: unknown,
      _context: PlatformExecutionContext,
    ): Promise<PlatformExecutionResult> {
      if (action !== FRAPPE_CREATE_TICKET_ACTION) {
        throw new Error(`Unsupported Frappe adapter action: ${action}`);
      }
      if (!isFrappeCreateTicketParams(payload)) {
        throw new Error("Invalid Frappe create-ticket payload");
      }

      const url = `${options.baseUrl}/api/resource/${doctype}`;
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `token ${options.apiKey}:${options.apiSecret}`,
        },
        body: JSON.stringify({
          data: {
            subject: payload.subject,
            description: payload.description,
            priority: payload.priority,
          },
        }),
      });

      if (!response.ok) {
        const text = await response.text().catch(() => "");
        throw new Error(`Frappe API error: status=${response.status} body=${text.slice(0, 200)}`);
      }

      const contentType = response.headers.get("content-type") ?? "";
      if (!contentType.includes("application/json")) {
        throw new Error(`Frappe API returned non-JSON content-type=${contentType} status=${response.status}`);
      }

      const result = await response.json() as Record<string, unknown>;
      const data = result["data"] as Record<string, unknown> | undefined;
      const rawName = data?.["name"];

      if (typeof rawName !== "string" && typeof rawName !== "number") {
        const keys = Object.keys(result).join(",");
        throw new Error(`Frappe API unexpected response shape: top-level keys=[${keys}]`);
      }

      const name = String(rawName);
      return {
        resource_id: name,
        details: { ticket_id: name, name },
      };
    },
  };
}
