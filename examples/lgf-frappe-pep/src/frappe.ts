// SPDX-License-Identifier: Apache-2.0
import type { FrappeAdapter, FrappeCreateTicketParams, FrappeCreateTicketResult } from "./types.js";

export type FrappeHttpAdapterOptions = {
  baseUrl: string;
  apiKey: string;
  apiSecret: string;
};

export function createFrappeHttpAdapter(options: FrappeHttpAdapterOptions): FrappeAdapter {
  const doctype = encodeURIComponent("HD Ticket");

  return {
    async createTicket(params: FrappeCreateTicketParams): Promise<FrappeCreateTicketResult> {
      const url = `${options.baseUrl}/api/resource/${doctype}`;
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `token ${options.apiKey}:${options.apiSecret}`,
        },
        body: JSON.stringify({
          data: {
            subject: params.subject,
            description: params.description,
            priority: params.priority,
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
      const name = data?.["name"];
      if (typeof name !== "string") {
        const keys = Object.keys(result).join(",");
        throw new Error(`Frappe API unexpected response shape: top-level keys=[${keys}]`);
      }

      return { ticket_id: name, name };
    },
  };
}
