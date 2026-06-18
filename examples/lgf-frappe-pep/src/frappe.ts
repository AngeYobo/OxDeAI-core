// SPDX-License-Identifier: Apache-2.0
import type { FrappeAdapter, FrappeCreateTicketParams, FrappeCreateTicketResult } from "./types.js";

export type FrappeHttpAdapterOptions = {
  baseUrl: string;
  apiKey: string;
  apiSecret: string;
};

export function createFrappeHttpAdapter(options: FrappeHttpAdapterOptions): FrappeAdapter {
  return {
    async createTicket(params: FrappeCreateTicketParams): Promise<FrappeCreateTicketResult> {
      const url = `${options.baseUrl}/api/resource/HD Ticket`;
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
        throw new Error(`Frappe API error: ${response.status} ${text}`);
      }

      const result = await response.json() as { data?: { name?: string } };
      const name = result?.data?.name;
      if (typeof name !== "string") {
        throw new Error("Frappe API returned unexpected response shape");
      }

      return { ticket_id: name, name };
    },
  };
}
