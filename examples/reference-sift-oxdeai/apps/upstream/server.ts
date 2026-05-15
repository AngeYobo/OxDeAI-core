// SPDX-License-Identifier: Apache-2.0
/**
 * Protected execution target (upstream).
 *
 * INVARIANT: direct access is impossible.
 *
 * Every request MUST carry the X-Internal-Execution-Token header matching
 * the token known only to the PEP Gateway. Any request without this exact
 * token receives 403 and the request is not processed.
 *
 * There is no authentication bypass, no fallback, and no default token.
 * The token is generated at startup and is never logged or returned in
 * any response body.
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface UpstreamConfig {
  port: number;
  internalToken: string;
}

export interface UpstreamHandle {
  url: string;
  close(): Promise<void>;
}

// ─── Server ───────────────────────────────────────────────────────────────────

function jsonResponse(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk: Buffer) => { data += chunk.toString(); });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

export function startUpstream(config: UpstreamConfig): Promise<UpstreamHandle> {
  return new Promise((resolve, reject) => {
    const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      // ── Invariant: non-bypassable execution boundary ───────────────────────
      // This is the ONLY check that matters. No AuthorizationV1 is inspected
      // here — that is the PEP's responsibility. The upstream trusts only the
      // internal token, which is never reachable from outside the PEP.
      const token = req.headers["x-internal-executor-token"];
      if (token !== config.internalToken) {
        return jsonResponse(res, 403, {
          ok: false,
          code: "FORBIDDEN",
          message: "Direct access not permitted. Route through PEP Gateway.",
        });
      }

      // Token valid — execute the request.
      try {
        await readBody(req); // consume body
        return jsonResponse(res, 200, { ok: true, executed: true });
      } catch (e) {
        return jsonResponse(res, 500, {
          ok: false,
          code: "UPSTREAM_ERROR",
          message: e instanceof Error ? e.message : String(e),
        });
      }
    });

    server.on("error", reject);

    server.listen(config.port, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        reject(new Error("Unexpected server address type"));
        return;
      }
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        close(): Promise<void> {
          return new Promise((res, rej) =>
            server.close((e) => (e ? rej(e) : res()))
          );
        },
      });
    });
  });
}
