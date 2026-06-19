// SPDX-License-Identifier: Apache-2.0
import { createServer } from "node:http";
import type { IncomingMessage, ServerResponse, Server } from "node:http";
import type { ReplayStore } from "@oxdeai/guard";
import { loadConfig, redactedConfigSummary } from "./config.js";
import type { PepConfig } from "./config.js";
import type { FrappeAdapter, DecisionLog } from "./types.js";
import { handleAuthorize } from "./authorize.js";
import { handleExecute } from "./execute.js";
import { createFrappeHttpAdapter } from "./frappe.js";
import { createReplayStoreHandle } from "./replay.js";

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(data),
  });
  res.end(data);
}

const MAX_BODY_BYTES = 1_048_576; // 1 MiB

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let totalBytes = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    totalBytes += buf.length;
    if (totalBytes > MAX_BODY_BYTES) {
      req.resume();
      throw Object.assign(new Error("BODY_TOO_LARGE"), { statusCode: 413 });
    }
    chunks.push(buf);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw.trim() ? JSON.parse(raw) : {};
}

function emitDecisionLog(log: DecisionLog): void {
  console.log(JSON.stringify(log));
}

export type PepServerOptions = {
  config: PepConfig;
  replayStore?: ReplayStore;
  frappeAdapter?: FrappeAdapter;
};

export function createPepServer(options: PepServerOptions): Server & { shutdown: () => Promise<void> } {
  const { config } = options;
  let replayDisconnect: () => Promise<void> = async () => {};
  let replayStore: import("@oxdeai/guard").ReplayStore;
  if (options.replayStore) {
    replayStore = options.replayStore;
  } else {
    const handle = createReplayStoreHandle({
      config: config.replayStore,
      issuer: config.issuer,
      audience: config.expectedAudience,
      authorizationTtlSeconds: config.authorizationTtlSeconds,
    });
    replayStore = handle.store;
    replayDisconnect = handle.disconnect;
  }
  const frappeAdapter =
    options.frappeAdapter ??
    createFrappeHttpAdapter({
      baseUrl: config.frappeBaseUrl,
      apiKey: config.frappeApiKey,
      apiSecret: config.frappeApiSecret,
    });

  const authorize = handleAuthorize(config);
  const execute = handleExecute(config, replayStore, frappeAdapter);

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    if (req.method === "GET" && req.url === "/healthz") {
      return sendJson(res, 200, { ok: true, status: "healthy", mode: config.mode });
    }

    if (req.method === "POST" && req.url === "/authorize") {
      try {
        const body = await readJson(req);
        const result = authorize(body);
        emitDecisionLog(result.log);
        return sendJson(res, result.status, result.body);
      } catch (err) {
        const status = (err as { statusCode?: number }).statusCode === 413 ? 413
          : err instanceof SyntaxError ? 400 : 500;
        const reason = status === 413 ? "BODY_TOO_LARGE"
          : err instanceof SyntaxError ? "INVALID_JSON" : "INTERNAL_ERROR";
        return sendJson(res, status, {
          ok: false, decision: "DENY", mode: config.mode, reason,
        });
      }
    }

    if (req.method === "POST" && req.url === "/execute") {
      try {
        const body = await readJson(req);
        const result = await execute(body);
        emitDecisionLog(result.log);
        return sendJson(res, result.status, result.body);
      } catch (err) {
        const status = (err as { statusCode?: number }).statusCode === 413 ? 413
          : err instanceof SyntaxError ? 400 : 500;
        const reason = status === 413 ? "BODY_TOO_LARGE"
          : err instanceof SyntaxError ? "INVALID_JSON" : "INTERNAL_ERROR";
        return sendJson(res, status, {
          ok: false, decision: "DENY", mode: config.mode, reason,
        });
      }
    }

    return sendJson(res, 404, { ok: false, error: "not found" });
  }) as Server & { shutdown: () => Promise<void> };

  server.shutdown = async () => {
    await replayDisconnect();
    server.closeAllConnections();
    await new Promise<void>((res, rej) => server.close((e) => (e ? rej(e) : res())));
  };

  return server;
}

// Main entry point — only runs when executed directly
const isMain = process.argv[1]?.endsWith("server.js") || process.argv[1]?.endsWith("server.ts");
if (isMain) {
  const config = loadConfig();
  console.log("OxDeAI PEP starting", JSON.stringify(redactedConfigSummary(config)));
  const server = createPepServer({ config });
  server.listen(config.port, () => {
    console.log(`OxDeAI PEP listening on :${config.port} [mode=${config.mode}]`);
  });
}
