// SPDX-License-Identifier: Apache-2.0
import { createServer, request as httpRequest } from "node:http";
import type { IncomingHttpHeaders, IncomingMessage, Server, ServerResponse } from "node:http";
import { sha256HexFromJson, verifyAuthorization } from "@oxdeai/core";
import type { AuthorizationAuthority, AuthorizationV1, KeySet } from "@oxdeai/core";
import { createInMemoryReplayStore } from "./replayStore.js";
import type { ReplayStore } from "./replayStore.js";

export const INTERNAL_EXECUTOR_TOKEN_HEADER = "x-internal-executor-token";

export type PepGatewayExecuteRequest = {
  action: unknown;
  authorization: AuthorizationV1;
};

export type PepGatewayResponseBody = {
  ok: boolean;
  decision: "ALLOW" | "DENY";
  executed: boolean;
  reason?: string;
  auth_id?: string;
  intent_hash?: string;
  upstream_result?: unknown;
  upstream_status?: number;
  upstream_error?: unknown;
};

export type PepGatewayResult = {
  status: 200 | 403 | 500 | 502 | 504;
  body: PepGatewayResponseBody;
  upstreamCalled: boolean;
};

export type UpstreamExecutor = (
  action: unknown,
  headers: Record<string, string>
) => Promise<{ status: number; body?: unknown }>;

export type PepGatewayOptions = {
  expectedAudience: string;
  trustedKeySets: KeySet | readonly KeySet[];
  internalExecutorToken: string;
  executeUpstream: UpstreamExecutor;
  /**
   * Deployer-configured (issuer, policyId) pairs authorized to issue
   * authorizations accepted by this gateway. REQUIRED.
   *
   * The gateway is the highest-risk boundary in the system: the authorization
   * arrives inside an untrusted request. A valid signature under
   * {@link trustedKeySets} proves that a trusted key for the *claimed* issuer
   * signed the artifact — it does not prove that this issuer may issue for the
   * claimed `policy_id`. This list is the only thing that can prove the latter,
   * and it must exist before the request arrives.
   *
   * ```text
   * missing    -> createPepGatewayExecutor() throws at construction
   * []         -> valid configuration authorizing no pair; every request denied
   * ```
   *
   * There is no unconstrained mode. `undefined` is a configuration error, not
   * "accept any issuer/policy".
   *
   * Authority is a complete pair, matched exactly on both members. Do not
   * decompose it into separate issuer and policy allow-lists: given `A/P1` and
   * `B/P2`, that would also authorize `A/P2` and `B/P1`.
   *
   * ⚠️ Supersedes the removed `expectedIssuer` option. To constrain the gateway
   * to a single issuer, list only that issuer's pairs.
   */
  trustedAuthorizationAuthorities: readonly AuthorizationAuthority[];
  replayStore?: ReplayStore;
  now?: () => number;
  timeoutMs?: number;
  hashAction?: (action: unknown) => string;
};

export type ProtectedUpstreamOptions<T = unknown> = {
  expectedToken: string;
  execute: (body: unknown) => T | Promise<T>;
};

function deny(status: PepGatewayResult["status"], reason: string, extra: Partial<PepGatewayResponseBody> = {}): PepGatewayResult {
  return {
    status,
    upstreamCalled: false,
    body: { ok: false, decision: "DENY", executed: false, reason, ...extra },
  };
}

function requireText(value: string | undefined, name: string): void {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${name} is required`);
  }
}

function asKeySets(keySets: KeySet | readonly KeySet[]): readonly KeySet[] {
  return Array.isArray(keySets) ? (keySets as readonly KeySet[]) : [keySets as KeySet];
}

function headerValue(headers: IncomingHttpHeaders | Record<string, string | string[] | undefined>, name: string): string | undefined {
  const raw = headers[name.toLowerCase()];
  if (Array.isArray(raw)) return raw.length === 1 ? raw[0] : undefined;
  return raw;
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) return promise;
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(Object.assign(new Error("UPSTREAM_TIMEOUT"), { code: "UPSTREAM_TIMEOUT" })), timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      }
    );
  });
}

export function hasValidInternalExecutorToken(
  headers: IncomingHttpHeaders | Record<string, string | string[] | undefined>,
  expectedToken: string
): boolean {
  requireText(expectedToken, "expectedToken");
  return headerValue(headers, INTERNAL_EXECUTOR_TOKEN_HEADER) === expectedToken;
}

export async function protectUpstreamExecution<T = unknown>(
  body: unknown,
  headers: IncomingHttpHeaders | Record<string, string | string[] | undefined>,
  options: ProtectedUpstreamOptions<T>
): Promise<{ status: 200 | 403 | 500; body: unknown; executed: boolean }> {
  if (!hasValidInternalExecutorToken(headers, options.expectedToken)) {
    return {
      status: 403,
      executed: false,
      body: { ok: false, executed: false, error: "missing or invalid internal executor token" },
    };
  }

  try {
    const result = await options.execute(body);
    return { status: 200, executed: true, body: result };
  } catch (err) {
    return {
      status: 500,
      executed: false,
      body: { ok: false, executed: false, error: err instanceof Error ? err.message : String(err) },
    };
  }
}

export function createPepGatewayExecutor(options: PepGatewayOptions) {
  requireText(options.expectedAudience, "expectedAudience");
  requireText(options.internalExecutorToken, "internalExecutorToken");
  const trustedKeySets = asKeySets(options.trustedKeySets);
  if (trustedKeySets.length === 0) throw new Error("trustedKeySets are required");
  // Fail at construction, not at first request: a gateway that cannot decide
  // policy authority must never come up in a state where it can serve traffic.
  // An explicitly configured empty array is accepted here and denies every
  // request at the authority check — a deliberate configuration, and distinct
  // from having configured nothing at all.
  const trustedAuthorizationAuthorities = options.trustedAuthorizationAuthorities;
  if (!Array.isArray(trustedAuthorizationAuthorities)) {
    throw new Error(
      "trustedAuthorizationAuthorities is required: the gateway accepts authorizations from untrusted " +
        "request input and cannot infer which issuer is authorized for which policy_id. " +
        "An absent authority list is not an unconstrained mode."
    );
  }
  const replayStore = options.replayStore ?? createInMemoryReplayStore();
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  const hashAction = options.hashAction ?? sha256HexFromJson;
  const timeoutMs = options.timeoutMs ?? 30_000;

  return async function executeThroughPep(input: unknown): Promise<PepGatewayResult> {
    if (!input || typeof input !== "object" || Array.isArray(input)) {
      return deny(403, "INVALID_REQUEST");
    }

    const requestBody = input as Partial<PepGatewayExecuteRequest>;
    if (requestBody.action === undefined || !requestBody.authorization) {
      return deny(403, "INVALID_REQUEST");
    }

    let intentHash: string;
    try {
      intentHash = hashAction(requestBody.action);
    } catch (err) {
      return deny(403, `ACTION_CANONICALIZATION_FAILED:${err instanceof Error ? err.message : String(err)}`);
    }

    const authorization = requestBody.authorization;
    const verification = verifyAuthorization(authorization, {
      now: now(),
      mode: "strict",
      trustedKeySets,
      requireSignatureVerification: true,
      expectedAudience: options.expectedAudience,
      // `expectedPolicyId: authorization.policy_id` was removed here (#301): it
      // compared the artifact against itself and proved nothing. Policy
      // authority now comes from deployer configuration that existed before the
      // request, evaluated as a complete (issuer, policy_id) pair.
      trustedAuthorizationAuthorities,
    });

    if (verification.status !== "ok") {
      const reason = verification.violations.map((v) => v.code).join(",") || "AUTHORIZATION_INVALID";
      return deny(403, reason);
    }

    if (authorization.intent_hash !== intentHash) {
      return deny(403, "INTENT_HASH_MISMATCH");
    }

    let consumed: boolean;
    try {
      consumed = await replayStore.consumeAuthId(authorization.auth_id, { expiry: authorization.expiry });
    } catch (err) {
      return deny(403, `REPLAY_STORE_UNAVAILABLE:${err instanceof Error ? err.message : String(err)}`);
    }
    if (!consumed) return deny(403, "AUTH_REPLAY");

    try {
      const upstream = await withTimeout(
        options.executeUpstream(requestBody.action, {
          [INTERNAL_EXECUTOR_TOKEN_HEADER]: options.internalExecutorToken,
        }),
        timeoutMs
      );

      if (!upstream || typeof upstream.status !== "number" || upstream.status >= 400) {
        return {
          status: 502,
          upstreamCalled: true,
          body: {
            ok: false,
            decision: "DENY",
            executed: false,
            reason: "UPSTREAM_ERROR",
            upstream_status: upstream?.status,
            upstream_error: upstream?.body,
          },
        };
      }

      return {
        status: 200,
        upstreamCalled: true,
        body: {
          ok: true,
          decision: "ALLOW",
          executed: true,
          auth_id: authorization.auth_id,
          intent_hash: intentHash,
          upstream_result: upstream.body,
        },
      };
    } catch (err) {
      if ((err as { code?: string })?.code === "UPSTREAM_TIMEOUT" || (err as Error)?.message === "UPSTREAM_TIMEOUT") {
        return {
          status: 504,
          upstreamCalled: true,
          body: { ok: false, decision: "DENY", executed: false, reason: "UPSTREAM_TIMEOUT" },
        };
      }
      return {
        status: 502,
        upstreamCalled: true,
        body: {
          ok: false,
          decision: "DENY",
          executed: false,
          reason: "UPSTREAM_ERROR",
          upstream_error: err instanceof Error ? err.message : String(err),
        },
      };
    }
  };
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(data),
  });
  res.end(data);
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw.trim() ? JSON.parse(raw) : {};
}

export function createPepGatewayHttpServer(options: PepGatewayOptions): Server {
  const executeThroughPep = createPepGatewayExecutor(options);
  return createServer(async (req, res) => {
    if (req.method === "GET" && req.url === "/healthz") {
      return sendJson(res, 200, { ok: true, route: "gateway", status: "healthy" });
    }
    if (req.method !== "POST" || req.url !== "/execute") {
      return sendJson(res, 404, { ok: false, error: "not found" });
    }

    try {
      const body = await readJson(req);
      const result = await executeThroughPep(body);
      return sendJson(res, result.status, result.body);
    } catch (err) {
      return sendJson(res, err instanceof SyntaxError ? 403 : 500, {
        ok: false,
        decision: "DENY",
        executed: false,
        reason: err instanceof SyntaxError ? "INVALID_JSON" : "GATEWAY_ERROR",
      });
    }
  });
}

export function createHttpUpstreamExecutor(options: {
  hostname?: string;
  port: number;
  path: string;
  method?: "POST";
}): UpstreamExecutor {
  return (action, headers) =>
    new Promise((resolve, reject) => {
      const body = JSON.stringify((action as { params?: unknown })?.params ?? action ?? {});
      const req = httpRequest(
        {
          hostname: options.hostname ?? "localhost",
          port: options.port,
          path: options.path,
          method: options.method ?? "POST",
          headers: {
            "content-type": "application/json",
            "content-length": Buffer.byteLength(body),
            ...headers,
          },
        },
        (resp) => {
          let data = "";
          resp.on("data", (chunk) => (data += chunk));
          resp.on("end", () => {
            try {
              resolve({ status: resp.statusCode ?? 502, body: data ? JSON.parse(data) : {} });
            } catch (err) {
              reject(err);
            }
          });
        }
      );
      req.on("error", reject);
      req.write(body);
      req.end();
    });
}

export function createProtectedUpstreamHttpServer<T = unknown>(options: ProtectedUpstreamOptions<T> & {
  path?: string;
}): Server {
  const path = options.path ?? "/execute";
  return createServer(async (req, res) => {
    if (req.method === "GET" && req.url === "/healthz") {
      return sendJson(res, 200, { ok: true, route: "upstream", status: "healthy" });
    }
    if (req.method !== "POST" || req.url !== path) {
      return sendJson(res, 404, { ok: false, error: "not found" });
    }

    try {
      const body = await readJson(req);
      const result = await protectUpstreamExecution(body, req.headers, options);
      return sendJson(res, result.status, result.body);
    } catch (err) {
      return sendJson(res, 500, {
        ok: false,
        executed: false,
        error: err instanceof SyntaxError ? "invalid JSON" : "upstream error",
      });
    }
  });
}
