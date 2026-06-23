// SPDX-License-Identifier: Apache-2.0
import { describe, test } from "node:test";
import assert from "node:assert/strict";
import type { PepConfig } from "../src/config.js";
import { createPepServer, installShutdownHandlers } from "../src/server.js";
import type { ReplayStoreHandle } from "../src/replay.js";

function makeConfig(replayStore: PepConfig["replayStore"]): Pick<PepConfig, "mode" | "replayStore" | "port"> {
  return {
    mode: "enforce",
    replayStore,
    port: 3000,
  };
}

describe("PEP runtime shutdown hardening", () => {
  test("shutdown request invokes server cleanup and exits 0", async () => {
    const logs: unknown[] = [];
    const exits: number[] = [];
    const registered = new Map<string, () => void>();
    let shutdownCalls = 0;

    const { requestShutdown } = installShutdownHandlers({
      config: makeConfig({ type: "memory" }),
      server: {
        shutdown: async () => {
          shutdownCalls += 1;
        },
      },
      logger: (entry) => logs.push(entry),
      exit: (code) => {
        exits.push(code);
      },
      on: (signal, handler) => {
        registered.set(signal, handler);
      },
    });

    assert.ok(registered.has("SIGTERM"));
    assert.ok(registered.has("SIGINT"));

    await requestShutdown("SIGTERM");

    assert.equal(shutdownCalls, 1);
    assert.deepEqual(exits, [0]);
    assert.deepEqual(logs, [
      {
        mode: "enforce",
        replay_store_type: "memory",
        port: 3000,
        signal: "SIGTERM",
        shutdown_status: "requested",
      },
      {
        mode: "enforce",
        replay_store_type: "memory",
        port: 3000,
        signal: "SIGTERM",
        shutdown_status: "completed",
      },
    ]);
  });

  test("multiple shutdown requests are idempotent", async () => {
    const exits: number[] = [];
    let shutdownCalls = 0;
    let resolveShutdown: (() => void) | undefined;

    const { requestShutdown } = installShutdownHandlers({
      config: makeConfig({ type: "memory" }),
      server: {
        shutdown: async () => {
          shutdownCalls += 1;
          await new Promise<void>((resolve) => {
            resolveShutdown = resolve;
          });
        },
      },
      exit: (code) => {
        exits.push(code);
      },
      on: () => {},
      logger: () => {},
    });

    const first = requestShutdown("SIGTERM");
    const second = requestShutdown("SIGINT");
    assert.equal(shutdownCalls, 1, "shutdown must not run concurrently");

    resolveShutdown?.();
    await Promise.all([first, second]);

    assert.equal(shutdownCalls, 1, "shutdown must only run once");
    assert.deepEqual(exits, [0], "successful idempotent shutdown exits once with 0");
  });

  test("shutdown failure exits non-zero", async () => {
    const exits: number[] = [];
    const logs: unknown[] = [];

    const { requestShutdown } = installShutdownHandlers({
      config: makeConfig({ type: "memory" }),
      server: {
        shutdown: async () => {
          throw new Error("boom");
        },
      },
      logger: (entry) => logs.push(entry),
      exit: (code) => {
        exits.push(code);
      },
      on: () => {},
    });

    await requestShutdown("SIGINT");

    assert.deepEqual(exits, [1]);
    assert.deepEqual(logs, [
      {
        mode: "enforce",
        replay_store_type: "memory",
        port: 3000,
        signal: "SIGINT",
        shutdown_status: "requested",
      },
      {
        mode: "enforce",
        replay_store_type: "memory",
        port: 3000,
        signal: "SIGINT",
        shutdown_status: "failed",
      },
    ]);
  });

  test("shutdown logs do not leak secrets", async () => {
    const logs: string[] = [];

    const { requestShutdown } = installShutdownHandlers({
      config: makeConfig({
        type: "redis",
        redisUrl: "redis://user:secret-password@redis.internal:6379/0",
        keyPrefix: "oxdeai:test:replay",
        ttlSkewSeconds: 60,
      }),
      server: { shutdown: async () => {} },
      logger: (entry) => logs.push(JSON.stringify(entry)),
      exit: () => {},
      on: () => {},
    });

    await requestShutdown("SIGTERM");

    const joined = logs.join("\n");
    assert.ok(joined.includes("\"replay_store_type\":\"redis\""));
    assert.ok(!joined.includes("redis.internal"));
    assert.ok(!joined.includes("secret-password"));
    assert.ok(!joined.includes("FRAPPE_API_SECRET"));
    assert.ok(!joined.includes("SIGNING_PRIVATE_KEY_PEM"));
    assert.ok(!joined.includes("/tmp/.env.pep.live"));
    assert.ok(!joined.includes("/tmp/pep-signing-key.pem"));
  });

  test("server shutdown disconnects owned Redis client through existing shutdown path", async () => {
    let disconnectCalls = 0;

    const server = createPepServer({
      config: {
        mode: "enforce",
        expectedAudience: "PEP-frappe.lgf.oxdeai.dev",
        frappeBaseUrl: "https://frappe.example.invalid",
        frappeApiKey: "test-key",
        frappeApiSecret: "test-secret",
        replayStore: {
          type: "redis",
          redisUrl: "redis://127.0.0.1:6379",
          keyPrefix: "oxdeai:test:replay",
          ttlSkewSeconds: 60,
        },
        port: 0,
        signingPrivateKey: {} as PepConfig["signingPrivateKey"],
        signingPublicKeyPem: "test-public-key",
        signingKid: "test-key-1",
        issuer: "oxdeai.lgf-frappe-pep",
        authorizationTtlSeconds: 60,
      },
      replayStoreHandleFactory: (): ReplayStoreHandle => ({
        store: {
          consumeAuthId: async () => true,
        },
        disconnect: async () => {
          disconnectCalls += 1;
        },
      }),
      frappeAdapter: {
        createTicket: async () => ({ ticket_id: "T1", name: "T1" }),
      },
    });

    await server.shutdown();
    await server.shutdown();

    assert.equal(disconnectCalls, 1, "owned Redis disconnect must run exactly once");
  });
});
