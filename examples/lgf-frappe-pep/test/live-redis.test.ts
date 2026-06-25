// SPDX-License-Identifier: Apache-2.0
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpServer } from "node:http";
import type { Server as HttpServer } from "node:http";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { Redis } from "ioredis";
import { sha256HexFromJson, signAuthorizationEd25519 } from "@oxdeai/core";
import type { AuthorizationV1 } from "@oxdeai/core";
import type { PepConfig } from "../src/config.js";
import { createPepServer } from "../src/server.js";
import type { ActionEnvelope } from "../src/types.js";
import type { PlatformAdapter } from "../src/adapters/platform.js";
import { POLICY_ID } from "../src/policy.js";

const LIVE_REDIS_URL = process.env["REDIS_URL"] ?? "redis://127.0.0.1:6379";
const LIVE_REDIS_ENABLED = process.env["OXDEAI_LIVE_REDIS_TEST"] === "1";
const LIVE_REDIS_TIMEOUT_MS = 8_000;
const AUTH_TTL_SECONDS = 60;
const REPLAY_TTL_SKEW_SECONDS = 45;
const TTL_BUFFER_SECONDS = 5;

type LiveHarness = {
  baseUrl: string;
  config: PepConfig;
  privateKeyPem: string;
  frappeCallCount: () => number;
  resetFrappe: () => void;
  close: () => Promise<void>;
};

function makeEnvelope(subject = "Live Redis replay test"): ActionEnvelope {
  return {
    source_bench: "openwebui-dev",
    target_bench: "frappe",
    agent_or_tool_context: "erp-assistant",
    user_identity: "redis-live-test@oxdeai.dev",
    session_id: "redis-live-test-session",
    action: {
      type: "EXECUTE",
      tool: "frappe.helpdesk.create_ticket",
      params: {
        subject,
        description: "Live Redis replay integration test",
        priority: "Low",
      },
    },
  };
}

function issueAuthorization(
  envelope: ActionEnvelope,
  privateKeyPem: string,
  config: PepConfig,
  authId = randomUUID(),
): AuthorizationV1 {
  const now = Math.floor(Date.now() / 1000);
  return signAuthorizationEd25519(
    {
      auth_id: authId,
      issuer: config.issuer,
      audience: config.expectedAudience,
      intent_hash: sha256HexFromJson(envelope.action),
      state_hash: sha256HexFromJson({}),
      policy_id: POLICY_ID,
      decision: "ALLOW",
      issued_at: now,
      expiry: now + config.authorizationTtlSeconds,
      kid: config.signingKid,
      nonce: randomUUID(),
    },
    privateKeyPem,
  );
}

async function postJson(url: string, body: unknown): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return {
    status: res.status,
    body: await res.json() as Record<string, unknown>,
  };
}

async function waitForRedis(url: string): Promise<void> {
  const redis = new Redis(url, {
    lazyConnect: true,
    maxRetriesPerRequest: 1,
    enableOfflineQueue: false,
    connectTimeout: LIVE_REDIS_TIMEOUT_MS,
  });

  try {
    await redis.connect();
    const pong = await redis.ping();
    assert.equal(pong, "PONG", "Redis must respond to PING");
  } finally {
    redis.disconnect();
  }
}

async function deleteKeysByPrefix(redis: Redis, prefix: string): Promise<void> {
  const keys = await redis.keys(`${prefix}:*`);
  if (keys.length > 0) {
    await redis.del(...keys);
  }
}

async function startHarness(replayKeyPrefix: string, redisUrl = LIVE_REDIS_URL): Promise<LiveHarness> {
  const keyPair = generateKeyPairSync("ed25519");
  const privateKeyPem = keyPair.privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  const publicKeyPem = keyPair.publicKey.export({ type: "spki", format: "pem" }) as string;

  let callCount = 0;
  const mockFrappe: PlatformAdapter = {
    name: "frappe",
    async execute() {
      callCount += 1;
      return { resource_id: `HD-TICKET-${callCount}` };
    },
  };

  const config: PepConfig = {
    mode: "enforce",
    expectedAudience: "PEP-frappe.lgf.oxdeai.dev",
    frappeBaseUrl: "https://frappe.example.invalid",
    frappeApiKey: "test-key",
    frappeApiSecret: "test-secret",
    replayStore: {
      type: "redis",
      redisUrl,
      keyPrefix: replayKeyPrefix,
      ttlSkewSeconds: REPLAY_TTL_SKEW_SECONDS,
    },
    port: 0,
    signingPrivateKey: keyPair.privateKey,
    signingPublicKeyPem: publicKeyPem,
    signingKid: "redis-live-test-key-1",
    issuer: "oxdeai.lgf-frappe-pep",
    authorizationTtlSeconds: AUTH_TTL_SECONDS,
  };

  const server = createPepServer({ config, platformAdapter: mockFrappe });
  await new Promise<void>((resolve, reject) => {
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });

  const addr = server.address();
  if (!addr || typeof addr === "string") {
    throw new Error("Unexpected server address");
  }

  return {
    baseUrl: `http://127.0.0.1:${addr.port}`,
    config,
    privateKeyPem,
    frappeCallCount: () => callCount,
    resetFrappe: () => {
      callCount = 0;
    },
    close: () => server.shutdown(),
  };
}

describe("LGF Frappe PEP live Redis replay integration", { skip: !LIVE_REDIS_ENABLED }, () => {
  const replayKeyPrefix = `oxdeai:test:replay:${Date.now()}:${randomUUID()}`;
  const redis = new Redis(LIVE_REDIS_URL, {
    lazyConnect: true,
    maxRetriesPerRequest: 1,
    enableOfflineQueue: false,
    connectTimeout: LIVE_REDIS_TIMEOUT_MS,
  });

  let harness: LiveHarness;

  before(async () => {
    await waitForRedis(LIVE_REDIS_URL);
    await redis.connect();
    await deleteKeysByPrefix(redis, replayKeyPrefix);
    harness = await startHarness(replayKeyPrefix);
  });

  after(async () => {
    if (harness) {
      await harness.close();
    }
    await deleteKeysByPrefix(redis, replayKeyPrefix);
    redis.disconnect();
  });

  test("first execution succeeds, replay key is created with expected prefix and positive TTL", async () => {
    harness.resetFrappe();
    const envelope = makeEnvelope("Live Redis first execution");
    const authorization = issueAuthorization(envelope, harness.privateKeyPem, harness.config);

    const result = await postJson(`${harness.baseUrl}/execute`, { envelope, authorization });
    assert.equal(result.status, 200);
    assert.equal(result.body["decision"], "ALLOW");
    assert.equal(harness.frappeCallCount(), 1, "First execution must call target adapter exactly once");

    const replayKey = `${replayKeyPrefix}:${harness.config.issuer}:${harness.config.expectedAudience}:${authorization.auth_id}`;
    const exists = await redis.exists(replayKey);
    assert.equal(exists, 1, "Replay key must exist after first execution");

    const ttl = await redis.ttl(replayKey);
    assert.ok(ttl > AUTH_TTL_SECONDS, `TTL must exceed authorization TTL (${ttl})`);
    assert.ok(
      ttl <= AUTH_TTL_SECONDS + REPLAY_TTL_SKEW_SECONDS + TTL_BUFFER_SECONDS,
      `TTL must stay within auth TTL + skew buffer (${ttl})`
    );
  });

  test("replay is denied and no second side effect occurs", async () => {
    harness.resetFrappe();
    const envelope = makeEnvelope("Live Redis replay denial");
    const authorization = issueAuthorization(envelope, harness.privateKeyPem, harness.config);

    const first = await postJson(`${harness.baseUrl}/execute`, { envelope, authorization });
    assert.equal(first.status, 200);
    assert.equal(first.body["decision"], "ALLOW");
    assert.equal(harness.frappeCallCount(), 1, "First execution must call target adapter exactly once");

    const second = await postJson(`${harness.baseUrl}/execute`, { envelope, authorization });
    assert.equal(second.status, 403);
    assert.equal(second.body["decision"], "DENY");
    assert.equal(second.body["reason"], "AUTH_REPLAY");
    assert.equal(harness.frappeCallCount(), 1, "Replay must not trigger a second side effect");
  });

  test("Redis outage fails closed with REPLAY_STORE_UNAVAILABLE", async () => {
    const outagePrefix = `${replayKeyPrefix}:outage`;
    const outageHarness = await startHarness(outagePrefix, "redis://127.0.0.1:6399");
    try {
      outageHarness.resetFrappe();
      const envelope = makeEnvelope("Live Redis outage");
      const authorization = issueAuthorization(envelope, outageHarness.privateKeyPem, outageHarness.config);

      const result = await postJson(`${outageHarness.baseUrl}/execute`, { envelope, authorization });
      assert.equal(result.status, 403);
      assert.equal(result.body["decision"], "DENY");
      assert.equal(result.body["reason"], "REPLAY_STORE_UNAVAILABLE");
      assert.equal(outageHarness.frappeCallCount(), 0, "Unavailable Redis must block target adapter calls");
    } finally {
      await outageHarness.close();
    }
  });
});
