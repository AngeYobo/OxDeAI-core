// SPDX-License-Identifier: Apache-2.0
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { sha256HexFromJson, signAuthorizationEd25519 } from "@oxdeai/core";
import type { AuthorizationV1 } from "@oxdeai/core";
import { createInMemoryReplayStore } from "@oxdeai/guard";
import type { PepConfig } from "../src/config.js";
import { createPepServer } from "../src/server.js";
import type { ActionEnvelope } from "../src/types.js";
import type { PlatformAdapter, PlatformExecutionContext } from "../src/adapters/platform.js";
import { POLICY_ID } from "../src/policy.js";

function makeEnvelope(): ActionEnvelope {
  return {
    source_bench: "openwebui-dev",
    target_bench: "frappe",
    agent_or_tool_context: "erp-assistant",
    user_identity: "adapter-boundary@oxdeai.dev",
    session_id: "adapter-boundary-session",
    action: {
      type: "EXECUTE",
      tool: "frappe.helpdesk.create_ticket",
      params: {
        subject: "Adapter boundary ticket",
        description: "Adapter boundary test",
        priority: "Low",
      },
    },
  };
}

function issueAuthorization(envelope: ActionEnvelope, privateKeyPem: string): AuthorizationV1 {
  const now = Math.floor(Date.now() / 1000);
  return signAuthorizationEd25519(
    {
      auth_id: randomUUID(),
      issuer: "oxdeai.lgf-frappe-pep",
      audience: "PEP-frappe.lgf.oxdeai.dev",
      intent_hash: sha256HexFromJson(envelope.action),
      state_hash: sha256HexFromJson({}),
      policy_id: POLICY_ID,
      decision: "ALLOW",
      issued_at: now,
      expiry: now + 60,
      kid: "test-key-1",
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
  return { status: res.status, body: await res.json() as Record<string, unknown> };
}

describe("Platform adapter boundary", () => {
  let baseUrl: string;
  let privateKeyPem: string;
  let adapterCalls: number;
  let lastAction: string | null;
  let lastPayload: unknown;
  let lastContext: PlatformExecutionContext | null;
  let close: () => Promise<void>;

  before(async () => {
    const keyPair = generateKeyPairSync("ed25519");
    privateKeyPem = keyPair.privateKey.export({ type: "pkcs8", format: "pem" }) as string;
    const publicKeyPem = keyPair.publicKey.export({ type: "spki", format: "pem" }) as string;

    adapterCalls = 0;
    lastAction = null;
    lastPayload = null;
    lastContext = null;

    const adapter: PlatformAdapter = {
      name: "frappe",
      async execute(action, payload, context) {
        adapterCalls += 1;
        lastAction = action;
        lastPayload = payload;
        lastContext = context;
        return { resource_id: "HD-TICKET-BOUNDARY-1" };
      },
    };

    const config: PepConfig = {
      mode: "enforce",
      expectedAudience: "PEP-frappe.lgf.oxdeai.dev",
      frappeBaseUrl: "https://frappe.example.invalid",
      frappeApiKey: "test-key",
      frappeApiSecret: "test-secret",
      replayStore: { type: "memory" },
      port: 0,
      signingPrivateKey: keyPair.privateKey,
      signingPublicKeyPem: publicKeyPem,
      signingKid: "test-key-1",
      issuer: "oxdeai.lgf-frappe-pep",
      trustedAuthorizationAuthorities: [{ issuer: "oxdeai.lgf-frappe-pep", policyId: POLICY_ID }],
      authorizationTtlSeconds: 60,
    };

    const server = createPepServer({
      config,
      replayStore: createInMemoryReplayStore(),
      platformAdapter: adapter,
    });

    await new Promise<void>((resolve, reject) => {
      server.on("error", reject);
      server.listen(0, "127.0.0.1", () => resolve());
    });

    const addr = server.address();
    if (!addr || typeof addr === "string") throw new Error("Unexpected address");
    baseUrl = `http://127.0.0.1:${addr.port}`;
    close = () => server.shutdown();
  });

  after(async () => {
    await close();
  });

  test("PEP uses injected adapter and returns its execution result", async () => {
    adapterCalls = 0;
    lastAction = null;
    lastPayload = null;
    lastContext = null;

    const envelope = makeEnvelope();
    const authorization = issueAuthorization(envelope, privateKeyPem);
    const result = await postJson(`${baseUrl}/execute`, { envelope, authorization });

    assert.equal(result.status, 200);
    assert.equal(result.body["decision"], "ALLOW");
    assert.equal(result.body["frappe_ticket_id"], "HD-TICKET-BOUNDARY-1");
    assert.equal(adapterCalls, 1);
    assert.equal(lastAction, "frappe.helpdesk.create_ticket");
    assert.deepEqual(lastPayload, envelope.action.params);
    const ctx = lastContext as PlatformExecutionContext | null;
    assert.ok(ctx, "adapter context must be provided");
    assert.equal(ctx.authId, authorization.auth_id);
    assert.equal(ctx.mode, "enforce");
  });
});
