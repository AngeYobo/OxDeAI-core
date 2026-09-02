import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { get, request } from "node:http";
import { setTimeout as delay } from "node:timers/promises";
import { hashAction, makeAuthorization } from "../non-bypassable-demo/auth-fixture.mjs";
import { checkStateBinding } from "./state-boundary.mjs";

const GATEWAY_PORT = 18887;
const UPSTREAM_PORT = 18888;
const TOKEN = "test-internal-token";

const action = {
  type: "EXECUTE",
  tool: "payments.charge",
  params: { amount: "500", currency: "USD", user_id: "user_123" },
};

function spawnService(name, script, env) {
  const child = spawn("node", [script], {
    cwd: new URL("../non-bypassable-demo/", import.meta.url),
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (chunk) => process.stdout.write(`[${name}] ${chunk}`));
  child.stderr.on("data", (chunk) => process.stderr.write(`[${name}] ${chunk}`));
  return child;
}

function stop(child) {
  if (!child.killed) child.kill("SIGTERM");
}

async function waitForHealth(port) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    const ok = await new Promise((resolve) => {
      const req = get(`http://localhost:${port}/healthz`, (res) => {
        res.resume();
        resolve(res.statusCode === 200);
      });
      req.on("error", () => resolve(false));
      req.setTimeout(250, () => {
        req.destroy();
        resolve(false);
      });
    });
    if (ok) return;
    await delay(100);
  }
  throw new Error(`service on port ${port} did not become healthy`);
}

function postJson(url, body) {
  return new Promise((resolve) => {
    const payload = JSON.stringify(body);
    const u = new URL(url);
    const req = request(
      {
        hostname: u.hostname,
        port: u.port,
        path: u.pathname,
        method: "POST",
        headers: { "content-type": "application/json", "content-length": Buffer.byteLength(payload) },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          let body_ = null;
          try {
            body_ = data ? JSON.parse(data) : null;
          } catch {
            body_ = { raw: data };
          }
          resolve({ status: res.statusCode, body: body_ });
        });
      }
    );
    req.on("error", (err) => resolve({ status: 0, body: { error: err.message } }));
    req.write(payload);
    req.end();
  });
}

async function main() {
  const upstream = spawnService("upstream", "protected-upstream.mjs", {
    PORT: String(UPSTREAM_PORT),
    UPSTREAM_EXECUTOR_TOKEN: TOKEN,
  });
  const gateway = spawnService("gateway", "pep-gateway.mjs", {
    PORT: String(GATEWAY_PORT),
    UPSTREAM_PORT: String(UPSTREAM_PORT),
    UPSTREAM_EXECUTOR_TOKEN: TOKEN,
  });

  try {
    await waitForHealth(UPSTREAM_PORT);
    await waitForHealth(GATEWAY_PORT);

    const intentHash = hashAction(action);

    // 1. Valid authorization reaches the protected execution path.
    const allowAuth = makeAuthorization({ action, authId: "case-allow", intentHash });
    const allow = await postJson(`http://localhost:${GATEWAY_PORT}/execute`, { action, authorization: allowAuth });
    assert.equal(allow.status, 200);
    assert.equal(allow.body?.decision, "ALLOW");
    assert.equal(allow.body?.executed, true);

    // 2. Intent/action mutation: binding no longer matches.
    const mutatedAction = { ...action, params: { ...action.params, amount: "999999" } };
    const mutated = await postJson(`http://localhost:${GATEWAY_PORT}/execute`, { action: mutatedAction, authorization: allowAuth });
    assert.equal(mutated.status, 403);
    assert.equal(mutated.body?.reason, "INTENT_HASH_MISMATCH");
    assert.notEqual(mutated.body?.executed, true);

    // 3. Signature tamper: state_hash is part of the signed payload, so
    // tampering it invalidates the signature. This is not the state-binding
    // check (see case 3b) - it proves the artifact itself is tamper-evident.
    const tamperAuth = makeAuthorization({ action, authId: "case-tamper", intentHash });
    tamperAuth.state_hash = "0".repeat(64);
    const tampered = await postJson(`http://localhost:${GATEWAY_PORT}/execute`, { action, authorization: tamperAuth });
    assert.equal(tampered.status, 403);
    assert.equal(tampered.body?.reason, "AUTH_SIGNATURE_INVALID");
    assert.notEqual(tampered.body?.executed, true);

    // 3b. State mutation: the authorization is untouched and signature
    // valid. OxDeAIGuard's own state_hash binding check (guard.ts step 6c,
    // boundaryFailure "STATE_HASH_MISMATCH") fires when the live state the
    // boundary hashes no longer matches what the authorization committed
    // to. The PEP gateway used above has no live-state concept, so this
    // runs in-process against OxDeAIGuard directly (state-boundary.mjs).
    const stateCheck = await checkStateBinding();
    assert.equal(stateCheck.boundaryFailure, "STATE_HASH_MISMATCH");
    assert.equal(stateCheck.executed, false);

    // 4. Replay: the ALLOW auth_id was already consumed in case 1.
    const replay = await postJson(`http://localhost:${GATEWAY_PORT}/execute`, { action, authorization: allowAuth });
    assert.equal(replay.status, 403);
    assert.equal(replay.body?.reason, "AUTH_REPLAY");
    assert.notEqual(replay.body?.executed, true);

    // 5. Direct bypass: no internal executor token.
    const bypass = await postJson(`http://localhost:${UPSTREAM_PORT}/charge`, action.params);
    assert.equal(bypass.status, 403);
    assert.notEqual(bypass.body?.executed, true);

    console.log("non-bypassable-openclaw tests: OK");
  } finally {
    stop(gateway);
    stop(upstream);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
