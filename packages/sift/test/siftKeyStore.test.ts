// SPDX-License-Identifier: Apache-2.0
/**
 * Unit tests for SiftHttpKeyStore — JWKS parsing, KRL parsing, refresh
 * lifecycle, and fail-closed behavior.
 *
 * All tests use an injected fetch mock.  No network calls are made.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  SiftHttpKeyStore,
  KeyStoreError,
  createStagingKeyStore,
} from "../src/siftKeyStore.js";

// ─── Fixtures ─────────────────────────────────────────────────────────────────
//
// RFC 8037 Appendix A test vector — deterministic across runs.
//   d  (private seed, base64url-no-padding)
//   x  (public key,   base64url-no-padding, decodes to 32 bytes)

const RFC8037_X   = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const RFC8037_KID = "key-rfc8037";

const VALID_JWKS = {
  keys: [
    {
      kty: "OKP",
      crv: "Ed25519",
      alg: "EdDSA",
      use: "sig",
      kid: RFC8037_KID,
      x: RFC8037_X,
    },
  ],
};

const EMPTY_KRL = {
  version: 1,
  issuer: "sift-staging",
  algorithm: "ed25519",
  generated_at: "2026-01-01T00:00:00Z",
  revoked_kids: [],
};

const KRL_WITH_REVOKED = {
  ...EMPTY_KRL,
  revoked_kids: [RFC8037_KID],
};

// ─── Mock fetch factory ───────────────────────────────────────────────────────

type MockResponse = { status: number; body: unknown } | { status: number; error: string };

function makeFetch(
  routes: Record<string, MockResponse>
): typeof globalThis.fetch {
  return async (input: string | URL | Request) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const route = routes[url];
    if (!route) {
      return new Response(null, { status: 404 }) as Response;
    }
    if ("error" in route) {
      throw new Error(route.error);
    }
    return new Response(JSON.stringify(route.body), {
      status: route.status,
      headers: { "content-type": "application/json" },
    }) as Response;
  };
}

const JWKS_URL = "https://sift-staging.example.test/sift-jwks.json";
const KRL_URL  = "https://sift-staging.example.test/sift-krl.json";

function makeStore(routes: Record<string, MockResponse>): SiftHttpKeyStore {
  return new SiftHttpKeyStore({
    jwksUrl: JWKS_URL,
    krlUrl: KRL_URL,
    fetch: makeFetch(routes),
  });
}

function happyRoutes(): Record<string, MockResponse> {
  return {
    [JWKS_URL]: { status: 200, body: VALID_JWKS },
    [KRL_URL]:  { status: 200, body: EMPTY_KRL },
  };
}

// ─── Tests: initial state (before refresh) ───────────────────────────────────

test("siftKeyStore: getPublicKeyByKid returns null before refresh", async () => {
  const store = makeStore(happyRoutes());
  const key = await store.getPublicKeyByKid(RFC8037_KID);
  assert.strictEqual(key, null);
});

test("siftKeyStore: isKidRevoked returns false before refresh", async () => {
  const store = makeStore(happyRoutes());
  const revoked = await store.isKidRevoked(RFC8037_KID);
  assert.strictEqual(revoked, false);
});

// ─── Tests: successful refresh ────────────────────────────────────────────────

test("siftKeyStore: refresh populates key cache from JWKS", async () => {
  const store = makeStore(happyRoutes());
  await store.refresh();
  const key = await store.getPublicKeyByKid(RFC8037_KID);
  assert.ok(key !== null, "key should be found after refresh");
  assert.strictEqual(key.length, 32, "raw key must be 32 bytes");
});

test("siftKeyStore: refreshed key matches RFC 8037 x-field decode", async () => {
  const store = makeStore(happyRoutes());
  await store.refresh();
  const key = await store.getPublicKeyByKid(RFC8037_KID);
  assert.ok(key !== null);

  // Decode x manually and compare.
  const normalized = RFC8037_X.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  const expected = Buffer.from(normalized, "base64url");
  assert.deepStrictEqual(Buffer.from(key), expected);
});

test("siftKeyStore: refresh loads empty KRL — no kids revoked", async () => {
  const store = makeStore(happyRoutes());
  await store.refresh();
  const revoked = await store.isKidRevoked(RFC8037_KID);
  assert.strictEqual(revoked, false);
});

test("siftKeyStore: refresh loads KRL with revoked kids", async () => {
  const store = makeStore({
    [JWKS_URL]: { status: 200, body: VALID_JWKS },
    [KRL_URL]:  { status: 200, body: KRL_WITH_REVOKED },
  });
  await store.refresh();
  const revoked = await store.isKidRevoked(RFC8037_KID);
  assert.strictEqual(revoked, true);
});

test("siftKeyStore: unknown kid is not in cache after refresh", async () => {
  const store = makeStore(happyRoutes());
  await store.refresh();
  const key = await store.getPublicKeyByKid("nonexistent-kid");
  assert.strictEqual(key, null);
});

// ─── Tests: JWKS parsing edge cases ──────────────────────────────────────────

test("siftKeyStore: JWKS entries with wrong kty are ignored", async () => {
  const store = makeStore({
    [JWKS_URL]: {
      status: 200,
      body: {
        keys: [
          { kty: "RSA", crv: "Ed25519", kid: "rsa-key", x: RFC8037_X },
          { kty: "OKP", crv: "Ed25519", kid: RFC8037_KID, x: RFC8037_X },
        ],
      },
    },
    [KRL_URL]: { status: 200, body: EMPTY_KRL },
  });
  await store.refresh();
  assert.strictEqual(await store.getPublicKeyByKid("rsa-key"), null);
  assert.ok((await store.getPublicKeyByKid(RFC8037_KID)) !== null);
});

test("siftKeyStore: JWKS entries with wrong crv are ignored", async () => {
  const store = makeStore({
    [JWKS_URL]: {
      status: 200,
      body: {
        keys: [
          { kty: "OKP", crv: "P-256", kid: "p256-key", x: RFC8037_X },
        ],
      },
    },
    [KRL_URL]: { status: 200, body: EMPTY_KRL },
  });
  await store.refresh();
  assert.strictEqual(await store.getPublicKeyByKid("p256-key"), null);
});

test("siftKeyStore: JWKS entries with empty kid are ignored", async () => {
  const store = makeStore({
    [JWKS_URL]: {
      status: 200,
      body: { keys: [{ kty: "OKP", crv: "Ed25519", kid: "", x: RFC8037_X }] },
    },
    [KRL_URL]: { status: 200, body: EMPTY_KRL },
  });
  await store.refresh();
  assert.strictEqual(await store.getPublicKeyByKid(""), null);
});

test("siftKeyStore: JWKS entries with invalid base64url x are ignored", async () => {
  const store = makeStore({
    [JWKS_URL]: {
      status: 200,
      body: { keys: [{ kty: "OKP", crv: "Ed25519", kid: "bad-x", x: "!!!not-base64url!!!" }] },
    },
    [KRL_URL]: { status: 200, body: EMPTY_KRL },
  });
  // Should not throw — invalid entries are skipped.
  await store.refresh();
  assert.strictEqual(await store.getPublicKeyByKid("bad-x"), null);
});

test("siftKeyStore: JWKS entries with x decoding to wrong byte length are ignored", async () => {
  // "AAEC" decodes to 3 bytes — not 32.
  const store = makeStore({
    [JWKS_URL]: {
      status: 200,
      body: { keys: [{ kty: "OKP", crv: "Ed25519", kid: "short-key", x: "AAEC" }] },
    },
    [KRL_URL]: { status: 200, body: EMPTY_KRL },
  });
  await store.refresh();
  assert.strictEqual(await store.getPublicKeyByKid("short-key"), null);
});

test("siftKeyStore: JWKS missing keys array throws JWKS_FETCH_FAILED", async () => {
  const store = makeStore({
    [JWKS_URL]: { status: 200, body: { notKeys: [] } },
    [KRL_URL]:  { status: 200, body: EMPTY_KRL },
  });
  await assert.rejects(
    () => store.refresh(),
    (err) => {
      assert.ok(err instanceof KeyStoreError);
      assert.strictEqual(err.code, "JWKS_FETCH_FAILED");
      return true;
    }
  );
});

test("siftKeyStore: JWKS null body throws JWKS_FETCH_FAILED", async () => {
  const store = makeStore({
    [JWKS_URL]: { status: 200, body: null },
    [KRL_URL]:  { status: 200, body: EMPTY_KRL },
  });
  await assert.rejects(
    () => store.refresh(),
    (err) => {
      assert.ok(err instanceof KeyStoreError);
      assert.strictEqual(err.code, "JWKS_FETCH_FAILED");
      return true;
    }
  );
});

// ─── Tests: KRL parsing edge cases ───────────────────────────────────────────

test("siftKeyStore: KRL missing revoked_kids throws KRL_FETCH_FAILED", async () => {
  const store = makeStore({
    [JWKS_URL]: { status: 200, body: VALID_JWKS },
    [KRL_URL]:  { status: 200, body: { version: 1 } },
  });
  await assert.rejects(
    () => store.refresh(),
    (err) => {
      assert.ok(err instanceof KeyStoreError);
      assert.strictEqual(err.code, "KRL_FETCH_FAILED");
      return true;
    }
  );
});

test("siftKeyStore: KRL null body throws KRL_FETCH_FAILED", async () => {
  const store = makeStore({
    [JWKS_URL]: { status: 200, body: VALID_JWKS },
    [KRL_URL]:  { status: 200, body: null },
  });
  await assert.rejects(
    () => store.refresh(),
    (err) => {
      assert.ok(err instanceof KeyStoreError);
      assert.strictEqual(err.code, "KRL_FETCH_FAILED");
      return true;
    }
  );
});

test("siftKeyStore: KRL with non-string entries in revoked_kids ignores them", async () => {
  const store = makeStore({
    [JWKS_URL]: { status: 200, body: VALID_JWKS },
    [KRL_URL]:  { status: 200, body: { ...EMPTY_KRL, revoked_kids: [42, null, "real-kid", {}] } },
  });
  await store.refresh();
  // Only string entries enter the revoked set.
  assert.strictEqual(await store.isKidRevoked("real-kid"), true);
  assert.strictEqual(await store.isKidRevoked("42"), false);
});

// ─── Tests: HTTP failures ─────────────────────────────────────────────────────

test("siftKeyStore: JWKS HTTP 500 throws JWKS_FETCH_FAILED", async () => {
  const store = makeStore({
    [JWKS_URL]: { status: 500, body: null },
    [KRL_URL]:  { status: 200, body: EMPTY_KRL },
  });
  await assert.rejects(
    () => store.refresh(),
    (err) => {
      assert.ok(err instanceof KeyStoreError);
      assert.strictEqual(err.code, "JWKS_FETCH_FAILED");
      return true;
    }
  );
});

test("siftKeyStore: KRL HTTP 503 throws KRL_FETCH_FAILED", async () => {
  const store = makeStore({
    [JWKS_URL]: { status: 200, body: VALID_JWKS },
    [KRL_URL]:  { status: 503, body: null },
  });
  await assert.rejects(
    () => store.refresh(),
    (err) => {
      assert.ok(err instanceof KeyStoreError);
      assert.strictEqual(err.code, "KRL_FETCH_FAILED");
      return true;
    }
  );
});

test("siftKeyStore: network error throws KEYSTORE_REFRESH_FAILED", async () => {
  const store = makeStore({
    [JWKS_URL]: { status: 0, error: "connection refused" },
    [KRL_URL]:  { status: 0, error: "connection refused" },
  });
  await assert.rejects(
    () => store.refresh(),
    (err) => {
      assert.ok(err instanceof KeyStoreError);
      assert.strictEqual(err.code, "KEYSTORE_REFRESH_FAILED");
      return true;
    }
  );
});

// ─── Tests: atomicity — caches only swapped on full success ──────────────────

test("siftKeyStore: failed refresh does not corrupt existing cache", async () => {
  // Stateful fetch: first JWKS call returns valid data; second returns a parse
  // failure.  Both calls are against the SAME store instance, so this test
  // actually exercises the atomic cache-swap property.
  const jwksCallCount = { n: 0 };

  const statefulFetch: typeof globalThis.fetch = async (input) => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.toString()
          : (input as Request).url;

    if (url === JWKS_URL) {
      jwksCallCount.n += 1;
      const body =
        jwksCallCount.n === 1
          ? VALID_JWKS          // first refresh: valid
          : { notKeys: [] };    // second refresh: parse failure → JWKS_FETCH_FAILED
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "content-type": "application/json" },
      }) as Response;
    }

    if (url === KRL_URL) {
      return new Response(JSON.stringify(EMPTY_KRL), {
        status: 200,
        headers: { "content-type": "application/json" },
      }) as Response;
    }

    return new Response(null, { status: 404 }) as Response;
  };

  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL,
    krlUrl: KRL_URL,
    fetch: statefulFetch,
  });

  // First refresh — populates the cache.
  await store.refresh();
  const keyBefore = await store.getPublicKeyByKid(RFC8037_KID);
  assert.ok(keyBefore !== null, "key should be present after first refresh");

  // Second refresh — JWKS parse failure; cache MUST remain intact.
  await assert.rejects(
    () => store.refresh(),
    (err) => {
      assert.ok(err instanceof KeyStoreError);
      assert.strictEqual(err.code, "JWKS_FETCH_FAILED");
      return true;
    }
  );

  const keyAfter = await store.getPublicKeyByKid(RFC8037_KID);
  assert.ok(keyAfter !== null, "key must survive a failed second refresh on the same instance");
});

// ─── Tests: createStagingKeyStore production guard ────────────────────────────

test("createStagingKeyStore: throws when NODE_ENV is 'production' without override", () => {
  const orig = process.env["NODE_ENV"];
  try {
    process.env["NODE_ENV"] = "production";
    assert.throws(
      () => createStagingKeyStore(),
      (err: unknown) => {
        assert.ok(err instanceof Error, "must throw an Error");
        assert.ok(
          err.message.includes("MUST NOT be called in production"),
          `unexpected message: ${err.message}`
        );
        return true;
      }
    );
  } finally {
    if (orig === undefined) delete process.env["NODE_ENV"];
    else process.env["NODE_ENV"] = orig;
  }
});

test("createStagingKeyStore: succeeds when NODE_ENV is 'production' and _allowInProduction is true", () => {
  const orig = process.env["NODE_ENV"];
  try {
    process.env["NODE_ENV"] = "production";
    const store = createStagingKeyStore({ _allowInProduction: true });
    assert.ok(store instanceof SiftHttpKeyStore, "must return a SiftHttpKeyStore");
  } finally {
    if (orig === undefined) delete process.env["NODE_ENV"];
    else process.env["NODE_ENV"] = orig;
  }
});

test("createStagingKeyStore: succeeds when NODE_ENV is 'test'", () => {
  const orig = process.env["NODE_ENV"];
  try {
    process.env["NODE_ENV"] = "test";
    const store = createStagingKeyStore();
    assert.ok(store instanceof SiftHttpKeyStore, "must return a SiftHttpKeyStore");
  } finally {
    if (orig === undefined) delete process.env["NODE_ENV"];
    else process.env["NODE_ENV"] = orig;
  }
});

test("createStagingKeyStore: succeeds when NODE_ENV is undefined", () => {
  const orig = process.env["NODE_ENV"];
  try {
    delete process.env["NODE_ENV"];
    const store = createStagingKeyStore();
    assert.ok(store instanceof SiftHttpKeyStore, "must return a SiftHttpKeyStore");
  } finally {
    if (orig === undefined) delete process.env["NODE_ENV"];
    else process.env["NODE_ENV"] = orig;
  }
});
