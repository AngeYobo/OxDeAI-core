// SPDX-License-Identifier: Apache-2.0
/**
 * Issue #116 — v-next migration warnings.
 *
 * Tests the structured deprecation warnings introduced in the v-next gate:
 *   - unsigned_legacy construction fires process.emitWarning with
 *     code DEP_OXDEAI_KRL_UNSIGNED_LEGACY
 *   - signed_preferred unsigned fallback refresh emits a console.warn
 *     exactly once per SiftHttpKeyStore instance
 *   - No unsigned-fallback warning on signed KRL success
 *   - signed_required behavior and fast-fail unchanged
 *   - Default krlMode remains signed_preferred
 *   - unsigned_legacy remains fully functional (behavior unchanged)
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { SiftHttpKeyStore } from "../src/siftKeyStore.js";

// ─── Constants ────────────────────────────────────────────────────────────────

const JWKS_URL = "https://sift-migration-test.example/sift-jwks.json";
const KRL_URL  = "https://sift-migration-test.example/sift-krl.json";

const RFC8037_X   = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const RFC8037_KID = "key-rfc8037";
const VALID_JWKS  = { keys: [{ kty: "OKP", crv: "Ed25519", kid: RFC8037_KID, x: RFC8037_X }] };

const UNSIGNED_KRL   = { version: 1, issuer: "s", revoked_kids: [] as string[] };
const SIGNED_KRL_BODY = {
  version: "SignedKRLV1", issuer: "krl-issuer", krl_version: 1,
  issued_at: 1744000000, not_after: 1744010000,
  revoked_kids: [] as string[],
  signature: { alg: "Ed25519", kid: "krl-key-1", sig: "placeholder" },
};

const TEST_NOW = 1744005000;

// ─── Helpers ──────────────────────────────────────────────────────────────────

type MockResponse = { status: number; body: unknown } | { status: number; error: string };

function makeFetch(routes: Record<string, MockResponse>): typeof globalThis.fetch {
  return async (input: string | URL | Request) => {
    const url = typeof input === "string" ? input : (input as URL).toString();
    const route = routes[url];
    if (!route) return new Response(null, { status: 404 }) as Response;
    if ("error" in route) throw new Error(route.error);
    return new Response(JSON.stringify(route.body), {
      status: route.status,
      headers: { "content-type": "application/json" },
    }) as Response;
  };
}

function happyRoutes(krlBody: unknown): Record<string, MockResponse> {
  return {
    [JWKS_URL]: { status: 200, body: VALID_JWKS },
    [KRL_URL]:  { status: 200, body: krlBody },
  };
}

// ─── MW-1: unsigned_legacy emits process.emitWarning ─────────────────────────

test("MW-1: unsigned_legacy construction emits process.emitWarning with DEP_OXDEAI_KRL_UNSIGNED_LEGACY", async () => {
  const warnings: Array<{ name: string; code: string | undefined }> = [];
  const handler = (w: Error & { code?: string }) => {
    warnings.push({ name: w.name, code: w.code });
  };
  process.on("warning", handler);

  try {
    new SiftHttpKeyStore({
      jwksUrl: JWKS_URL,
      krlUrl: KRL_URL,
      krlMode: "unsigned_legacy",
    });

    // process.emitWarning fires on the next tick — flush it.
    await new Promise<void>(resolve => process.nextTick(resolve));

    const krlWarning = warnings.find(w => w.code === "DEP_OXDEAI_KRL_UNSIGNED_LEGACY");
    assert.ok(
      krlWarning !== undefined,
      `expected DEP_OXDEAI_KRL_UNSIGNED_LEGACY warning; got codes: ${JSON.stringify(warnings.map(w => w.code))}`
    );
    assert.strictEqual(krlWarning!.name, "DeprecationWarning",
      "warning type must be DeprecationWarning");
  } finally {
    process.off("warning", handler);
  }
});

test("MW-1b: unsigned_legacy warning fires for each new instance construction", async () => {
  let callCount = 0;
  const handler = (w: Error & { code?: string }) => {
    if (w.code === "DEP_OXDEAI_KRL_UNSIGNED_LEGACY") callCount++;
  };
  process.on("warning", handler);

  try {
    new SiftHttpKeyStore({ jwksUrl: JWKS_URL, krlUrl: KRL_URL, krlMode: "unsigned_legacy" });
    new SiftHttpKeyStore({ jwksUrl: JWKS_URL, krlUrl: KRL_URL, krlMode: "unsigned_legacy" });

    // process.emitWarning fires on the next tick — flush both.
    await new Promise<void>(resolve => process.nextTick(resolve));

    assert.strictEqual(callCount, 2, "warning must fire for each instance construction");
  } finally {
    process.off("warning", handler);
  }
});

// ─── MW-2: signed_preferred unsigned fallback emits console.warn once per instance

test("MW-2a: signed_preferred unsigned fallback emits console.warn on first occurrence", async () => {
  const warned: string[] = [];
  const origWarn = console.warn;
  console.warn = (...args: unknown[]) => {
    warned.push(args.map(String).join(" "));
  };

  try {
    const store = new SiftHttpKeyStore({
      jwksUrl: JWKS_URL, krlUrl: KRL_URL,
      krlMode: "signed_preferred",
      // No verifyKrl — unsigned KRL triggers fallback path
      fetch: makeFetch(happyRoutes(UNSIGNED_KRL)),
      now: () => TEST_NOW,
    });

    await store.refresh();

    const fallbackWarnings = warned.filter(w => w.includes("unsigned fallback"));
    assert.ok(fallbackWarnings.length >= 1,
      `expected unsigned fallback warning; got: ${JSON.stringify(warned)}`);
    assert.ok(fallbackWarnings[0].includes("signed_required"),
      "warning must mention signed_required migration path");
  } finally {
    console.warn = origWarn;
  }
});

test("MW-2b: signed_preferred unsigned-fallback warning fires only once per instance (not on every refresh)", async () => {
  const warned: string[] = [];
  const origWarn = console.warn;
  console.warn = (...args: unknown[]) => {
    warned.push(args.map(String).join(" "));
  };

  try {
    const store = new SiftHttpKeyStore({
      jwksUrl: JWKS_URL, krlUrl: KRL_URL,
      krlMode: "signed_preferred",
      fetch: makeFetch(happyRoutes(UNSIGNED_KRL)),
      now: () => TEST_NOW,
    });

    // Three refreshes — all use unsigned fallback
    await store.refresh();
    await store.refresh();
    await store.refresh();

    const fallbackWarnings = warned.filter(w => w.includes("unsigned fallback"));
    assert.strictEqual(fallbackWarnings.length, 1,
      `unsigned-fallback warning must fire exactly once per instance; fired ${fallbackWarnings.length} times`);
  } finally {
    console.warn = origWarn;
  }
});

test("MW-2c: two separate SiftHttpKeyStore instances each emit the warning once", async () => {
  const warned: string[] = [];
  const origWarn = console.warn;
  console.warn = (...args: unknown[]) => {
    warned.push(args.map(String).join(" "));
  };

  try {
    const opts = {
      jwksUrl: JWKS_URL, krlUrl: KRL_URL,
      krlMode: "signed_preferred" as const,
      fetch: makeFetch(happyRoutes(UNSIGNED_KRL)),
      now: () => TEST_NOW,
    };

    const store1 = new SiftHttpKeyStore(opts);
    const store2 = new SiftHttpKeyStore(opts);

    await store1.refresh();
    await store2.refresh();

    const fallbackWarnings = warned.filter(w => w.includes("unsigned fallback"));
    assert.strictEqual(fallbackWarnings.length, 2,
      "each instance must emit the warning once (two instances = two warnings)");
  } finally {
    console.warn = origWarn;
  }
});

// ─── MW-3: signed KRL success does not emit unsigned-fallback warning ─────────

test("MW-3: signed_preferred signed KRL success does not emit unsigned-fallback warning", async () => {
  const warned: string[] = [];
  const origWarn = console.warn;
  console.warn = (...args: unknown[]) => {
    warned.push(args.map(String).join(" "));
  };

  try {
    const store = new SiftHttpKeyStore({
      jwksUrl: JWKS_URL, krlUrl: KRL_URL,
      krlMode: "signed_preferred",
      verifyKrl: () => ({
        ok: true,
        violations: [],
        accepted: { issuer: "krl-issuer", krl_version: 1 },
      }),
      fetch: makeFetch(happyRoutes(SIGNED_KRL_BODY)),
      now: () => TEST_NOW,
    });

    await store.refresh();

    const fallbackWarnings = warned.filter(w => w.includes("unsigned fallback"));
    assert.strictEqual(fallbackWarnings.length, 0,
      "signed KRL success must not emit the unsigned-fallback warning");

    // Normal LKG write failure warning may appear, but not unsigned-fallback
    assert.ok(store.getKrlStatus().lastIntegrity === "signed");
  } finally {
    console.warn = origWarn;
  }
});

test("MW-3b: unsigned_legacy mode does not emit the signed_preferred unsigned-fallback warning", async () => {
  const warned: string[] = [];
  const origWarn = console.warn;
  console.warn = (...args: unknown[]) => {
    warned.push(args.map(String).join(" "));
  };

  try {
    const store = new SiftHttpKeyStore({
      jwksUrl: JWKS_URL, krlUrl: KRL_URL,
      krlMode: "unsigned_legacy",
      fetch: makeFetch(happyRoutes(UNSIGNED_KRL)),
      now: () => TEST_NOW,
    });

    await store.refresh();

    const fallbackWarnings = warned.filter(w => w.includes("unsigned fallback"));
    assert.strictEqual(fallbackWarnings.length, 0,
      "unsigned_legacy must not emit the signed_preferred fallback warning");
  } finally {
    console.warn = origWarn;
  }
});

// ─── MW-4: signed_required behavior unchanged ─────────────────────────────────

test("MW-4a: signed_required still fails fast at construction without verifyKrl", () => {
  assert.throws(
    () => new SiftHttpKeyStore({ jwksUrl: JWKS_URL, krlUrl: KRL_URL, krlMode: "signed_required" }),
    (err: unknown) => {
      assert.ok(err instanceof TypeError);
      assert.ok((err as TypeError).message.includes("verifyKrl"));
      return true;
    }
  );
});

test("MW-4b: signed_required does not emit unsigned-fallback warning", async () => {
  const warned: string[] = [];
  const origWarn = console.warn;
  console.warn = (...args: unknown[]) => {
    warned.push(args.map(String).join(" "));
  };

  try {
    const store = new SiftHttpKeyStore({
      jwksUrl: JWKS_URL, krlUrl: KRL_URL,
      krlMode: "signed_required",
      verifyKrl: () => ({
        ok: true,
        violations: [],
        accepted: { issuer: "krl-issuer", krl_version: 1 },
      }),
      fetch: makeFetch(happyRoutes(SIGNED_KRL_BODY)),
      now: () => TEST_NOW,
    });

    await store.refresh();

    const fallbackWarnings = warned.filter(w => w.includes("unsigned fallback"));
    assert.strictEqual(fallbackWarnings.length, 0,
      "signed_required must never emit unsigned-fallback warning");
  } finally {
    console.warn = origWarn;
  }
});

// ─── MW-5: Default krlMode remains signed_preferred ──────────────────────────

test("MW-5: default krlMode remains signed_preferred (no default change in this PR)", () => {
  const store = new SiftHttpKeyStore({ jwksUrl: JWKS_URL, krlUrl: KRL_URL });
  assert.strictEqual(store.getKrlStatus().mode, "signed_preferred",
    "default must remain signed_preferred — not changed in v-next");
});

// ─── MW-6: unsigned_legacy remains fully functional ──────────────────────────

test("MW-6: unsigned_legacy mode still accepts unsigned KRLs and populates revokedKids", async () => {
  const store = new SiftHttpKeyStore({
    jwksUrl: JWKS_URL, krlUrl: KRL_URL,
    krlMode: "unsigned_legacy",
    fetch: makeFetch(happyRoutes({ version: 1, issuer: "s", revoked_kids: ["kid-1"] })),
    now: () => TEST_NOW,
  });

  await store.refresh();

  assert.strictEqual(await store.isKidRevoked("kid-1"), true,
    "unsigned_legacy must still populate revokedKids correctly");
  assert.strictEqual(store.getKrlStatus().lastIntegrity, "unsigned_legacy");
  assert.strictEqual(store.getKrlStatus().mode, "unsigned_legacy");
});
