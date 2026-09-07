// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalJson, verifyAuthorization } from "@oxdeai/core";
import type { AuthorizationV1, KeySet } from "@oxdeai/core";
import { createPepGatewayExecutor } from "../gateway.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "../../../..");
const fixedNow = 1712448050;

function loadJson(path: string): any {
  return JSON.parse(readFileSync(resolve(repoRoot, path), "utf8"));
}

function sha256Hex(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

function vectorKeySet(authVectors: any): KeySet {
  return {
    issuer: "issuer-1",
    version: "vectors",
    keys: authVectors.keys.map((key: any) => ({
      kid: key.kid,
      alg: key.alg,
      public_key: key.public_key_pem,
    })),
  };
}

function authByRef(authVectors: any, id: string): AuthorizationV1 {
  const vector = authVectors.vectors.find((entry: any) => entry.id === id);
  assert.ok(vector, `missing authorization vector ${id}`);
  return structuredClone(vector.artifact) as AuthorizationV1;
}

/**
 * Issuer-policy authority for the locked vector corpus.
 *
 * Fixed corpus constants, NOT read off the artifact under test. The previous
 * helper passed `expectedPolicyId: auth.policy_id`, which compared each vector
 * against itself and could never fail (#301).
 */
const VECTOR_AUTHORITIES = [{ issuer: "issuer-1", policyId: "policy-1" }] as const;

function expectedAuthorizationDecision(vector: any, authVectors: any): { decision: "ALLOW" | "DENY"; error: string | null } {
  const auth = structuredClone(vector.artifact) as AuthorizationV1;
  const keySet = vectorKeySet(authVectors);
  const verification = verifyAuthorization(auth, {
    now: fixedNow,
    mode: "strict",
    trustedKeySets: [keySet],
    requireSignatureVerification: true,
    expectedAudience: "pep-gateway.local",
    trustedAuthorizationAuthorities: VECTOR_AUTHORITIES,
  });

  if (verification.status !== "ok") {
    if (verification.violations.some((v) => v.code === "AUTH_EXPIRED")) {
      return { decision: "DENY", error: "EXPIRED" };
    }
    if (verification.violations.some((v) => v.code === "AUTH_SIGNATURE_INVALID")) {
      return { decision: "DENY", error: "INVALID_SIGNATURE" };
    }
    return { decision: "DENY", error: verification.violations[0]?.code ?? "AUTHORIZATION_INVALID" };
  }

  const expectedIntentHash = authVectors.vectors.find((entry: any) => entry.id === "auth-allow-valid")?.artifact.intent_hash;
  if (expectedIntentHash && auth.intent_hash !== expectedIntentHash) {
    return { decision: "DENY", error: "INTENT_HASH_MISMATCH" };
  }
  return { decision: "ALLOW", error: null };
}

test("canonicalization-v1 locked vectors match core canonicalJson", () => {
  const vectors = loadJson("docs/spec/test-vectors/canonicalization-v1.json");
  for (const vector of vectors) {
    if (vector.status === "ok") {
      const actual = canonicalJson(vector.input);
      assert.equal(actual, vector.expected_canonical_json, vector.id);
      assert.equal(sha256Hex(actual), vector.expected_sha256, vector.id);
    } else {
      assert.throws(
        () => canonicalJson(vector.input),
        (err: unknown) => err instanceof Error && err.message === vector.expected_error,
        vector.id
      );
    }
  }
});

test("authorization-v1 locked vectors verify through core verifier", () => {
  const authVectors = loadJson("docs/spec/test-vectors/authorization-v1.json");
  for (const vector of authVectors.vectors) {
    const actual = expectedAuthorizationDecision(vector, authVectors);
    assert.deepEqual(actual, vector.expected, vector.id);
  }
});

test("pep-gateway-v1 locked vectors execute through reusable gateway", async () => {
  const authVectors = loadJson("docs/spec/test-vectors/authorization-v1.json");
  const pepVectors = loadJson("docs/spec/test-vectors/pep-vectors-v1.json");
  const keySet = vectorKeySet(authVectors);

  for (const vector of pepVectors.vectors) {
    const gateway = createPepGatewayExecutor({
      expectedAudience: "pep-gateway.local",
      trustedAuthorizationAuthorities: VECTOR_AUTHORITIES,
      trustedKeySets: [keySet],
      internalExecutorToken: pepVectors.gateway_secret,
      now: () => fixedNow,
      timeoutMs: 10,
      executeUpstream: async (_action, headers) => {
        assert.equal(headers[pepVectors.upstream_header], pepVectors.gateway_secret, vector.id);
        switch (vector.request.upstream_behavior) {
          case "success":
            return { status: 200, body: { ok: true, executed: true } };
          case "error":
            return { status: 500, body: { ok: false, executed: false } };
          case "timeout":
            return new Promise((resolve) => setTimeout(() => resolve({ status: 200, body: {} }), 100));
          case "not_called":
          default:
            throw new Error("UPSTREAM_MUST_NOT_BE_CALLED");
        }
      },
    });

    const result = await gateway({
      action: vector.request.action,
      authorization: authByRef(authVectors, vector.request.authorization_ref),
    });

    assert.equal(result.status, vector.expected.status, vector.id);
    assert.equal(result.body.decision, vector.expected.decision, vector.id);
    assert.equal(result.body.executed, vector.expected.executed, vector.id);
  }
});
