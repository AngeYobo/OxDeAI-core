// SPDX-License-Identifier: Apache-2.0
import { createPrivateKey, createPublicKey } from "node:crypto";
import type { KeyObject } from "node:crypto";

export type PepMode = "enforce" | "observe";

export type PepConfig = {
  mode: PepMode;
  expectedAudience: string;
  frappeBaseUrl: string;
  frappeApiKey: string;
  frappeApiSecret: string;
  replayStore: "memory";
  port: number;
  signingPrivateKey: KeyObject;
  signingPublicKeyPem: string;
  signingKid: string;
  issuer: string;
  authorizationTtlSeconds: number;
};

function requireEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.length === 0) {
    throw new Error(`Required environment variable ${name} is missing or empty`);
  }
  return value;
}

export function loadConfig(): PepConfig {
  const rawMode = requireEnv("OXDEAI_MODE");
  if (rawMode !== "enforce" && rawMode !== "observe") {
    throw new Error(`OXDEAI_MODE must be "enforce" or "observe", got "${rawMode}"`);
  }

  const expectedAudience = requireEnv("EXPECTED_AUDIENCE");
  const frappeBaseUrl = requireEnv("FRAPPE_BASE_URL");

  const mode: PepMode = rawMode;
  let frappeApiKey = "";
  let frappeApiSecret = "";
  if (mode === "enforce") {
    frappeApiKey = requireEnv("FRAPPE_API_KEY");
    frappeApiSecret = requireEnv("FRAPPE_API_SECRET");
  } else {
    frappeApiKey = process.env["FRAPPE_API_KEY"] ?? "";
    frappeApiSecret = process.env["FRAPPE_API_SECRET"] ?? "";
  }

  const replayStoreType = process.env["REPLAY_STORE"] ?? "memory";
  if (replayStoreType !== "memory") {
    throw new Error(`Unsupported REPLAY_STORE: "${replayStoreType}". Only "memory" is supported in this PoC.`);
  }

  const privateKeyPem = requireEnv("SIGNING_PRIVATE_KEY_PEM");
  const signingPrivateKey = createPrivateKey(privateKeyPem);
  const signingPublicKeyPem = createPublicKey(signingPrivateKey)
    .export({ type: "spki", format: "pem" }) as string;

  const signingKid = process.env["SIGNING_KID"] ?? "lgf-frappe-pep-key-1";
  const issuer = process.env["ISSUER"] ?? "oxdeai.lgf-frappe-pep";

  const authorizationTtlSeconds = Number(process.env["AUTHORIZATION_TTL_SECONDS"] ?? "60");
  if (!Number.isFinite(authorizationTtlSeconds) || authorizationTtlSeconds < 1) {
    throw new Error(`AUTHORIZATION_TTL_SECONDS must be a positive integer, got "${process.env["AUTHORIZATION_TTL_SECONDS"]}"`);
  }

  const port = Number(process.env["PORT"] ?? "3000");
  if (!Number.isFinite(port) || port < 0 || port > 65535) {
    throw new Error(`PORT must be 0-65535, got "${process.env["PORT"]}"`);
  }

  return {
    mode,
    expectedAudience,
    frappeBaseUrl,
    frappeApiKey,
    frappeApiSecret,
    replayStore: "memory",
    port,
    signingPrivateKey,
    signingPublicKeyPem,
    signingKid,
    issuer,
    authorizationTtlSeconds,
  };
}

export function redactedConfigSummary(config: PepConfig): Record<string, unknown> {
  return {
    mode: config.mode,
    expectedAudience: config.expectedAudience,
    frappeBaseUrl: config.frappeBaseUrl,
    frappeApiKey: config.frappeApiKey ? "***" : "(not set)",
    frappeApiSecret: config.frappeApiSecret ? "***" : "(not set)",
    replayStore: config.replayStore,
    port: config.port,
    signingKid: config.signingKid,
    issuer: config.issuer,
    authorizationTtlSeconds: config.authorizationTtlSeconds,
  };
}
