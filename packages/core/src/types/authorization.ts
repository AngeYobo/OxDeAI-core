/** @public */
export type AuthorizationV1 = {
  auth_id: string;
  issuer: string;
  audience: string;
  intent_hash: string; // sha256 hex
  state_hash: string; // sha256 hex
  policy_id: string; // stable policy id / hash
  decision: "ALLOW" | "DENY";
  issued_at: number; // unix seconds
  expiry: number; // unix seconds
  nonce?: string;
  capability?: string;
  signature?: string;
};

/** @public */
export type AuthorizationLegacy = {
  authorization_id: string;
  intent_hash: string; // sha256 hex
  policy_version: string;
  state_snapshot_hash: string; // sha256 hex
  decision: "ALLOW";
  expires_at: number; // unix seconds
  engine_signature: string; // HMAC-SHA256 hex over canonical payload
};

/**
 * @public
 * Backward-compatible authorization shape emitted by the reference engine.
 * Carries legacy v1.0.x fields and additive AuthorizationV1 fields.
 */
export type Authorization = AuthorizationLegacy & AuthorizationV1;
