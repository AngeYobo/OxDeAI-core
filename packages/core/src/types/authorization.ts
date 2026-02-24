export type Authorization = {
  authorization_id: string;
  intent_hash: string; // sha256 hex
  policy_version: string;
  state_snapshot_hash: string; // sha256 hex
  decision: "ALLOW";
  expires_at: number; // unix seconds
  engine_signature: string; // HMAC-SHA256 hex over canonical payload
};