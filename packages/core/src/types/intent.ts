export type ActionType = "PAYMENT" | "PURCHASE" | "PROVISION" | "ONCHAIN_TX";

export type Intent = {
  intent_id: string;
  agent_id: string;
  action_type: ActionType;
  amount: bigint; // fixed-point integer (e.g., 6 decimals)
  asset?: string;
  target: string;
  timestamp: number; // unix seconds
  metadata_hash: string; // hex string
  nonce: bigint;
  signature: string; // placeholder in v0.1
};