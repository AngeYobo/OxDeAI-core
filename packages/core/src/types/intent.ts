/** @public */
export type ActionType = "PAYMENT" | "PURCHASE" | "PROVISION" | "ONCHAIN_TX";

type IntentBase = {
  intent_id: string;
  agent_id: string;
  action_type: ActionType;
  depth?: number;
  amount: bigint; // fixed-point integer (e.g., 6 decimals)
  asset?: string;
  target: string;
  timestamp: number; // unix seconds
  metadata_hash: string; // hex string
  nonce: bigint;
  signature: string; // placeholder in v0.1
  tool?: string;
  tool_call?: boolean;
};

/** @public */
export type Intent =
  | (IntentBase & {
      type?: "EXECUTE";
      authorization_id?: string;
    })
  | (IntentBase & {
      type: "RELEASE";
      authorization_id: string;
    });
