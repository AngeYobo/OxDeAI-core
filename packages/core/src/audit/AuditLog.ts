type AuditEntryBase = {
  timestamp: number;
  policyId?: string;
};

/** @public */
export type AuditEntry =
  | (AuditEntryBase & {
      type: "INTENT_RECEIVED";
      intent_hash: string;
      agent_id: string;
    })
  | (AuditEntryBase & {
      type: "DECISION";
      intent_hash: string;
      decision: "ALLOW" | "DENY";
      reasons: string[];
      policy_version: string;
    })
  | (AuditEntryBase & {
      type: "AUTH_EMITTED";
      authorization_id: string;
      intent_hash: string;
      expires_at: number;
    })
  | (AuditEntryBase & {
      type: "EXECUTION_ATTESTED";
      intent_hash: string;
      execution_ref: string;
    })
  | (AuditEntryBase & {
      type: "STATE_CHECKPOINT";
      stateHash: string;
    });

/** @public */
export type AuditEvent = AuditEntry;

/** @public */
export interface AuditLog {
  append(event: AuditEntry): void;
  getEvents(): readonly AuditEntry[];
}
