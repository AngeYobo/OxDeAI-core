export type AuditEvent =
  | {
      type: "INTENT_RECEIVED";
      intent_hash: string;
      agent_id: string;
      timestamp: number;
    }
  | {
      type: "DECISION";
      intent_hash: string;
      decision: "ALLOW" | "DENY";
      reasons: string[];
      policy_version: string;
      timestamp: number;
    }
  | {
      type: "AUTH_EMITTED";
      authorization_id: string;
      intent_hash: string;
      expires_at: number;
      timestamp: number;
    }
  | {
      type: "EXECUTION_ATTESTED";
      intent_hash: string;
      execution_ref: string;
      timestamp: number;
    };

export interface AuditLog {
  append(event: AuditEvent): void;
  getEvents(): readonly AuditEvent[];
}