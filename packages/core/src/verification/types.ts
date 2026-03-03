export type VerificationStatus = "ok" | "invalid" | "inconclusive";

export type VerificationResult = {
  status: VerificationStatus;
  violations: string[];
};

export type SnapshotVerificationResult = VerificationResult & {
  stateHash?: string;
  policyId?: string;
  formatVersion?: number;
};
