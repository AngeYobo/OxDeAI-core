export class StrictDeterminismError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StrictDeterminismError";
  }
}

export function assertNoEntropy(signal: { hasEntropy: boolean; context?: string }): void {
  if (signal.hasEntropy) {
    throw new StrictDeterminismError(
      signal.context ? `Entropy source detected: ${signal.context}` : "Entropy source detected"
    );
  }
}
