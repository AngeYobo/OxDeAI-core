// SPDX-License-Identifier: Apache-2.0

// Receipt verification
export type {
  SiftDecision,
  SiftReceipt,
  VerifyReceiptOptions,
  KeyStoreVerifyOptions,
  VerifyReceiptErrorCode,
  VerifyReceiptResult,
} from "./verifyReceipt.js";
export { verifyReceipt, verifyReceiptWithKeyStore } from "./verifyReceipt.js";

// Intent normalization
export type {
  OxDeAIIntent,
  NormalizedIntentValue,
  NormalizeIntentInput,
  NormalizeIntentErrorCode,
  NormalizeIntentResult,
} from "./normalizeIntent.js";
export { normalizeIntent } from "./normalizeIntent.js";

// State normalization
export type {
  NormalizedStateValue,
  NormalizedState,
  NormalizeStateInput,
  NormalizeStateErrorCode,
  NormalizeStateResult,
} from "./state.js";
export { normalizeState } from "./state.js";

// Authorization construction
export type {
  AuthorizationV1Payload,
  SigningPayload,
  ReceiptToAuthorizationInput,
  ReceiptToAuthorizationErrorCode,
  ReceiptToAuthorizationResult,
} from "./receiptToAuthorization.js";
export { receiptToAuthorization } from "./receiptToAuthorization.js";

// Key store
export type {
  SiftKeyStore,
  SiftHttpKeyStoreOptions,
  KeyStoreErrorCode,
  CreateStagingKeyStoreOptions,
  KrlMode,
  KrlIntegrity,
  KrlVerifyFn,
  KrlStatus,
} from "./siftKeyStore.js";
export {
  KeyStoreError,
  SiftHttpKeyStore,
  createStagingKeyStore,
} from "./siftKeyStore.js";

// KRL watermark store (persistent per-issuer krl_version high-watermark)
export type { KrlWatermarkStore } from "./krlWatermarkStore.js";
export { createInMemoryKrlWatermarkStore } from "./krlWatermarkStore.js";
export { createFileBackedKrlWatermarkStore } from "./krlWatermarkStore.file.js";

// Signed KRL cache (last-known-good cache for cold-start / fetch-failure resilience)
export type { SignedKrlCache } from "./signedKrlCache.js";
export { createInMemorySignedKrlCache } from "./signedKrlCache.js";
export { createFileBackedSignedKrlCache } from "./signedKrlCache.file.js";
