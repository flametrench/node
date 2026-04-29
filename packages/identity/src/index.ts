// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * @flametrench/identity — users, credentials, and user-bound sessions.
 *
 * See the normative specification at spec/docs/identity.md and the design
 * rationale at spec/decisions/0004-identity-model.md.
 */

export type {
  CreateCredentialInput,
  CreatePasswordCredentialInput,
  CreatePasskeyCredentialInput,
  CreateOidcCredentialInput,
  CreateSessionInput,
  CreateSessionResult,
  CreateUserInput,
  Credential,
  CredentialType,
  CredId,
  FindCredentialInput,
  ListOptions,
  ListUsersOptions,
  OidcCredential,
  Page,
  PasskeyCredential,
  PasswordCredential,
  RotateCredentialInput,
  RotatePasswordInput,
  RotatePasskeyInput,
  RotateOidcInput,
  SesId,
  Session,
  Status,
  UpdateUserInput,
  User,
  UsrId,
  VerifiedCredentialResult,
  VerifyPasswordInput,
} from "./types.js";
export { ARGON2ID_FLOOR } from "./types.js";

export type { IdentityStore } from "./store.js";

export {
  InMemoryIdentityStore,
  type InMemoryIdentityStoreOptions,
} from "./in-memory.js";

export { hashPassword, verifyPasswordHash } from "./hashing.js";

// v0.2 — MFA primitives (Proposed; ADR 0008)
export {
  DEFAULT_TOTP_ALGORITHM,
  DEFAULT_TOTP_DIGITS,
  DEFAULT_TOTP_PERIOD,
  RECOVERY_CODE_COUNT,
  RECOVERY_CODE_LENGTH,
  generateRecoveryCode,
  generateRecoveryCodes,
  generateTotpSecret,
  isMfaPolicyActiveNow,
  isValidRecoveryCode,
  normalizeRecoveryInput,
  totpCompute,
  totpOtpauthUri,
  totpVerify,
  type Factor,
  type FactorStatus,
  type FactorType,
  type MfaProof,
  type MfaVerifyResult,
  type RecoveryEnrollmentResult,
  type RecoveryFactor,
  type RecoveryProof,
  type TotpAlgorithm,
  type TotpEnrollmentResult,
  type TotpFactor,
  type TotpProof,
  type UserMfaPolicy,
  type WebAuthnEnrollmentResult,
  type WebAuthnFactor,
  type WebAuthnProof,
} from "./mfa.js";

export type {
  ConfirmWebAuthnFactorInput,
  EnrollWebAuthnFactorInput,
  SetMfaPolicyInput,
} from "./store.js";

export {
  AlreadyTerminalError,
  CredentialNotActiveError,
  CredentialTypeMismatchError,
  DuplicateCredentialError,
  IdentityError,
  InvalidCredentialError,
  InvalidTokenError,
  NotFoundError,
  PreconditionError,
  SessionExpiredError,
} from "./errors.js";

// v0.2 — WebAuthn assertion verification (Proposed; ADR 0008)
export {
  WebAuthnChallengeMismatchError,
  WebAuthnCounterRegressionError,
  WebAuthnError,
  WebAuthnMalformedError,
  WebAuthnOriginMismatchError,
  WebAuthnRpIdMismatchError,
  WebAuthnSignatureError,
  WebAuthnTypeMismatchError,
  WebAuthnUnsupportedKeyError,
  WebAuthnUserNotPresentError,
  WebAuthnUserNotVerifiedError,
  b64urlEncode,
  coseKeyEs256,
  webauthnVerifyAssertion,
  type VerifyAssertionInput,
  type WebAuthnAssertionResult,
  type WebAuthnFailureReason,
} from "./webauthn.js";
