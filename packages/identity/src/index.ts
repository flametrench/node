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
  Credential,
  CredentialType,
  CredId,
  FindCredentialInput,
  ListOptions,
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
