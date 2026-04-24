// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import type {
  CreateCredentialInput,
  CreateSessionInput,
  CreateSessionResult,
  Credential,
  CredId,
  FindCredentialInput,
  ListOptions,
  Page,
  RotateCredentialInput,
  SesId,
  Session,
  User,
  UsrId,
  VerifiedCredentialResult,
  VerifyPasswordInput,
} from "./types.js";

/**
 * The IdentityStore interface is the contract every identity backend fulfills.
 *
 * **Cascades (spec-required):**
 *   - Revoking a user MUST terminate all the user's active sessions AND
 *     transition all the user's active credentials to `revoked`.
 *   - Suspending a user MUST terminate all active sessions.
 *   - Rotating a credential MUST terminate every session established by
 *     the rotated credential.
 *   - Revoking a credential MUST terminate every session established by it.
 */
export interface IdentityStore {
  // ─── Users ───

  createUser(): Promise<User>;
  getUser(usrId: UsrId): Promise<User>;
  suspendUser(usrId: UsrId): Promise<User>;
  reinstateUser(usrId: UsrId): Promise<User>;
  revokeUser(usrId: UsrId): Promise<User>;

  // ─── Credentials ───

  createCredential(input: CreateCredentialInput): Promise<Credential>;
  getCredential(credId: CredId): Promise<Credential>;
  listCredentialsForUser(usrId: UsrId): Promise<Credential[]>;
  findCredentialByIdentifier(input: FindCredentialInput): Promise<Credential | null>;

  /** Revoke-and-re-add rotation. Returns the new active credential. */
  rotateCredential(input: RotateCredentialInput): Promise<Credential>;

  suspendCredential(credId: CredId): Promise<Credential>;
  reinstateCredential(credId: CredId): Promise<Credential>;
  revokeCredential(credId: CredId): Promise<Credential>;

  /**
   * Verify a password proof. Constant-time comparison against the stored
   * Argon2id hash. Returns the matched user/credential ids on success, or
   * throws InvalidCredentialError on failure.
   */
  verifyPassword(input: VerifyPasswordInput): Promise<VerifiedCredentialResult>;

  // ─── Sessions ───

  createSession(input: CreateSessionInput): Promise<CreateSessionResult>;
  getSession(sesId: SesId): Promise<Session>;
  listSessionsForUser(usrId: UsrId, options?: ListOptions): Promise<Page<Session>>;

  /** Verify an opaque bearer token and return the backing session. */
  verifySessionToken(token: string): Promise<Session>;

  /** Rotate: new session id, new token; previous session marked revoked. */
  refreshSession(sesId: SesId): Promise<CreateSessionResult>;

  revokeSession(sesId: SesId): Promise<Session>;
}
