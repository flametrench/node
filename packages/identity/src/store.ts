// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import type {
  Factor,
  MfaProof,
  MfaVerifyResult,
  RecoveryEnrollmentResult,
  TotpEnrollmentResult,
  TotpFactor,
  UserMfaPolicy,
  WebAuthnEnrollmentResult,
  WebAuthnFactor,
} from "./mfa.js";
import type {
  CreatePatInput,
  CreatePatResult,
  ListPatsForUserOptions,
  PatId,
  PersonalAccessToken,
  VerifiedPat,
} from "./pat.js";
import type {
  CreateCredentialInput,
  CreateSessionInput,
  CreateSessionResult,
  CreateUserInput,
  Credential,
  CredId,
  FindCredentialInput,
  ListOptions,
  ListUsersOptions,
  Page,
  RotateCredentialInput,
  SesId,
  Session,
  UpdateUserInput,
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

  createUser(input?: CreateUserInput): Promise<User>;
  getUser(usrId: UsrId): Promise<User>;
  /**
   * Partial update of v0.2 user metadata per ADR 0014. An omitted field
   * means "don't change"; explicit `null` clears. Suspended users MAY
   * be updated; revoked users raise AlreadyTerminalError.
   */
  updateUser(input: UpdateUserInput): Promise<User>;
  /**
   * Paginated user enumeration per ADR 0015. Cursor + ordering match
   * `listMembers`. Adopters MUST gate the call site (sysadmin or equivalent);
   * the SDK does not enforce authorization.
   */
  listUsers(options?: ListUsersOptions): Promise<Page<User>>;
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

  // ─── v0.2 MFA store operations (ADR 0008) ───

  enrollTotpFactor(usrId: UsrId, identifier: string): Promise<TotpEnrollmentResult>;
  enrollWebAuthnFactor(input: EnrollWebAuthnFactorInput): Promise<WebAuthnEnrollmentResult>;
  enrollRecoveryFactor(usrId: UsrId): Promise<RecoveryEnrollmentResult>;

  confirmTotpFactor(mfaId: string, code: string): Promise<TotpFactor>;
  confirmWebAuthnFactor(input: ConfirmWebAuthnFactorInput): Promise<WebAuthnFactor>;

  listMfaFactors(usrId: UsrId): Promise<Factor[]>;
  getMfaFactor(mfaId: string): Promise<Factor>;
  revokeMfaFactor(mfaId: string): Promise<Factor>;

  /**
   * Verify an MFA proof and return the matched factor's id + type.
   *
   * Does NOT mint a session — the spec's three-step session flow is
   * `verifyPassword → verifyMfa → createSession`. WebAuthn proofs
   * advance and persist the sign count atomically with the verify.
   *
   * Throws InvalidCredentialError on mismatch (wrong code, bad
   * signature, no active factor of the proof's type, etc.).
   */
  verifyMfa(usrId: UsrId, proof: MfaProof): Promise<MfaVerifyResult>;

  /** Returns null when the user has no policy row. */
  getMfaPolicy(usrId: UsrId): Promise<UserMfaPolicy | null>;
  setMfaPolicy(input: SetMfaPolicyInput): Promise<UserMfaPolicy>;

  // ─── v0.3 personal access tokens (ADR 0016) ───

  /**
   * Mint a new PAT bound to the user. Returns the persisted record and
   * the plaintext bearer token in `pat_<32hex>_<base64url>` form. The
   * plaintext token is returned ONCE; the server stores only an
   * Argon2id hash of the secret segment at the cred-password
   * parameter floor.
   *
   * @security Adopter MUST gate this call so the requesting principal
   * either owns `input.usrId` OR is a sysadmin acting on the user's
   * behalf. The SDK does not enforce. (security-audit-v0.3.md H7.)
   *
   * @security Adopter MUST gate calls on `input.scope`. The SDK
   * persists scope as opaque strings — it does NOT interpret them at
   * verifyPatToken time. Unlike `tup.relation` (which `check()`
   * enforces against the rule registry), scope is purely an audit tag
   * unless the adopter's request handler reads `VerifiedPat.scope` and
   * gates the request. (security-audit-v0.3.md F5.)
   */
  createPat(input: CreatePatInput): Promise<CreatePatResult>;

  /**
   * @security Adopter MUST gate so the requesting principal either
   * owns the PAT (matches `usrId` of the row) OR is a sysadmin. The
   * SDK returns the row regardless — without route-layer gating an
   * unauthenticated/wrong-principal request leaks the PAT's
   * existence, scope, and metadata. (security-audit-v0.3.md H7.)
   */
  getPat(patId: PatId): Promise<PersonalAccessToken>;

  /**
   * Cursor-paginated PAT list for a user. Mirrors `listMembers`.
   *
   * @security Adopter MUST gate so the requesting principal either is
   * `usrId` OR is a sysadmin. Without gating, any caller can
   * enumerate any user's PATs. (security-audit-v0.3.md H7.)
   */
  listPatsForUser(
    usrId: UsrId,
    options?: ListPatsForUserOptions,
  ): Promise<Page<PersonalAccessToken>>;

  /**
   * Terminal-state revoke. Idempotent: revoking an already-revoked
   * PAT returns the existing row.
   *
   * @security Adopter MUST gate so the requesting principal either
   * owns the PAT OR is a sysadmin. Without gating, any caller can
   * revoke any user's PAT — locking the legitimate owner out of
   * their own automation. (security-audit-v0.3.md H7.)
   */
  revokePat(patId: PatId): Promise<PersonalAccessToken>;

  /**
   * Verify a PAT bearer token per ADR 0016 §"Verification semantics".
   *
   * Throws InvalidPatTokenError for malformed tokens, missing rows,
   * or wrong-secret matches (the missing/wrong cases MUST conflate to
   * defend against a token-presence timing oracle). Throws
   * PatRevokedError for terminal-revoked tokens. Throws
   * PatExpiredError for past-expiry tokens.
   *
   * On success, side-effect: updates `lastUsedAt`. Implementations MAY
   * coalesce these writes within a configurable window (60s default)
   * to avoid a write-per-request hot path.
   */
  verifyPatToken(token: string): Promise<VerifiedPat>;
}

export interface EnrollWebAuthnFactorInput {
  usrId: UsrId;
  /** Base64url-encoded WebAuthn credential ID; SDK indexes on it. */
  identifier: string;
  /** COSE_Key bytes from the registration ceremony. */
  publicKey: Uint8Array;
  /** Initial sign count from the registration response. */
  signCount: number;
  /** RP ID the credential was registered under. */
  rpId: string;
  aaguid?: string | null;
  transports?: string[];
}

export interface ConfirmWebAuthnFactorInput {
  mfaId: string;
  authenticatorData: Uint8Array;
  clientDataJson: Uint8Array;
  signature: Uint8Array;
  expectedChallenge: Uint8Array;
  expectedOrigin: string;
}

export interface SetMfaPolicyInput {
  usrId: UsrId;
  required: boolean;
  graceUntil?: Date | null;
}
